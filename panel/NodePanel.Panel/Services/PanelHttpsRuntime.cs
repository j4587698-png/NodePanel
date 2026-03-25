using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using FreeSql;
using Microsoft.AspNetCore.Http;
using NodePanel.Panel.Configuration;
using NodePanel.Panel.Models;

namespace NodePanel.Panel.Services;

public sealed class PanelHttpsRuntime : IDisposable
{
    private readonly object _sync = new();
    private readonly PanelOptions _options;
    private X509Certificate2? _currentCertificate;
    private X509Certificate2? _fallbackCertificate;
    private PanelHttpsRuntimeSnapshot _snapshot = new();
    private bool _listenerConfigured;
    private int _activeHttpsPort = 443;

    public PanelHttpsRuntime(PanelOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options;
    }

    public PanelHttpsRuntimeSnapshot LoadSnapshot()
    {
        var snapshot = ReadSnapshot();
        ApplySnapshot(snapshot);
        return snapshot;
    }

    public void MarkListenerConfigured(PanelHttpsRuntimeSnapshot snapshot)
    {
        lock (_sync)
        {
            _listenerConfigured = true;
            _activeHttpsPort = snapshot.Port is > 0 and <= 65535 ? snapshot.Port : 443;
        }
    }

    public Task RefreshAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        LoadSnapshot();
        return Task.CompletedTask;
    }

    public PanelHttpsRuntimeSnapshot GetSnapshot()
    {
        lock (_sync)
        {
            return _snapshot;
        }
    }

    public bool ShouldRedirectHttp(PathString requestPath)
    {
        var snapshot = GetSnapshot();
        var pathValue = requestPath.Value ?? string.Empty;
        return snapshot.Enabled &&
               IsListenerConfigured() &&
               snapshot.RedirectHttpToHttps &&
               !pathValue.StartsWith("/.well-known/acme-challenge", StringComparison.OrdinalIgnoreCase) &&
               !pathValue.StartsWith("/control/ws", StringComparison.OrdinalIgnoreCase);
    }

    public Uri BuildRedirectUri(HttpRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        var activePort = GetActiveHttpsPort();
        var builder = new UriBuilder(Uri.UriSchemeHttps, request.Host.Host)
        {
            Path = request.Path.ToString(),
            Query = request.QueryString.HasValue ? request.QueryString.Value : string.Empty,
            Port = activePort is > 0 and not 443 ? activePort : -1
        };

        return builder.Uri;
    }

    public SslServerAuthenticationOptions CreateAuthenticationOptions()
        => new()
        {
            ServerCertificate = GetOrCreateServerCertificate(),
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
        };

    public void Dispose()
    {
        lock (_sync)
        {
            _currentCertificate?.Dispose();
            _currentCertificate = null;
            _fallbackCertificate?.Dispose();
            _fallbackCertificate = null;
        }
    }

    private X509Certificate2 GetOrCreateServerCertificate()
    {
        lock (_sync)
        {
            if (_currentCertificate is not null)
            {
                return _currentCertificate;
            }

            _fallbackCertificate ??= CreateFallbackCertificate(_snapshot);
            return _fallbackCertificate;
        }
    }

    private bool IsListenerConfigured()
    {
        lock (_sync)
        {
            return _listenerConfigured;
        }
    }

    private int GetActiveHttpsPort()
    {
        lock (_sync)
        {
            return _activeHttpsPort;
        }
    }

    private void ApplySnapshot(PanelHttpsRuntimeSnapshot snapshot)
    {
        lock (_sync)
        {
            var previous = _currentCertificate;
            var previousFallback = _fallbackCertificate;
            _snapshot = snapshot;
            _currentCertificate = snapshot.Certificate;
            _fallbackCertificate = null;
            previous?.Dispose();
            previousFallback?.Dispose();
        }
    }

    private PanelHttpsRuntimeSnapshot ReadSnapshot()
    {
        var defaultSnapshot = new PanelHttpsRuntimeSnapshot
        {
            Enabled = true
        };

        if (string.IsNullOrWhiteSpace(_options.DbType) || string.IsNullOrWhiteSpace(_options.DbConnectionString))
        {
            return defaultSnapshot;
        }

        try
        {
            using var fsql = CreateFreeSql();
            var settings = fsql.Select<SettingEntity>()
                .ToList()
                .ToDictionary(static item => item.Key, static item => item.Value, StringComparer.Ordinal);

            var form = PanelHttpsSettingsFormInput.FromSettings(settings);
            var snapshot = new PanelHttpsRuntimeSnapshot
            {
                Enabled = form.Enabled,
                ListenAddress = string.IsNullOrWhiteSpace(form.ListenAddress) ? "0.0.0.0" : NodeFormValueCodec.TrimOrEmpty(form.ListenAddress),
                Port = form.Port is > 0 and <= 65535 ? form.Port : 443,
                RedirectHttpToHttps = form.RedirectHttpToHttps,
                CertificateId = NodeFormValueCodec.TrimOrEmpty(form.CertificateId)
            };

            if (string.IsNullOrWhiteSpace(snapshot.CertificateId))
            {
                return snapshot;
            }

            var certificate = fsql.Select<PanelCertificateEntity>()
                .Where(item => item.CertificateId == snapshot.CertificateId)
                .First();

            if (certificate is null)
            {
                return snapshot with
                {
                    LastError = $"找不到 Panel HTTPS 绑定的证书: {snapshot.CertificateId}。"
                };
            }

            snapshot = snapshot with
            {
                FallbackServerNames = BuildFallbackServerNames(certificate)
            };

            if (string.IsNullOrWhiteSpace(certificate.PfxBase64))
            {
                return snapshot with
                {
                    LastError = $"证书 {snapshot.CertificateId} 当前还没有可用的 PFX 资产，将临时使用自签证书。"
                };
            }

            var pfxBytes = Convert.FromBase64String(certificate.PfxBase64);
            var loaded = X509CertificateLoader.LoadPkcs12(
                pfxBytes,
                certificate.PfxPassword,
                X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);

            return snapshot with
            {
                Certificate = loaded
            };
        }
        catch (Exception ex)
        {
            return defaultSnapshot with
            {
                LastError = ex.Message
            };
        }
    }

    private static IReadOnlyList<string> BuildFallbackServerNames(PanelCertificateEntity certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        return certificate.AltNames
            .Prepend(certificate.Domain)
            .Where(static item => !string.IsNullOrWhiteSpace(item))
            .Select(static item => item.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static X509Certificate2 CreateFallbackCertificate(PanelHttpsRuntimeSnapshot snapshot)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=NodePanel Temporary TLS",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                critical: false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        var enhancedKeyUsages = new OidCollection
        {
            new("1.3.6.1.5.5.7.3.1")
        };
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(enhancedKeyUsages, false));

        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName("localhost");
        sanBuilder.AddIpAddress(IPAddress.Loopback);
        sanBuilder.AddIpAddress(IPAddress.IPv6Loopback);

        foreach (var serverName in snapshot.FallbackServerNames)
        {
            TryAddSubjectAlternativeName(sanBuilder, serverName);
        }

        if (!string.IsNullOrWhiteSpace(snapshot.ListenAddress))
        {
            TryAddSubjectAlternativeName(sanBuilder, snapshot.ListenAddress);
        }

        request.CertificateExtensions.Add(sanBuilder.Build());

        var notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
        var notAfter = notBefore.AddYears(10);
        using var certificate = request.CreateSelfSigned(notBefore, notAfter);
        var exported = certificate.Export(X509ContentType.Pfx, string.Empty);

        return X509CertificateLoader.LoadPkcs12(
            exported,
            string.Empty,
            X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);
    }

    private static void TryAddSubjectAlternativeName(SubjectAlternativeNameBuilder sanBuilder, string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        var normalized = value.Trim();
        if (IPAddress.TryParse(normalized, out var address))
        {
            if (!IPAddress.Any.Equals(address) && !IPAddress.IPv6Any.Equals(address))
            {
                sanBuilder.AddIpAddress(address);
            }

            return;
        }

        if (string.Equals(normalized, "0.0.0.0", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(normalized, "::", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        try
        {
            sanBuilder.AddDnsName(normalized);
        }
        catch (ArgumentException)
        {
        }
    }

    private IFreeSql CreateFreeSql()
    {
        var dataType = string.Equals(_options.DbType, "mysql", StringComparison.OrdinalIgnoreCase)
            ? DataType.MySql
            : DataType.Sqlite;

        return new FreeSqlBuilder()
            .UseConnectionString(dataType, _options.DbConnectionString)
            .UseAutoSyncStructure(false)
            .Build();
    }
}

public sealed record PanelHttpsRuntimeSnapshot
{
    public bool Enabled { get; init; }

    public string ListenAddress { get; init; } = "0.0.0.0";

    public int Port { get; init; } = 443;

    public bool RedirectHttpToHttps { get; init; }

    public string CertificateId { get; init; } = string.Empty;

    public X509Certificate2? Certificate { get; init; }

    public IReadOnlyList<string> FallbackServerNames { get; init; } = Array.Empty<string>();

    public string LastError { get; init; } = string.Empty;
}
