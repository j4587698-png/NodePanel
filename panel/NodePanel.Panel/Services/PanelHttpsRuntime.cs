using System.Net.Security;
using System.Security.Authentication;
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
            _listenerConfigured = snapshot.Enabled;
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

        var snapshot = GetSnapshot();
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
    {
        var certificate = GetCurrentCertificate();
        if (certificate is null)
        {
            throw new InvalidOperationException("Panel HTTPS 已启用，但当前没有可用证书。");
        }

        return new SslServerAuthenticationOptions
        {
            ServerCertificate = certificate,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
        };
    }

    public void Dispose()
    {
        lock (_sync)
        {
            _currentCertificate?.Dispose();
            _currentCertificate = null;
        }
    }

    private X509Certificate2? GetCurrentCertificate()
    {
        lock (_sync)
        {
            return _currentCertificate;
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
            _snapshot = snapshot;
            _currentCertificate = snapshot.Certificate;
            previous?.Dispose();
        }
    }

    private PanelHttpsRuntimeSnapshot ReadSnapshot()
    {
        if (string.IsNullOrWhiteSpace(_options.DbType) || string.IsNullOrWhiteSpace(_options.DbConnectionString))
        {
            return new PanelHttpsRuntimeSnapshot();
        }

        try
        {
            using var fsql = CreateFreeSql();
            var settings = fsql.Select<SettingEntity>()
                .ToList()
                .ToDictionary(static item => item.Key, static item => item.Value, StringComparer.Ordinal);

            var form = PanelHttpsSettingsFormInput.FromSettings(settings);
            if (!form.Enabled)
            {
                return new PanelHttpsRuntimeSnapshot
                {
                    Enabled = false,
                    ListenAddress = form.ListenAddress,
                    Port = form.Port,
                    RedirectHttpToHttps = form.RedirectHttpToHttps,
                    CertificateId = form.CertificateId
                };
            }

            var snapshot = new PanelHttpsRuntimeSnapshot
            {
                Enabled = true,
                ListenAddress = string.IsNullOrWhiteSpace(form.ListenAddress) ? "0.0.0.0" : NodeFormValueCodec.TrimOrEmpty(form.ListenAddress),
                Port = form.Port is > 0 and <= 65535 ? form.Port : 443,
                RedirectHttpToHttps = form.RedirectHttpToHttps,
                CertificateId = NodeFormValueCodec.TrimOrEmpty(form.CertificateId)
            };

            if (string.IsNullOrWhiteSpace(snapshot.CertificateId))
            {
                return snapshot with
                {
                    LastError = "Panel HTTPS 已启用，但未选择证书。"
                };
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

            if (string.IsNullOrWhiteSpace(certificate.PfxBase64))
            {
                return snapshot with
                {
                    LastError = $"证书 {snapshot.CertificateId} 当前还没有可用的 PFX 资产。"
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
            return new PanelHttpsRuntimeSnapshot
            {
                LastError = ex.Message
            };
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

    public string LastError { get; init; } = string.Empty;
}
