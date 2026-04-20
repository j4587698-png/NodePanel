using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace NodePanel.Core.Runtime;

internal static class RuntimeTlsServerCertificateSelector
{
    private static readonly ConcurrentDictionary<string, byte> ImportedCertificateThumbprints = new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConditionalWeakTable<X509Certificate2, ActivatedServerCertificate> WindowsServerCertificates = new();

    static RuntimeTlsServerCertificateSelector()
    {
        AppDomain.CurrentDomain.ProcessExit += static (_, _) => CleanupImportedCertificatesOnProcessExit();
    }

    public static X509Certificate2 GetServerCertificate(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        if (!OperatingSystem.IsWindows())
        {
            return certificate;
        }

        try
        {
            return WindowsServerCertificates.GetValue(certificate, static source => ActivatedServerCertificate.Create(source)).Certificate;
        }
        catch (CryptographicException)
        {
            return certificate;
        }
        catch (UnauthorizedAccessException)
        {
            return certificate;
        }
    }

    private sealed class ActivatedServerCertificate
    {
        private readonly string _thumbprint;
        private readonly bool _removeOnFinalize;
        private int _disposed;

        private ActivatedServerCertificate(
            X509Certificate2 certificate,
            string thumbprint,
            bool removeOnFinalize)
        {
            Certificate = certificate;
            _thumbprint = thumbprint;
            _removeOnFinalize = removeOnFinalize;
        }

        ~ActivatedServerCertificate()
        {
            Dispose(disposing: false);
        }

        public X509Certificate2 Certificate { get; }

        public static ActivatedServerCertificate Create(X509Certificate2 source)
        {
            ArgumentNullException.ThrowIfNull(source);

            var thumbprint = source.Thumbprint;
            ArgumentException.ThrowIfNullOrWhiteSpace(thumbprint);

            using var store = OpenCurrentUserMyStore(OpenFlags.ReadWrite);

            var existingCertificate = FindCertificateWithPrivateKey(store, thumbprint);
            if (existingCertificate is not null)
            {
                return new ActivatedServerCertificate(existingCertificate, thumbprint, removeOnFinalize: false);
            }

            store.Add(source);
            ImportedCertificateThumbprints[thumbprint] = 0;

            var importedCertificate = FindCertificateWithPrivateKey(store, thumbprint);
            if (importedCertificate is null)
            {
                ImportedCertificateThumbprints.TryRemove(thumbprint, out _);
                throw new CryptographicException("Unable to activate the TLS server certificate from the Windows certificate store.");
            }

            return new ActivatedServerCertificate(importedCertificate, thumbprint, removeOnFinalize: true);
        }

        private void Dispose(bool disposing)
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            try
            {
                if (disposing)
                {
                    Certificate.Dispose();
                }
                else
                {
                    TryDisposeCertificate();
                }
            }
            finally
            {
                if (_removeOnFinalize)
                {
                    RuntimeTlsServerCertificateSelector.TryRemoveImportedCertificate(_thumbprint);
                }
            }
        }

        private void TryDisposeCertificate()
        {
            try
            {
                Certificate.Dispose();
            }
            catch
            {
            }
        }
    }

    private static X509Store OpenCurrentUserMyStore(OpenFlags openFlags)
    {
        var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(openFlags);
        return store;
    }

    private static X509Certificate2? FindCertificateWithPrivateKey(X509Store store, string thumbprint)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentException.ThrowIfNullOrWhiteSpace(thumbprint);

        return store.Certificates
            .Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false)
            .OfType<X509Certificate2>()
            .FirstOrDefault(static certificate => certificate.HasPrivateKey);
    }

    private static void CleanupImportedCertificatesOnProcessExit()
    {
        foreach (var entry in ImportedCertificateThumbprints.Keys.ToArray())
        {
            TryRemoveImportedCertificate(entry);
        }
    }

    private static void TryRemoveImportedCertificate(string thumbprint)
    {
        try
        {
            using var store = OpenCurrentUserMyStore(OpenFlags.ReadWrite);
            var certificateToRemove = FindCertificateWithPrivateKey(store, thumbprint);
            if (certificateToRemove is null)
            {
                ImportedCertificateThumbprints.TryRemove(thumbprint, out _);
                return;
            }

            store.Remove(certificateToRemove);
            certificateToRemove.Dispose();
            ImportedCertificateThumbprints.TryRemove(thumbprint, out _);
        }
        catch
        {
        }
    }
}
