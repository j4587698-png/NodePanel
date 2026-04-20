using System.Net.Security;
using System.Security.Authentication;

namespace NodePanel.Core.Runtime;

public interface IRuntimeRealityHandshakeProvider
{
    string Identity { get; }

    ValueTask<RuntimeRealityHandshakeResult> SecureAsync(
        RuntimeRealityHandshakeRequest request,
        CancellationToken cancellationToken);
}

public sealed record RuntimeRealityHandshakeRequest
{
    public required Stream TransportStream { get; init; }

    public required string ServerHost { get; init; }

    public required string ServerName { get; init; }

    public required string TransportProtocol { get; init; }

    public required IReadOnlyList<string> ApplicationProtocols { get; init; }

    public required RuntimeRealityOptions RealityOptions { get; init; }

    public bool SkipCertificateValidation { get; init; }

    public RemoteCertificateValidationCallback? CertificateValidationCallback { get; init; }

    public SslProtocols EnabledSslProtocols { get; init; } = SslProtocols.Tls12 | SslProtocols.Tls13;
}

public sealed record RuntimeRealityHandshakeResult
{
    public required Stream TransportStream { get; init; }

    public SslStream? SslStream { get; init; }

    public required RuntimeInternetSecurityState SecurityState { get; init; }
}

internal interface IRuntimeRealityHandshakeProviderAccessor
{
    IRuntimeRealityHandshakeProvider? RealityHandshakeProvider { get; }
}
