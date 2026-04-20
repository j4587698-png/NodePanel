using System.Net;
using System.Net.Security;
using System.Net.WebSockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

public enum VmessClientTransportType
{
    Tcp = 0,
    Tls = 1,
    Ws = 2,
    Wss = 3,
    HttpUpgrade = 4,
    HttpUpgradeTls = 5,
    Grpc = 6,
    SplitHttp = 7
}

public static class VmessClientTransportProtocols
{
    public const string Tcp = "tcp";
    public const string Ws = "ws";
    public const string HttpUpgrade = RuntimeInternetTransportProtocols.HttpUpgrade;
    public const string Grpc = RuntimeInternetTransportProtocols.Grpc;
    public const string SplitHttp = RuntimeInternetTransportProtocols.SplitHttp;

    public static string Normalize(string? value)
        => RuntimeInternetTransportProtocols.Normalize(value);
}

public static class VmessClientSecurityTypes
{
    public const string None = "none";
    public const string Tls = "tls";
    public const string Reality = "reality";

    public static string Normalize(string? value)
        => RuntimeInternetSecurityTypes.Normalize(value);
}

public sealed record VmessClientOptions : IRuntimeGrpcClientDialOptions, IRuntimeTlsSessionResumptionOptions
{
    public DispatchContext DialContext { get; init; } = new();

    public EndPoint? SourceEndPoint { get; init; }

    public EndPoint? LocalEndPoint { get; init; }

    public string Via { get; init; } = string.Empty;

    public string ViaCidr { get; init; } = string.Empty;

    public string ServerHost { get; init; } = string.Empty;

    public int ServerPort { get; init; } = 443;

    public string ServerName { get; init; } = string.Empty;

    public string Fingerprint { get; init; } = string.Empty;

    public VmessClientTransportType Transport { get; init; } = VmessClientTransportType.Tls;

    public string TransportProtocol { get; init; } = string.Empty;

    public string SecurityType { get; init; } = string.Empty;

    public RuntimeRealityOptions RealityOptions { get; init; } = RuntimeRealityOptions.Empty;

    public string WebSocketPath { get; init; } = "/ws";

    public IReadOnlyDictionary<string, string> WebSocketHeaders { get; init; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    public int WebSocketEarlyDataBytes { get; init; }

    public int WebSocketHeartbeatPeriodSeconds { get; init; }

    public string SplitHttpHost { get; init; } = string.Empty;

    public string SplitHttpPath { get; init; } = "/";

    public IReadOnlyDictionary<string, string> SplitHttpHeaders { get; init; }
        = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    public string SplitHttpMode { get; init; } = string.Empty;

    public bool SplitHttpNoGrpcHeader { get; init; }

    public RuntimeInt32Range SplitHttpXPaddingBytes { get; init; } = RuntimeInt32Range.Empty;

    public bool SplitHttpXPaddingObfsMode { get; init; }

    public string SplitHttpXPaddingKey { get; init; } = string.Empty;

    public string SplitHttpXPaddingHeader { get; init; } = string.Empty;

    public string SplitHttpXPaddingPlacement { get; init; } = string.Empty;

    public string SplitHttpXPaddingMethod { get; init; } = string.Empty;

    public string SplitHttpUplinkHttpMethod { get; init; } = string.Empty;

    public string SplitHttpSessionPlacement { get; init; } = string.Empty;

    public string SplitHttpSessionKey { get; init; } = string.Empty;

    public string SplitHttpSeqPlacement { get; init; } = string.Empty;

    public string SplitHttpSeqKey { get; init; } = string.Empty;

    public string SplitHttpUplinkDataPlacement { get; init; } = string.Empty;

    public string SplitHttpUplinkDataKey { get; init; } = string.Empty;

    public RuntimeInt32Range SplitHttpUplinkChunkSize { get; init; } = RuntimeInt32Range.Empty;

    public RuntimeInt32Range SplitHttpScMaxEachPostBytes { get; init; } = RuntimeInt32Range.Empty;

    public RuntimeInt32Range SplitHttpScMinPostsIntervalMs { get; init; } = RuntimeInt32Range.Empty;

    public int SplitHttpScMaxBufferedPosts { get; init; }

    public RuntimeSplitHttpXmuxOptions SplitHttpXmux { get; init; } = RuntimeSplitHttpXmuxOptions.Empty;

    public RuntimeSplitHttpDownloadOptions? SplitHttpDownloadSettings { get; init; }

    public IReadOnlyList<string> ApplicationProtocols { get; init; } = Array.Empty<string>();

    public RuntimeQuicOptions QuicOptions { get; init; } = RuntimeQuicOptions.Empty;

    public string GrpcServiceName { get; init; } = string.Empty;

    public string GrpcAuthority { get; init; } = string.Empty;

    public bool GrpcMultiMode { get; init; }

    public string GrpcUserAgent { get; init; } = string.Empty;

    public int GrpcIdleTimeoutSeconds { get; init; }

    public int GrpcHealthCheckTimeoutSeconds { get; init; }

    public bool GrpcPermitWithoutStream { get; init; }

    public int GrpcInitialWindowSize { get; init; }

    public string UserUuid { get; init; } = string.Empty;

    public string RequestSecurity { get; init; } = VmessOutboundSecurityTypes.Auto;

    public bool AuthenticatedLength { get; init; } = true;

    public bool NoTerminationSignal { get; init; }

    public VmessCommand Command { get; init; } = VmessCommand.Connect;

    public string TargetHost { get; init; } = string.Empty;

    public int TargetPort { get; init; } = 443;

    public int ConnectTimeoutSeconds { get; init; } = 10;

    public int HandshakeTimeoutSeconds { get; init; } = 10;

    public bool EnableTlsSessionResumption { get; init; }

    public bool SkipCertificateValidation { get; init; }

    public RemoteCertificateValidationCallback? CertificateValidationCallback { get; init; }

    public SslProtocols EnabledSslProtocols { get; init; } = SslProtocols.Tls12 | SslProtocols.Tls13;

    public IRuntimeRealityHandshakeProvider? RealityHandshakeProvider { get; init; }

    public Func<CancellationToken, ValueTask<Stream>>? TransportStreamFactory { get; init; }

    public Func<CancellationToken, ValueTask<Stream>>? SplitHttpDownloadTransportStreamFactory { get; init; }
}

public sealed class VmessClientConnection : RuntimeClientConnection
{
    private int _disposed;

    internal VmessClientConnection(
        RuntimeInternetConnectionContext context,
        bool noTerminationSignal,
        Stream? applicationStream = null)
        : base(context)
    {
        NoTerminationSignal = noTerminationSignal;
        if (applicationStream is not null)
        {
            SetApplicationStream(applicationStream);
        }
    }

    internal bool NoTerminationSignal { get; }

    public override async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        if (!NoTerminationSignal &&
            Stream is VmessClientDataStream vmessStream)
        {
            try
            {
                await vmessStream.CompleteRequestAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch (IOException)
            {
            }
            catch (ObjectDisposedException)
            {
            }
        }

        await base.DisposeAsync().ConfigureAwait(false);
    }
}
