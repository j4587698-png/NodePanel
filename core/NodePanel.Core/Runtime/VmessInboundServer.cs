using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.ExceptionServices;
using System.Security.Authentication;
using System.Text;
using NodePanel.Core.Transport;

namespace NodePanel.Core.Runtime;

public sealed class VmessInboundServer
{
    private readonly VmessInboundConnectionHandler _vmessInboundConnectionHandler;

    public VmessInboundServer(VmessInboundConnectionHandler vmessInboundConnectionHandler)
    {
        _vmessInboundConnectionHandler = vmessInboundConnectionHandler;
    }

    public async Task RunAsync(VmessInboundServerOptions options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);

        var listeners = options.Plan.TlsListeners;
        if (listeners.Count == 0)
        {
            return;
        }

        var tlsOptions = options.Tls ?? throw new InvalidOperationException("VMess inbound server requires TLS options when listeners are configured.");

        var activeListeners = new List<ListenerRuntime>(listeners.Count);
        try
        {
            foreach (var listener in listeners)
            {
                var handle = ListenerHandle.Create(listener.Binding);
                activeListeners.Add(new ListenerRuntime(listener, handle));
                InvokeSafely(options.Callbacks.ListenerStarted, listener);
            }

            var acceptTasks = activeListeners
                .Select(listener => AcceptLoopAsync(listener, tlsOptions, options, cancellationToken))
                .ToArray();
            var acceptGroup = Task.WhenAll(acceptTasks);
            var firstLoopCompletion = Task.WhenAny(acceptTasks);
            var stopSignal = WaitForCancellationAsync(cancellationToken);

            var completed = await Task.WhenAny(firstLoopCompletion, stopSignal).ConfigureAwait(false);

            foreach (var listener in activeListeners)
            {
                listener.Handle.Stop();
            }

            try
            {
                await acceptGroup.ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
            }

            if (completed == stopSignal || cancellationToken.IsCancellationRequested)
            {
                return;
            }

            if (acceptGroup.Exception is not null)
            {
                var exception = acceptGroup.Exception.InnerExceptions.Count == 1
                    ? acceptGroup.Exception.InnerExceptions[0]
                    : acceptGroup.Exception;
                ExceptionDispatchInfo.Capture(exception).Throw();
            }

            throw new InvalidOperationException("VMess inbound accept loop ended unexpectedly.");
        }
        finally
        {
            foreach (var listener in activeListeners)
            {
                listener.Handle.Dispose();
            }
        }
    }

    private async Task AcceptLoopAsync(
        ListenerRuntime listener,
        TrojanInboundTlsOptions tlsOptions,
        VmessInboundServerOptions options,
        CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            AcceptedConnection connection;
            try
            {
                connection = await listener.Handle.AcceptAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (SocketException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }

            _ = Task.Run(
                () => HandleAcceptedConnectionAsync(connection, tlsOptions, options, listener.Definition, cancellationToken),
                CancellationToken.None);
        }
    }

    private async Task HandleAcceptedConnectionAsync(
        AcceptedConnection connection,
        TrojanInboundTlsOptions tlsOptions,
        VmessInboundServerOptions options,
        VmessTlsListenerRuntime listener,
        CancellationToken cancellationToken)
    {
        await using var connectionLease = connection;
        var networkStream = connection.Stream;
        var effectiveRemoteEndPoint = connection.RemoteEndPoint;
        var effectiveLocalEndPoint = connection.LocalEndPoint;
        IPEndPoint? originalDestinationEndPoint = null;

        if ((listener.RawTlsInbound?.ReceiveOriginalDestination == true ||
             listener.WebSocketInbound?.ReceiveOriginalDestination == true) &&
            OriginalTcpDestinationResolver.TryResolve(connection.Socket, out var resolvedOriginalDestination))
        {
            originalDestinationEndPoint = resolvedOriginalDestination;
        }

        try
        {
            if (listener.AcceptProxyProtocol)
            {
                var proxyHeader = await ProxyProtocolReader.ReadAsync(networkStream, cancellationToken).ConfigureAwait(false);
                effectiveRemoteEndPoint = proxyHeader.RemoteEndPoint;
                effectiveLocalEndPoint = proxyHeader.LocalEndPoint;
            }

            Stream tlsTransportStream = networkStream;
            if (tlsOptions.ClientHelloPolicy.Enabled)
            {
                var handshakePayload = await TrojanTlsClientHelloReader.ReadAsync(networkStream, cancellationToken).ConfigureAwait(false);
                if (handshakePayload.Length == 0)
                {
                    return;
                }

                TrojanTlsClientHelloMetadata? clientHelloMetadata = null;
                if (TrojanTlsClientHelloParser.TryParse(handshakePayload, out var parsedMetadata))
                {
                    clientHelloMetadata = parsedMetadata;
                }

                if (TrojanClientHelloPolicyEvaluator.ShouldReject(
                        tlsOptions.ClientHelloPolicy,
                        clientHelloMetadata,
                        out var decision))
                {
                    InvokeSafely(
                        options.Callbacks.ClientHelloRejected,
                        new TrojanInboundClientHelloRejectionContext
                        {
                            RemoteEndPoint = connection.LogRemoteEndPoint ?? effectiveRemoteEndPoint,
                            Metadata = clientHelloMetadata,
                            Reason = decision.Reason
                        });
                    return;
                }

                tlsTransportStream = new PrefixedReadStream(networkStream, handshakePayload);
            }

            using var sslStream = new SslStream(tlsTransportStream, leaveInnerStreamOpen: false);
            await sslStream.AuthenticateAsServerAsync(
                BuildAuthenticationOptions(listener, tlsOptions.Certificate),
                cancellationToken).ConfigureAwait(false);

            if (TrojanTlsServerNamePolicy.ShouldReject(
                    tlsOptions.ServerNamePolicy,
                    tlsOptions.Certificate,
                    sslStream.TargetHostName))
            {
                InvokeSafely(
                    options.Callbacks.UnknownServerNameRejected,
                    new TrojanInboundSniRejectionContext
                    {
                        RemoteEndPoint = connection.LogRemoteEndPoint ?? effectiveRemoteEndPoint,
                        RequestedServerName = sslStream.TargetHostName ?? string.Empty
                    });
                return;
            }

            await HandleTlsConnectionAsync(
                sslStream,
                options,
                listener,
                effectiveRemoteEndPoint,
                effectiveLocalEndPoint,
                originalDestinationEndPoint,
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            InvokeSafely(
                options.Callbacks.ConnectionError,
                new TrojanInboundConnectionErrorContext
                {
                    Exception = ex,
                    RemoteEndPoint = connection.LogRemoteEndPoint ?? effectiveRemoteEndPoint
                });
        }
    }

    private static SslServerAuthenticationOptions BuildAuthenticationOptions(
        VmessTlsListenerRuntime listener,
        System.Security.Cryptography.X509Certificates.X509Certificate2 certificate)
    {
        var options = new SslServerAuthenticationOptions
        {
            ServerCertificate = certificate,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            CertificateRevocationCheckMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck,
            ClientCertificateRequired = false
        };

        if (listener.ApplicationProtocols.Count > 0)
        {
            options.ApplicationProtocols = listener.ApplicationProtocols
                .Where(static value => !string.IsNullOrWhiteSpace(value))
                .Select(static value => new SslApplicationProtocol(value))
                .ToList();
        }

        return options;
    }

    private async Task HandleTlsConnectionAsync(
        SslStream sslStream,
        VmessInboundServerOptions options,
        VmessTlsListenerRuntime listener,
        EndPoint? remoteEndPoint,
        EndPoint? localEndPoint,
        IPEndPoint? originalDestinationEndPoint,
        CancellationToken cancellationToken)
    {
        var negotiatedAlpn = Encoding.ASCII.GetString(sslStream.NegotiatedApplicationProtocol.Protocol.Span);

        if (!listener.IsShared)
        {
            var inbound = listener.RawTlsInbound ?? listener.WebSocketInbound ?? throw new InvalidOperationException("VMess listener has no inbound definition.");
            await HandleResolvedInboundAsync(
                sslStream,
                options,
                inbound,
                sslStream.TargetHostName ?? string.Empty,
                negotiatedAlpn,
                remoteEndPoint,
                localEndPoint,
                originalDestinationEndPoint,
                cancellationToken).ConfigureAwait(false);
            return;
        }

        var initialPayload = await ReadInitialPayloadAsync(sslStream, cancellationToken).ConfigureAwait(false);
        var prefixedStream = new PrefixedReadStream(sslStream, initialPayload);
        var inboundSelection = VmessInboundRuntimePlanner.SelectInbound(listener, initialPayload)
            ?? throw new InvalidOperationException("VMess shared listener could not resolve an inbound transport.");

        await HandleResolvedInboundAsync(
            prefixedStream,
            options,
            inboundSelection,
            sslStream.TargetHostName ?? string.Empty,
            negotiatedAlpn,
            remoteEndPoint,
            localEndPoint,
            originalDestinationEndPoint,
            cancellationToken).ConfigureAwait(false);
    }

    private async Task HandleResolvedInboundAsync(
        Stream stream,
        VmessInboundServerOptions options,
        VmessTlsInboundRuntime inbound,
        string serverName,
        string alpn,
        EndPoint? remoteEndPoint,
        EndPoint? localEndPoint,
        IPEndPoint? originalDestinationEndPoint,
        CancellationToken cancellationToken)
    {
        if (string.Equals(inbound.Transport, InboundTransports.Wss, StringComparison.Ordinal))
        {
            await using var webSocketStream = await WebSocketServerHandshake.AcceptAsync(
                stream,
                new WebSocketServerHandshakeOptions
                {
                    Host = inbound.Host,
                    Path = inbound.Path,
                    EarlyDataBytes = inbound.EarlyDataBytes,
                    HeartbeatPeriodSeconds = inbound.HeartbeatPeriodSeconds
                },
                cancellationToken).ConfigureAwait(false);

            await _vmessInboundConnectionHandler.HandleAsync(
                webSocketStream,
                CreateSessionOptions(options, inbound, serverName, alpn, remoteEndPoint, localEndPoint, originalDestinationEndPoint),
                cancellationToken).ConfigureAwait(false);
            return;
        }

        await _vmessInboundConnectionHandler.HandleAsync(
            stream,
            CreateSessionOptions(options, inbound, serverName, alpn, remoteEndPoint, localEndPoint, originalDestinationEndPoint),
            cancellationToken).ConfigureAwait(false);
    }

    private static VmessInboundSessionOptions CreateSessionOptions(
        VmessInboundServerOptions options,
        VmessTlsInboundRuntime inbound,
        string serverName,
        string alpn,
        EndPoint? remoteEndPoint,
        EndPoint? localEndPoint,
        IPEndPoint? originalDestinationEndPoint)
        => new()
        {
            InboundTag = inbound.Tag,
            HandshakeTimeoutSeconds = inbound.HandshakeTimeoutSeconds,
            ConnectTimeoutSeconds = options.Limits.ConnectTimeoutSeconds,
            ConnectionIdleSeconds = options.Limits.ConnectionIdleSeconds,
            UplinkOnlySeconds = options.Limits.UplinkOnlySeconds,
            DownlinkOnlySeconds = options.Limits.DownlinkOnlySeconds,
            ServerName = serverName,
            Alpn = alpn,
            RemoteEndPoint = remoteEndPoint,
            LocalEndPoint = localEndPoint,
            OriginalDestinationEndPoint = inbound.ReceiveOriginalDestination ? originalDestinationEndPoint : null,
            UseCone = options.UseCone,
            ReceiveOriginalDestination = inbound.ReceiveOriginalDestination,
            DrainOnHandshakeFailure = true,
            Sniffing = inbound.Sniffing,
            Users = inbound.Users,
            RuntimeState = inbound.RuntimeState
        };

    private static async Task<byte[]> ReadInitialPayloadAsync(Stream stream, CancellationToken cancellationToken)
    {
        var buffer = new byte[4096];
        var read = 0;

        while (read < 64)
        {
            var current = await stream.ReadAsync(buffer.AsMemory(read, buffer.Length - read), cancellationToken).ConfigureAwait(false);
            if (current == 0)
            {
                break;
            }

            read += current;
            if (read == buffer.Length)
            {
                break;
            }
        }

        return read == buffer.Length ? buffer : buffer.AsSpan(0, read).ToArray();
    }

    private static Task WaitForCancellationAsync(CancellationToken cancellationToken)
        => Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);

    private static void InvokeSafely<TContext>(Action<TContext>? callback, TContext context)
    {
        if (callback is null)
        {
            return;
        }

        try
        {
            callback(context);
        }
        catch
        {
        }
    }

    private sealed record ListenerRuntime(VmessTlsListenerRuntime Definition, ListenerHandle Handle);
}
