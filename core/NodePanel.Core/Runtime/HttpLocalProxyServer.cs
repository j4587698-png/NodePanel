using System.Text;
using System.Runtime.InteropServices;

namespace NodePanel.Core.Runtime;

public sealed class HttpLocalProxyServer
{
    private const int MaxHeaderBytes = 64 * 1024;

    private readonly IDispatcher _dispatcher;
    private readonly RelayService _relayService;

    public HttpLocalProxyServer(IDispatcher dispatcher, RelayService relayService)
    {
        _dispatcher = dispatcher;
        _relayService = relayService;
    }

    public async Task RunAsync(HttpLocalProxyServerOptions options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (options.Listeners.Count == 0)
        {
            return;
        }

        var activeListeners = new List<ListenerRuntime>(options.Listeners.Count);
        try
        {
            foreach (var listener in options.Listeners)
            {
                var handle = ListenerHandle.Create(listener.Binding);
                activeListeners.Add(new ListenerRuntime(listener, handle));
                options.Callbacks.ListenerStarted?.Invoke(listener);
            }

            var acceptTasks = activeListeners
                .Select(listener => AcceptLoopAsync(listener, options, cancellationToken))
                .ToArray();
            var acceptGroup = Task.WhenAll(acceptTasks);
            var completed = await Task.WhenAny(acceptGroup, WaitForCancellationAsync(cancellationToken)).ConfigureAwait(false);

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

            if (completed == acceptGroup && acceptGroup.Exception is not null)
            {
                throw acceptGroup.Exception.InnerExceptions.Count == 1
                    ? acceptGroup.Exception.InnerExceptions[0]
                    : acceptGroup.Exception;
            }
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
        HttpLocalProxyServerOptions options,
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
            catch (System.Net.Sockets.SocketException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }

            _ = Task.Run(
                () => HandleAcceptedConnectionAsync(connection, listener.Definition, options, cancellationToken),
                CancellationToken.None);
        }
    }

    private async Task HandleAcceptedConnectionAsync(
        AcceptedConnection connection,
        LocalProxyListenerDefinition listener,
        HttpLocalProxyServerOptions options,
        CancellationToken cancellationToken)
    {
        await using var connectionLease = connection;
        try
        {
            using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            handshakeCts.CancelAfter(TimeSpan.FromSeconds(listener.HandshakeTimeoutSeconds));

            var headerBlock = await ReadHeaderBlockAsync(connection.Stream, handshakeCts.Token).ConfigureAwait(false);
            if (headerBlock is null)
            {
                return;
            }

            if (!TryParseRequest(headerBlock.HeaderBytes, out var request))
            {
                await WriteBadGatewayAsync(connection.Stream, cancellationToken).ConfigureAwait(false);
                return;
            }

            var proxyOptions = CreateConnectionOptions(listener, connection, options.Limits);
            var context = new DispatchContext
            {
                InboundProtocol = LocalInboundProtocols.Http,
                InboundTag = listener.Tag,
                DetectedProtocol = request.IsConnect
                    ? request.Port == 443 ? RoutingProtocols.Tls : string.Empty
                    : RoutingProtocols.Http,
                DetectedDomain = request.Host,
                ConnectTimeoutSeconds = proxyOptions.ConnectTimeoutSeconds,
                ConnectionIdleSeconds = proxyOptions.ConnectionIdleSeconds,
                UplinkOnlySeconds = proxyOptions.UplinkOnlySeconds,
                DownlinkOnlySeconds = proxyOptions.DownlinkOnlySeconds,
                SourceEndPoint = proxyOptions.RemoteEndPoint,
                LocalEndPoint = proxyOptions.LocalEndPoint,
                OriginalDestinationHost = request.Host,
                OriginalDestinationPort = request.Port
            };

            await using var remoteStream = await _dispatcher.DispatchTcpAsync(
                    context,
                    new DispatchDestination
                    {
                        Host = request.Host,
                        Port = request.Port,
                        Network = DispatchNetwork.Tcp
                    },
                    cancellationToken)
                .ConfigureAwait(false);

            if (request.IsConnect)
            {
                await WriteConnectEstablishedAsync(connection.Stream, cancellationToken).ConfigureAwait(false);
                await _relayService.RelayAsync(connection.Stream, remoteStream, proxyOptions, cancellationToken).ConfigureAwait(false);
                return;
            }

            await remoteStream.WriteAsync(request.RewrittenHeaderBytes, cancellationToken).ConfigureAwait(false);
            if (headerBlock.Remainder.Length > 0)
            {
                await remoteStream.WriteAsync(headerBlock.Remainder, cancellationToken).ConfigureAwait(false);
            }

            await remoteStream.FlushAsync(cancellationToken).ConfigureAwait(false);
            await _relayService.RelayAsync(connection.Stream, remoteStream, proxyOptions, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            options.Callbacks.ConnectionError?.Invoke(new LocalProxyConnectionErrorContext
            {
                Protocol = LocalInboundProtocols.Http,
                InboundTag = listener.Tag,
                Exception = ex,
                RemoteEndPoint = connection.LogRemoteEndPoint ?? connection.RemoteEndPoint
            });
        }
    }

    private static async ValueTask<HeaderBlock?> ReadHeaderBlockAsync(Stream stream, CancellationToken cancellationToken)
    {
        var buffer = new byte[1024];
        var collected = new List<byte>(1024);

        while (collected.Count < MaxHeaderBytes)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return null;
            }

            collected.AddRange(buffer.AsSpan(0, read).ToArray());
            var terminator = FindHeaderTerminator(CollectionsMarshal.AsSpan(collected));
            if (terminator < 0)
            {
                continue;
            }

            var headerBytes = collected.Take(terminator).ToArray();
            var remainder = collected.Skip(terminator + 4).ToArray();
            return new HeaderBlock
            {
                HeaderBytes = headerBytes,
                Remainder = remainder
            };
        }

        return null;
    }

    private static int FindHeaderTerminator(ReadOnlySpan<byte> buffer)
    {
        for (var index = 0; index <= buffer.Length - 4; index++)
        {
            if (buffer[index] == (byte)'\r' &&
                buffer[index + 1] == (byte)'\n' &&
                buffer[index + 2] == (byte)'\r' &&
                buffer[index + 3] == (byte)'\n')
            {
                return index;
            }
        }

        return -1;
    }

    private static bool TryParseRequest(byte[] headerBytes, out ParsedHttpProxyRequest request)
    {
        request = default!;
        var text = Encoding.ASCII.GetString(headerBytes);
        var lines = text.Split("\r\n", StringSplitOptions.None);
        if (lines.Length == 0)
        {
            return false;
        }

        var firstLineParts = lines[0].Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (firstLineParts.Length != 3)
        {
            return false;
        }

        var method = firstLineParts[0].Trim();
        var target = firstLineParts[1].Trim();
        var version = firstLineParts[2].Trim();
        var headers = lines
            .Skip(1)
            .Where(static line => !string.IsNullOrWhiteSpace(line))
            .Select(ParseHeader)
            .Where(static header => header.HasValue)
            .Select(static header => header!.Value)
            .ToList();

        if (string.Equals(method, "CONNECT", StringComparison.OrdinalIgnoreCase))
        {
            if (!TryParseAuthority(target, out var host, out var port))
            {
                return false;
            }

            request = new ParsedHttpProxyRequest
            {
                Host = host,
                Port = port,
                IsConnect = true,
                RewrittenHeaderBytes = Array.Empty<byte>()
            };
            return true;
        }

        if (!TryResolveHttpTarget(target, headers, out var resolvedHost, out var resolvedPort, out var pathAndQuery))
        {
            return false;
        }

        var builder = new StringBuilder();
        builder.Append(method).Append(' ').Append(pathAndQuery).Append(' ').Append(version).Append("\r\n");

        var hasHostHeader = false;
        foreach (var header in headers)
        {
            if (header.Key.Equals("Proxy-Connection", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (header.Key.Equals("Host", StringComparison.OrdinalIgnoreCase))
            {
                hasHostHeader = true;
            }

            builder.Append(header.Key).Append(": ").Append(header.Value).Append("\r\n");
        }

        if (!hasHostHeader)
        {
            builder.Append("Host: ").Append(resolvedHost);
            if (resolvedPort is not (80 or 443))
            {
                builder.Append(':').Append(resolvedPort);
            }

            builder.Append("\r\n");
        }

        builder.Append("\r\n");
        request = new ParsedHttpProxyRequest
        {
            Host = resolvedHost,
            Port = resolvedPort,
            IsConnect = false,
            RewrittenHeaderBytes = Encoding.ASCII.GetBytes(builder.ToString())
        };
        return true;
    }

    private static KeyValuePair<string, string>? ParseHeader(string line)
    {
        var separator = line.IndexOf(':');
        if (separator <= 0)
        {
            return null;
        }

        var name = line[..separator].Trim();
        var value = line[(separator + 1)..].Trim();
        if (name.Length == 0)
        {
            return null;
        }

        return new KeyValuePair<string, string>(name, value);
    }

    private static bool TryResolveHttpTarget(
        string target,
        IReadOnlyList<KeyValuePair<string, string>> headers,
        out string host,
        out int port,
        out string pathAndQuery)
    {
        if (Uri.TryCreate(target, UriKind.Absolute, out var absoluteUri))
        {
            if (!absoluteUri.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase))
            {
                host = string.Empty;
                port = 0;
                pathAndQuery = string.Empty;
                return false;
            }

            host = absoluteUri.Host;
            port = absoluteUri.IsDefaultPort
                ? absoluteUri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase) ? 443 : 80
                : absoluteUri.Port;
            pathAndQuery = string.IsNullOrWhiteSpace(absoluteUri.PathAndQuery) ? "/" : absoluteUri.PathAndQuery;
            return host.Length > 0 && port > 0;
        }

        var hostHeader = headers.FirstOrDefault(header => header.Key.Equals("Host", StringComparison.OrdinalIgnoreCase));
        if (hostHeader.Key is null || !TryParseHostHeader(hostHeader.Value, out host, out port))
        {
            host = string.Empty;
            port = 0;
            pathAndQuery = string.Empty;
            return false;
        }

        pathAndQuery = string.IsNullOrWhiteSpace(target) ? "/" : target;
        return true;
    }

    private static bool TryParseAuthority(string value, out string host, out int port)
    {
        host = string.Empty;
        port = 0;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var trimmed = value.Trim();
        if (trimmed.StartsWith("[", StringComparison.Ordinal))
        {
            var closing = trimmed.IndexOf(']');
            if (closing <= 1 || closing + 2 >= trimmed.Length || trimmed[closing + 1] != ':')
            {
                return false;
            }

            host = trimmed[1..closing];
            return int.TryParse(trimmed[(closing + 2)..], out port) && port is > 0 and <= 65535;
        }

        var separator = trimmed.LastIndexOf(':');
        if (separator <= 0 || separator == trimmed.Length - 1)
        {
            return false;
        }

        host = trimmed[..separator];
        return int.TryParse(trimmed[(separator + 1)..], out port) && port is > 0 and <= 65535;
    }

    private static bool TryParseHostHeader(string value, out string host, out int port)
    {
        if (TryParseAuthority(value, out host, out port))
        {
            return true;
        }

        host = string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim();
        port = 80;
        return host.Length > 0;
    }

    private static Task WriteConnectEstablishedAsync(Stream stream, CancellationToken cancellationToken)
        => stream.WriteAsync(
                Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n"),
                cancellationToken)
            .AsTask();

    private static Task WriteBadGatewayAsync(Stream stream, CancellationToken cancellationToken)
        => stream.WriteAsync(
                Encoding.ASCII.GetBytes("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"),
                cancellationToken)
            .AsTask();

    private static LocalProxyConnectionOptions CreateConnectionOptions(
        LocalProxyListenerDefinition listener,
        AcceptedConnection connection,
        LocalProxyServerLimits limits)
        => new()
        {
            InboundTag = listener.Tag,
            HandshakeTimeoutSeconds = listener.HandshakeTimeoutSeconds,
            ConnectTimeoutSeconds = limits.ConnectTimeoutSeconds,
            ConnectionIdleSeconds = limits.ConnectionIdleSeconds,
            UplinkOnlySeconds = limits.UplinkOnlySeconds,
            DownlinkOnlySeconds = limits.DownlinkOnlySeconds,
            RemoteEndPoint = connection.RemoteEndPoint,
            LocalEndPoint = connection.LocalEndPoint
        };

    private static Task WaitForCancellationAsync(CancellationToken cancellationToken)
        => Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);

    private sealed record ListenerRuntime(LocalProxyListenerDefinition Definition, ListenerHandle Handle);

    private sealed record HeaderBlock
    {
        public byte[] HeaderBytes { get; init; } = Array.Empty<byte>();

        public byte[] Remainder { get; init; } = Array.Empty<byte>();
    }

    private sealed record ParsedHttpProxyRequest
    {
        public string Host { get; init; } = string.Empty;

        public int Port { get; init; }

        public bool IsConnect { get; init; }

        public byte[] RewrittenHeaderBytes { get; init; } = Array.Empty<byte>();
    }
}
