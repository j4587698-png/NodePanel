using System.Globalization;
using System.Text;

namespace NodePanel.Core.Runtime;

internal static class HttpInboundProcessor
{
    private const string HttpDispatchContentProtocol = "http/1.1";
    private const int MaxHeaderBytes = 64 * 1024;
    private const int MaxChunkLineBytes = 8 * 1024;
    private const int StreamCopyBufferBytes = 16 * 1024;

    public static async Task HandleAsync(
        Stream clientStream,
        IDispatcher dispatcher,
        IRuntimeRelayService relayService,
        IRuntimeSniffer runtimeSniffer,
        ProxyInboundConnectionOptions options,
        CancellationToken cancellationToken,
        Socks5LocalAuthenticationOptions? authentication = null)
    {
        ArgumentNullException.ThrowIfNull(clientStream);
        ArgumentNullException.ThrowIfNull(dispatcher);
        ArgumentNullException.ThrowIfNull(relayService);
        ArgumentNullException.ThrowIfNull(runtimeSniffer);
        ArgumentNullException.ThrowIfNull(options);

        var clientReader = new BufferedHttpStream(clientStream);

        while (!cancellationToken.IsCancellationRequested)
        {
            using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            handshakeCts.CancelAfter(TimeSpan.FromSeconds(options.HandshakeTimeoutSeconds));

            var headerBytes = await clientReader.ReadHeaderBlockAsync(handshakeCts.Token).ConfigureAwait(false);
            if (headerBytes is null)
            {
                return;
            }

            if (!TryParseRequest(headerBytes, options.AllowTransparent, out var request))
            {
                await WriteBadRequestAsync(clientStream, cancellationToken).ConfigureAwait(false);
                return;
            }

            var userId = string.Empty;
            if (authentication?.Enabled == true)
            {
                if (!TryAuthenticate(request.Headers, authentication, out userId))
                {
                    await WriteAuthenticationRequiredAsync(clientStream, cancellationToken).ConfigureAwait(false);
                    return;
                }
            }

            var context = RuntimeInboundDispatchContextFactory.Create(
                ProxyInboundProtocols.Http,
                options,
                RoutingNetworks.Tcp,
                userId: userId,
                scopedUserId: userId,
                network: RoutingNetworks.Tcp,
                originalDestinationHost: request.Host,
                originalDestinationPort: request.Port,
                detectedProtocol: request.IsConnect
                    ? request.Port == 443 ? RoutingProtocols.Tls : string.Empty
                    : RoutingProtocols.Http,
                detectedDomain: request.Host,
                content: request.Content);

            var connectInitialPayload = request.IsConnect
                ? clientReader.DrainBufferedBytes()
                : Array.Empty<byte>();
            if (connectInitialPayload.Length > 0)
            {
                context = context with
                {
                    InitialPayload = connectInitialPayload
                };
            }

            if (request.IsConnect)
            {
                await WriteConnectEstablishedAsync(clientStream, cancellationToken).ConfigureAwait(false);
                var dispatchResult = await RuntimeTcpDispatchPipeline.DispatchAsync(
                        dispatcher,
                        runtimeSniffer,
                        options.Sniffing,
                        CreateRelayInputStream(clientStream, connectInitialPayload),
                        context,
                        new DispatchDestination
                        {
                            Host = request.Host,
                            Port = request.Port,
                            Network = DispatchNetwork.Tcp
                        },
                        cancellationToken,
                        cancellationToken)
                    .ConfigureAwait(false);
                await using var remoteStream = dispatchResult.OutboundStream;
                await relayService
                    .RelayAsync(
                        dispatchResult.InboundStream,
                        remoteStream,
                        options,
                        cancellationToken)
                    .ConfigureAwait(false);
                return;
            }

            await using var remoteHttpStream = await dispatcher.DispatchTcpAsync(
                    context,
                    new DispatchDestination
                    {
                        Host = request.Host,
                        Port = request.Port,
                        Network = DispatchNetwork.Tcp
                    },
                    cancellationToken)
                .ConfigureAwait(false);

            var keepAlive = await HandlePlainHttpAsync(
                    clientStream,
                    clientReader,
                    remoteHttpStream,
                    request,
                    cancellationToken)
                .ConfigureAwait(false);
            if (!keepAlive)
            {
                return;
            }
        }
    }

    private static async Task<bool> HandlePlainHttpAsync(
        Stream clientStream,
        BufferedHttpStream clientReader,
        Stream remoteStream,
        ParsedHttpProxyRequest request,
        CancellationToken cancellationToken)
    {
        var remoteReader = new BufferedHttpStream(remoteStream);
        var requestTask = ForwardPlainHttpRequestAsync(
            clientReader,
            remoteStream,
            request,
            cancellationToken);
        var responseTask = ForwardPlainHttpResponseAsync(
            clientStream,
            remoteReader,
            request,
            cancellationToken);

        await Task.WhenAll(requestTask, responseTask).ConfigureAwait(false);
        return await responseTask.ConfigureAwait(false);
    }

    private static async Task ForwardPlainHttpRequestAsync(
        BufferedHttpStream clientReader,
        Stream remoteStream,
        ParsedHttpProxyRequest request,
        CancellationToken cancellationToken)
    {
        await remoteStream.WriteAsync(request.RewrittenHeaderBytes, cancellationToken).ConfigureAwait(false);
        await CopyBodyAsync(clientReader, remoteStream, request.BodyTransferMode, cancellationToken).ConfigureAwait(false);
        await remoteStream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<bool> ForwardPlainHttpResponseAsync(
        Stream clientStream,
        BufferedHttpStream remoteReader,
        ParsedHttpProxyRequest request,
        CancellationToken cancellationToken)
    {
        ParsedHttpProxyResponse? response;
        try
        {
            response = await ReadFinalResponseAsync(remoteReader, clientStream, request.Method, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is InvalidDataException or EndOfStreamException or IOException)
        {
            response = null;
        }

        if (response is null)
        {
            await WriteServiceUnavailableAsync(clientStream, cancellationToken).ConfigureAwait(false);
            await clientStream.FlushAsync(cancellationToken).ConfigureAwait(false);
            return false;
        }

        var keepAlive = request.KeepAliveRequested && response.CanKeepAlive;
        await WriteResponseAsync(clientStream, response, keepAlive, cancellationToken).ConfigureAwait(false);
        await CopyBodyAsync(remoteReader, clientStream, response.BodyTransferMode, cancellationToken).ConfigureAwait(false);
        await clientStream.FlushAsync(cancellationToken).ConfigureAwait(false);
        return keepAlive;
    }

    private static async Task<ParsedHttpProxyResponse?> ReadFinalResponseAsync(
        BufferedHttpStream remoteReader,
        Stream clientStream,
        string requestMethod,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            var headerBytes = await remoteReader.ReadHeaderBlockAsync(cancellationToken).ConfigureAwait(false);
            if (headerBytes is null)
            {
                return null;
            }

            if (!TryParseResponse(headerBytes, requestMethod, out var response))
            {
                return null;
            }

            if (response.IsInformational)
            {
                await clientStream.WriteAsync(headerBytes, cancellationToken).ConfigureAwait(false);
                await clientStream.WriteAsync("\r\n\r\n"u8.ToArray(), cancellationToken).ConfigureAwait(false);
                await clientStream.FlushAsync(cancellationToken).ConfigureAwait(false);
                continue;
            }
            return response;
        }
    }

    private static async Task WriteResponseAsync(
        Stream clientStream,
        ParsedHttpProxyResponse response,
        bool keepAlive,
        CancellationToken cancellationToken)
    {
        var headerBytes = BuildResponseHeaderBytes(response, keepAlive);
        await clientStream.WriteAsync(headerBytes, cancellationToken).ConfigureAwait(false);
    }

    private static byte[] BuildResponseHeaderBytes(ParsedHttpProxyResponse response, bool keepAlive)
    {
        var builder = new StringBuilder();
        builder.Append(response.Version).Append(' ').Append(response.StatusCode);
        if (!string.IsNullOrWhiteSpace(response.ReasonPhrase))
        {
            builder.Append(' ').Append(response.ReasonPhrase);
        }

        builder.Append("\r\n");

        foreach (var header in FilterHopByHopHeaders(response.Headers))
        {
            builder.Append(header.Key).Append(": ").Append(header.Value).Append("\r\n");
        }

        if (response.BodyTransferMode.Kind == HttpBodyTransferKind.Chunked)
        {
            builder.Append("Transfer-Encoding: chunked\r\n");
        }

        if (keepAlive)
        {
            builder.Append("Proxy-Connection: keep-alive\r\n");
            builder.Append("Connection: keep-alive\r\n");
            builder.Append("Keep-Alive: timeout=60\r\n");
        }
        else
        {
            builder.Append("Proxy-Connection: close\r\n");
            builder.Append("Connection: close\r\n");
        }

        builder.Append("\r\n");
        return Encoding.ASCII.GetBytes(builder.ToString());
    }

    private static Stream CreateRelayInputStream(Stream clientStream, byte[] bufferedBytes)
        => bufferedBytes.Length == 0
            ? clientStream
            : new PrefixedReadStream(clientStream, bufferedBytes);

    private static async Task CopyBodyAsync(
        BufferedHttpStream source,
        Stream destination,
        HttpBodyTransferMode bodyTransferMode,
        CancellationToken cancellationToken)
    {
        switch (bodyTransferMode.Kind)
        {
            case HttpBodyTransferKind.None:
                return;
            case HttpBodyTransferKind.ContentLength:
                await source.CopyExactToAsync(destination, bodyTransferMode.ContentLength, cancellationToken).ConfigureAwait(false);
                return;
            case HttpBodyTransferKind.Chunked:
                await source.CopyChunkedBodyToAsync(destination, cancellationToken).ConfigureAwait(false);
                return;
            case HttpBodyTransferKind.UntilEof:
                await source.CopyToEndAsync(destination, cancellationToken).ConfigureAwait(false);
                return;
            default:
                throw new InvalidOperationException($"Unsupported HTTP body transfer mode: {bodyTransferMode.Kind}.");
        }
    }

    private static bool TryParseRequest(
        byte[] headerBytes,
        bool allowTransparent,
        out ParsedHttpProxyRequest request)
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
                Method = method,
                Version = version,
                Host = host,
                Port = port,
                IsConnect = true,
                Headers = headers,
                KeepAliveRequested = false,
                RewrittenHeaderBytes = Array.Empty<byte>(),
                BodyTransferMode = HttpBodyTransferMode.None,
                Content = DispatchContent.Empty
            };
            return true;
        }

        if (!TryResolveHttpTarget(
                target,
                headers,
                allowTransparent,
                out var resolvedHost,
                out var resolvedPort,
                out var pathAndQuery,
                out var overrideHostHeaderValue))
        {
            return false;
        }

        var bodyTransferMode = ResolveRequestBodyTransferMode(headers);
        var path = ExtractPathForContent(pathAndQuery);
        var builder = new StringBuilder();
        builder.Append(method).Append(' ').Append(pathAndQuery).Append(' ').Append(version).Append("\r\n");

        var headersToForward = FilterHopByHopHeaders(headers);
        var hasHostHeader = false;
        var hasUserAgentHeader = false;
        foreach (var header in headersToForward)
        {
            if (header.Key.Equals("Host", StringComparison.OrdinalIgnoreCase))
            {
                if (!string.IsNullOrWhiteSpace(overrideHostHeaderValue))
                {
                    continue;
                }

                hasHostHeader = true;
            }

            if (header.Key.Equals("User-Agent", StringComparison.OrdinalIgnoreCase))
            {
                hasUserAgentHeader = true;
            }

            builder.Append(header.Key).Append(": ").Append(header.Value).Append("\r\n");
        }

        if (!string.IsNullOrWhiteSpace(overrideHostHeaderValue))
        {
            builder.Append("Host: ").Append(overrideHostHeaderValue).Append("\r\n");
        }
        else if (!hasHostHeader)
        {
            builder.Append("Host: ").Append(resolvedHost);
            if (resolvedPort is not (80 or 443))
            {
                builder.Append(':').Append(resolvedPort);
            }

            builder.Append("\r\n");
        }

        if (bodyTransferMode.Kind == HttpBodyTransferKind.Chunked)
        {
            builder.Append("Transfer-Encoding: chunked\r\n");
        }

        if (!hasUserAgentHeader)
        {
            builder.Append("User-Agent: \r\n");
        }

        builder.Append("Connection: close\r\n");
        builder.Append("\r\n");

        request = new ParsedHttpProxyRequest
        {
            Method = method,
            Version = version,
            Host = resolvedHost,
            Port = resolvedPort,
            IsConnect = false,
            Headers = headers,
            KeepAliveRequested = headers.Any(static header =>
                header.Key.Equals("Proxy-Connection", StringComparison.OrdinalIgnoreCase) &&
                header.Value.Trim().Equals("keep-alive", StringComparison.OrdinalIgnoreCase)),
            RewrittenHeaderBytes = Encoding.ASCII.GetBytes(builder.ToString()),
            BodyTransferMode = bodyTransferMode,
            Content = CreateDispatchContent(method, path, headersToForward, hasUserAgentHeader)
        };
        return true;
    }

    private static bool TryParseResponse(
        byte[] headerBytes,
        string requestMethod,
        out ParsedHttpProxyResponse response)
    {
        response = default!;
        var text = Encoding.ASCII.GetString(headerBytes);
        var lines = text.Split("\r\n", StringSplitOptions.None);
        if (lines.Length == 0)
        {
            return false;
        }

        var firstSpace = lines[0].IndexOf(' ');
        if (firstSpace <= 0)
        {
            return false;
        }

        var secondSpace = lines[0].IndexOf(' ', firstSpace + 1);
        var version = lines[0][..firstSpace].Trim();
        var statusText = secondSpace > firstSpace
            ? lines[0].Substring(firstSpace + 1, secondSpace - firstSpace - 1).Trim()
            : lines[0][(firstSpace + 1)..].Trim();
        if (!version.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase) ||
            !int.TryParse(statusText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var statusCode))
        {
            return false;
        }

        var reasonPhrase = secondSpace > firstSpace
            ? lines[0][(secondSpace + 1)..].Trim()
            : string.Empty;
        var headers = lines
            .Skip(1)
            .Where(static line => !string.IsNullOrWhiteSpace(line))
            .Select(ParseHeader)
            .Where(static header => header.HasValue)
            .Select(static header => header!.Value)
            .ToList();

        var bodyTransferMode = ResolveResponseBodyTransferMode(requestMethod, statusCode, headers);
        response = new ParsedHttpProxyResponse
        {
            Version = version,
            StatusCode = statusCode,
            ReasonPhrase = reasonPhrase,
            Headers = headers,
            BodyTransferMode = bodyTransferMode,
            CanKeepAlive = bodyTransferMode.Kind is HttpBodyTransferKind.None or HttpBodyTransferKind.ContentLength,
            IsInformational = statusCode is >= 100 and < 200,
            BufferedBody = Array.Empty<byte>()
        };
        return true;
    }

    private static HttpBodyTransferMode ResolveRequestBodyTransferMode(
        IReadOnlyList<KeyValuePair<string, string>> headers)
    {
        if (HasChunkedTransferEncoding(headers))
        {
            return HttpBodyTransferMode.Chunked;
        }

        return TryGetContentLength(headers, out var contentLength)
            ? new HttpBodyTransferMode(HttpBodyTransferKind.ContentLength, contentLength)
            : HttpBodyTransferMode.None;
    }

    private static HttpBodyTransferMode ResolveResponseBodyTransferMode(
        string requestMethod,
        int statusCode,
        IReadOnlyList<KeyValuePair<string, string>> headers)
    {
        if (string.Equals(requestMethod, "HEAD", StringComparison.OrdinalIgnoreCase) ||
            statusCode is >= 100 and < 200 or 204 or 304)
        {
            return HttpBodyTransferMode.None;
        }

        if (HasChunkedTransferEncoding(headers))
        {
            return HttpBodyTransferMode.Chunked;
        }

        return TryGetContentLength(headers, out var contentLength)
            ? new HttpBodyTransferMode(HttpBodyTransferKind.ContentLength, contentLength)
            : HttpBodyTransferMode.UntilEof;
    }

    private static bool HasChunkedTransferEncoding(
        IReadOnlyList<KeyValuePair<string, string>> headers)
    {
        var header = headers.FirstOrDefault(static pair =>
            pair.Key.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase));
        if (header.Key is null)
        {
            return false;
        }

        return header.Value
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Any(static value => value.Equals("chunked", StringComparison.OrdinalIgnoreCase));
    }

    private static bool TryGetContentLength(
        IReadOnlyList<KeyValuePair<string, string>> headers,
        out long contentLength)
    {
        var header = headers.FirstOrDefault(static pair =>
            pair.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase));
        if (header.Key is not null &&
            long.TryParse(header.Value.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out contentLength) &&
            contentLength >= 0)
        {
            return true;
        }

        contentLength = 0;
        return false;
    }

    private static bool TryAuthenticate(
        IReadOnlyList<KeyValuePair<string, string>> headers,
        Socks5LocalAuthenticationOptions authentication,
        out string userId)
    {
        var header = headers.FirstOrDefault(static candidate =>
            candidate.Key.Equals("Proxy-Authorization", StringComparison.OrdinalIgnoreCase));
        if (header.Key is null ||
            !TryParseBasicAuth(header.Value, out var username, out var password) ||
            !authentication.TryAuthenticate(username, password))
        {
            userId = string.Empty;
            return false;
        }

        userId = username;
        return true;
    }

    private static bool TryParseBasicAuth(
        string rawValue,
        out string username,
        out string password)
    {
        username = string.Empty;
        password = string.Empty;

        const string prefix = "Basic ";
        if (!rawValue.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        byte[] decoded;
        try
        {
            decoded = Convert.FromBase64String(rawValue[prefix.Length..].Trim());
        }
        catch (FormatException)
        {
            return false;
        }

        var combined = Encoding.UTF8.GetString(decoded);
        var separator = combined.IndexOf(':');
        if (separator < 0)
        {
            return false;
        }

        username = combined[..separator];
        password = combined[(separator + 1)..];
        return true;
    }

    private static IReadOnlyList<KeyValuePair<string, string>> FilterHopByHopHeaders(
        IReadOnlyList<KeyValuePair<string, string>> headers)
    {
        var excluded = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Proxy-Connection",
            "Proxy-Authenticate",
            "Proxy-Authorization",
            "TE",
            "Trailers",
            "Transfer-Encoding",
            "Upgrade",
            "Connection"
        };

        foreach (var header in headers.Where(static header =>
                     header.Key.Equals("Connection", StringComparison.OrdinalIgnoreCase)))
        {
            foreach (var connectionHeader in header.Value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                excluded.Add(connectionHeader);
            }
        }

        return headers
            .Where(header => !excluded.Contains(header.Key))
            .ToArray();
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

    private static DispatchContent CreateDispatchContent(
        string method,
        string path,
        IReadOnlyList<KeyValuePair<string, string>> headers,
        bool hasUserAgentHeader)
    {
        var attributes = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [":method"] = method.ToUpperInvariant(),
            [":path"] = path
        };

        foreach (var header in headers)
        {
            if (header.Key.Equals("Host", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var normalizedKey = header.Key.ToLowerInvariant();
            attributes.TryAdd(normalizedKey, header.Value);
        }

        if (!hasUserAgentHeader)
        {
            attributes["user-agent"] = string.Empty;
        }

        return new DispatchContent
        {
            Protocol = HttpDispatchContentProtocol,
            Attributes = attributes
        };
    }

    private static string ExtractPathForContent(string pathAndQuery)
    {
        if (string.IsNullOrWhiteSpace(pathAndQuery))
        {
            return "/";
        }

        var path = pathAndQuery;
        foreach (var separator in new[] { path.IndexOf('?'), path.IndexOf('#') })
        {
            if (separator >= 0)
            {
                path = path[..separator];
            }
        }

        return path.Length == 0 ? "/" : path;
    }

    private static bool TryResolveHttpTarget(
        string target,
        IReadOnlyList<KeyValuePair<string, string>> headers,
        bool allowTransparent,
        out string host,
        out int port,
        out string pathAndQuery,
        out string overrideHostHeaderValue)
    {
        if (Uri.TryCreate(target, UriKind.Absolute, out var absoluteUri))
        {
            if (!absoluteUri.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase) &&
                !absoluteUri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
            {
                host = string.Empty;
                port = 0;
                pathAndQuery = string.Empty;
                overrideHostHeaderValue = string.Empty;
                return false;
            }

            host = absoluteUri.Host;
            port = absoluteUri.IsDefaultPort
                ? absoluteUri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase) ? 443 : 80
                : absoluteUri.Port;
            pathAndQuery = string.IsNullOrWhiteSpace(absoluteUri.PathAndQuery) ? "/" : absoluteUri.PathAndQuery;
            overrideHostHeaderValue = ExtractAuthorityFromAbsoluteTarget(target);
            return host.Length > 0 && port > 0;
        }

        if (!allowTransparent)
        {
            host = string.Empty;
            port = 0;
            pathAndQuery = string.Empty;
            overrideHostHeaderValue = string.Empty;
            return false;
        }

        var hostHeader = headers.FirstOrDefault(static header => header.Key.Equals("Host", StringComparison.OrdinalIgnoreCase));
        if (hostHeader.Key is null || !TryParseHostHeader(hostHeader.Value, out host, out port))
        {
            host = string.Empty;
            port = 0;
            pathAndQuery = string.Empty;
            overrideHostHeaderValue = string.Empty;
            return false;
        }

        pathAndQuery = string.IsNullOrWhiteSpace(target) ? "/" : target;
        overrideHostHeaderValue = string.Empty;
        return true;
    }

    private static string ExtractAuthorityFromAbsoluteTarget(string target)
    {
        var schemeSeparator = target.IndexOf("://", StringComparison.Ordinal);
        if (schemeSeparator < 0 || schemeSeparator + 3 >= target.Length)
        {
            return string.Empty;
        }

        var authorityStart = schemeSeparator + 3;
        var authorityEnd = target.Length;
        foreach (var separator in new[]
                 {
                     target.IndexOf('/', authorityStart),
                     target.IndexOf('?', authorityStart),
                     target.IndexOf('#', authorityStart)
                 })
        {
            if (separator >= 0)
            {
                authorityEnd = Math.Min(authorityEnd, separator);
            }
        }

        var authority = target[authorityStart..authorityEnd];
        var userInfoSeparator = authority.LastIndexOf('@');
        return userInfoSeparator >= 0
            ? authority[(userInfoSeparator + 1)..]
            : authority;
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

    private static Task WriteBadRequestAsync(Stream stream, CancellationToken cancellationToken)
        => stream.WriteAsync(
                Encoding.ASCII.GetBytes("HTTP/1.1 400 Bad Request\r\nConnection: close\r\nProxy-Connection: close\r\n\r\n"),
                cancellationToken)
            .AsTask();

    private static Task WriteServiceUnavailableAsync(Stream stream, CancellationToken cancellationToken)
        => stream.WriteAsync(
                Encoding.ASCII.GetBytes("HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nProxy-Connection: close\r\n\r\n"),
                cancellationToken)
            .AsTask();

    private static Task WriteAuthenticationRequiredAsync(Stream stream, CancellationToken cancellationToken)
        => stream.WriteAsync(
                Encoding.ASCII.GetBytes("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nConnection: close\r\nProxy-Connection: close\r\n\r\n"),
                cancellationToken)
            .AsTask();

    private enum HttpBodyTransferKind
    {
        None = 0,
        ContentLength = 1,
        Chunked = 2,
        UntilEof = 3
    }

    private readonly record struct HttpBodyTransferMode(HttpBodyTransferKind Kind, long ContentLength = 0)
    {
        public static HttpBodyTransferMode None => new(HttpBodyTransferKind.None);

        public static HttpBodyTransferMode Chunked => new(HttpBodyTransferKind.Chunked);

        public static HttpBodyTransferMode UntilEof => new(HttpBodyTransferKind.UntilEof);
    }

    private sealed record ParsedHttpProxyRequest
    {
        public string Method { get; init; } = string.Empty;

        public string Version { get; init; } = string.Empty;

        public string Host { get; init; } = string.Empty;

        public int Port { get; init; }

        public bool IsConnect { get; init; }

        public bool KeepAliveRequested { get; init; }

        public HttpBodyTransferMode BodyTransferMode { get; init; } = HttpBodyTransferMode.None;

        public IReadOnlyList<KeyValuePair<string, string>> Headers { get; init; } = Array.Empty<KeyValuePair<string, string>>();

        public byte[] RewrittenHeaderBytes { get; init; } = Array.Empty<byte>();

        public DispatchContent Content { get; init; } = DispatchContent.Empty;
    }

    private sealed record ParsedHttpProxyResponse
    {
        public string Version { get; init; } = string.Empty;

        public int StatusCode { get; init; }

        public string ReasonPhrase { get; init; } = string.Empty;

        public bool IsInformational { get; init; }

        public bool CanKeepAlive { get; init; }

        public HttpBodyTransferMode BodyTransferMode { get; init; } = HttpBodyTransferMode.None;

        public IReadOnlyList<KeyValuePair<string, string>> Headers { get; init; } = Array.Empty<KeyValuePair<string, string>>();

        public byte[] BufferedBody { get; init; } = Array.Empty<byte>();
    }

    private sealed class BufferedHttpStream
    {
        private readonly Stream _stream;
        private byte[] _buffer = new byte[StreamCopyBufferBytes];
        private int _start;
        private int _end;

        public BufferedHttpStream(Stream stream)
        {
            _stream = stream;
        }

        public async ValueTask<byte[]?> ReadHeaderBlockAsync(CancellationToken cancellationToken)
        {
            while (true)
            {
                var headerEnd = FindHeaderTerminator(_buffer.AsSpan(_start, BufferedCount));
                if (headerEnd >= 0)
                {
                    var headerBytes = _buffer.AsSpan(_start, headerEnd).ToArray();
                    Consume(headerEnd + 4);
                    return headerBytes;
                }

                if (BufferedCount >= MaxHeaderBytes)
                {
                    throw new InvalidDataException("HTTP header exceeds maximum size.");
                }

                var read = await FillAsync(cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    if (BufferedCount == 0)
                    {
                        return null;
                    }

                    throw new InvalidDataException("HTTP header is incomplete.");
                }
            }
        }

        public byte[] DrainBufferedBytes()
        {
            var bytes = _buffer.AsSpan(_start, BufferedCount).ToArray();
            _start = 0;
            _end = 0;
            return bytes;
        }

        public async Task CopyExactToAsync(
            Stream destination,
            long length,
            CancellationToken cancellationToken)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(length);

            while (length > 0)
            {
                if (BufferedCount > 0)
                {
                    var toWrite = (int)Math.Min(length, BufferedCount);
                    await destination.WriteAsync(_buffer.AsMemory(_start, toWrite), cancellationToken).ConfigureAwait(false);
                    Consume(toWrite);
                    length -= toWrite;
                    continue;
                }

                var buffer = new byte[(int)Math.Min(StreamCopyBufferBytes, length)];
                var read = await _stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    throw new EndOfStreamException("HTTP body ended unexpectedly.");
                }

                await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                length -= read;
            }
        }

        public async Task CopyChunkedBodyToAsync(
            Stream destination,
            CancellationToken cancellationToken)
        {
            while (true)
            {
                var line = await ReadLineAsync(MaxChunkLineBytes, cancellationToken).ConfigureAwait(false)
                           ?? throw new EndOfStreamException("HTTP chunk header is incomplete.");
                await destination.WriteAsync(line, cancellationToken).ConfigureAwait(false);

                var chunkSize = ParseChunkSize(line);
                if (chunkSize == 0)
                {
                    while (true)
                    {
                        var trailerLine = await ReadLineAsync(MaxHeaderBytes, cancellationToken).ConfigureAwait(false)
                                          ?? throw new EndOfStreamException("HTTP chunk trailer is incomplete.");
                        await destination.WriteAsync(trailerLine, cancellationToken).ConfigureAwait(false);

                        if (trailerLine.Length == 2 &&
                            trailerLine[0] == (byte)'\r' &&
                            trailerLine[1] == (byte)'\n')
                        {
                            return;
                        }
                    }
                }

                await CopyExactToAsync(destination, chunkSize, cancellationToken).ConfigureAwait(false);
                var chunkTerminator = await ReadExactAsync(2, cancellationToken).ConfigureAwait(false);
                if (chunkTerminator[0] != (byte)'\r' || chunkTerminator[1] != (byte)'\n')
                {
                    throw new InvalidDataException("HTTP chunk body is malformed.");
                }

                await destination.WriteAsync(chunkTerminator, cancellationToken).ConfigureAwait(false);
            }
        }

        public async Task CopyToEndAsync(
            Stream destination,
            CancellationToken cancellationToken)
        {
            if (BufferedCount > 0)
            {
                await destination.WriteAsync(_buffer.AsMemory(_start, BufferedCount), cancellationToken).ConfigureAwait(false);
                _start = 0;
                _end = 0;
            }

            var buffer = new byte[StreamCopyBufferBytes];
            while (true)
            {
                var read = await _stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    return;
                }

                await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            }
        }

        private async ValueTask<byte[]?> ReadLineAsync(int maxBytes, CancellationToken cancellationToken)
        {
            while (true)
            {
                var lineEnd = FindLineTerminator(_buffer.AsSpan(_start, BufferedCount));
                if (lineEnd >= 0)
                {
                    var line = _buffer.AsSpan(_start, lineEnd + 2).ToArray();
                    Consume(lineEnd + 2);
                    return line;
                }

                if (BufferedCount >= maxBytes)
                {
                    throw new InvalidDataException("HTTP line exceeds maximum size.");
                }

                var read = await FillAsync(cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    if (BufferedCount == 0)
                    {
                        return null;
                    }

                    throw new InvalidDataException("HTTP line is incomplete.");
                }
            }
        }

        private async Task<byte[]> ReadExactAsync(int length, CancellationToken cancellationToken)
        {
            var buffer = new byte[length];
            var offset = 0;

            while (offset < length)
            {
                if (BufferedCount > 0)
                {
                    var copied = Math.Min(length - offset, BufferedCount);
                    _buffer.AsSpan(_start, copied).CopyTo(buffer.AsSpan(offset));
                    Consume(copied);
                    offset += copied;
                    continue;
                }

                var read = await _stream.ReadAsync(buffer.AsMemory(offset, length - offset), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    throw new EndOfStreamException("HTTP payload ended unexpectedly.");
                }

                offset += read;
            }

            return buffer;
        }

        private async Task<int> FillAsync(CancellationToken cancellationToken)
        {
            Compact();
            EnsureCapacity(BufferedCount + StreamCopyBufferBytes);
            var read = await _stream.ReadAsync(_buffer.AsMemory(_end, _buffer.Length - _end), cancellationToken).ConfigureAwait(false);
            _end += read;
            return read;
        }

        private void Consume(int count)
        {
            _start += count;
            if (_start == _end)
            {
                _start = 0;
                _end = 0;
            }
        }

        private void Compact()
        {
            if (_start == 0)
            {
                return;
            }

            if (_start == _end)
            {
                _start = 0;
                _end = 0;
                return;
            }

            Buffer.BlockCopy(_buffer, _start, _buffer, 0, BufferedCount);
            _end = BufferedCount;
            _start = 0;
        }

        private void EnsureCapacity(int required)
        {
            if (_buffer.Length >= required)
            {
                return;
            }

            var newSize = _buffer.Length;
            while (newSize < required)
            {
                newSize *= 2;
            }

            Array.Resize(ref _buffer, newSize);
        }

        private int BufferedCount => _end - _start;

        private static long ParseChunkSize(byte[] line)
        {
            var text = Encoding.ASCII.GetString(line, 0, line.Length - 2);
            var separator = text.IndexOf(';');
            var sizeText = (separator >= 0 ? text[..separator] : text).Trim();
            if (!long.TryParse(sizeText, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var size) ||
                size < 0)
            {
                throw new InvalidDataException("HTTP chunk header is invalid.");
            }

            return size;
        }

        private static int FindLineTerminator(ReadOnlySpan<byte> buffer)
        {
            for (var index = 0; index < buffer.Length - 1; index++)
            {
                if (buffer[index] == (byte)'\r' && buffer[index + 1] == (byte)'\n')
                {
                    return index;
                }
            }

            return -1;
        }
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
}
