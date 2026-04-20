using System.Globalization;
using System.Net.Quic;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;

namespace NodePanel.Core.Runtime;

internal sealed class RuntimeSplitHttpInboundBridge
{
    private const int DefaultXPaddingBytesFrom = 100;
    private const int DefaultXPaddingBytesTo = 1000;
    private const int DefaultScMaxBufferedPosts = 30;
    private const int DefaultScStreamUpServerSecsFrom = 20;
    private const int DefaultScStreamUpServerSecsTo = 80;
    private const int DefaultServerMaxHeaderBytes = 8192;
    private const int HeaderDrainLimitBytes = 65536;
    private const string DefaultNonObfsRequestPaddingKey = "x_padding";
    private const string DefaultNonObfsRequestPaddingHeader = "Referer";
    private const string DefaultNonObfsResponsePaddingHeader = "X-Padding";
    private const int TokenishValidationTolerance = 2;
    private const string XPaddingBase62Charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    private readonly RuntimeSplitHttpInboundOptions _options;
    private readonly RuntimeSplitHttpSessionRegistry _sessions;
    private readonly RuntimeInt32Range _xPaddingBytes;
    private readonly RuntimeInt32Range _scMaxEachPostBytes;
    private readonly RuntimeInt32Range _scStreamUpServerSecs;
    private readonly int _serverMaxHeaderBytes;

    public RuntimeSplitHttpInboundBridge(RuntimeSplitHttpInboundOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _xPaddingBytes = NormalizeXPaddingBytes(options.XPaddingBytes);
        _scMaxEachPostBytes = RuntimeSplitHttpClientConnector.NormalizeScMaxEachPostBytes(options.ScMaxEachPostBytes);
        _scStreamUpServerSecs = NormalizeScStreamUpServerSecs(options.ScStreamUpServerSecs);
        _serverMaxHeaderBytes = options.ServerMaxHeaderBytes > 0
            ? options.ServerMaxHeaderBytes
            : DefaultServerMaxHeaderBytes;
        _sessions = new RuntimeSplitHttpSessionRegistry(
            options.ScMaxBufferedPosts > 0
                ? options.ScMaxBufferedPosts
                : DefaultScMaxBufferedPosts);
    }

    public async Task ServeAsync(
        Stream transportStream,
        Func<Stream, CancellationToken, Task> handler,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transportStream);
        ArgumentNullException.ThrowIfNull(handler);

        ParsedHttpRequest request;
        try
        {
            request = await ReadRequestAsync(transportStream, cancellationToken).ConfigureAwait(false);
        }
        catch (SplitHttpRequestHeaderTooLargeException)
        {
            await TryDrainRequestHeadersAsync(transportStream, cancellationToken).ConfigureAwait(false);
            await TryWriteHeadersOnlyAsync(
                    transportStream,
                    431,
                    new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
                    cancellationToken)
                .ConfigureAwait(false);
            return;
        }
        catch (InvalidDataException)
        {
            await TryDrainRequestHeadersAsync(transportStream, cancellationToken).ConfigureAwait(false);
            await TryWriteHeadersOnlyAsync(
                    transportStream,
                    400,
                    new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
                    cancellationToken)
                .ConfigureAwait(false);
            return;
        }

        if (string.Equals(request.Method, "PRI", StringComparison.OrdinalIgnoreCase) &&
            string.Equals(request.Target, "*", StringComparison.Ordinal) &&
            string.Equals(request.Version, "HTTP/2.0", StringComparison.OrdinalIgnoreCase))
        {
            await request.DisposeAsync().ConfigureAwait(false);
            await ServeHttp2Async(transportStream, handler, cancellationToken).ConfigureAwait(false);
            return;
        }

        await using var requestContext = new Http11RequestContext(transportStream, request);
        await HandleRequestAsync(requestContext, handler, cancellationToken).ConfigureAwait(false);
    }

    public async Task ServeHttp3Async(
        QuicConnection connection,
        Func<Stream, CancellationToken, Task> handler,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(handler);

        await using var session = await RuntimeHttp3ServerSession
            .AcceptAsync(connection, cancellationToken)
            .ConfigureAwait(false);

        var activeTasks = new List<Task>();
        var activeTasksLock = new object();
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                RuntimeHttp3ServerSession.AcceptedRequest? acceptedRequest;
                try
                {
                    acceptedRequest = await session.AcceptRequestAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }

                if (acceptedRequest is null)
                {
                    break;
                }

                var task = HandleHttp3RequestAsync(acceptedRequest, handler, cancellationToken);
                lock (activeTasksLock)
                {
                    activeTasks.Add(task);
                }

                _ = task.ContinueWith(
                    static (completedTask, state) =>
                    {
                        var tuple = ((List<Task> Tasks, object SyncRoot))state!;
                        lock (tuple.SyncRoot)
                        {
                            tuple.Tasks.Remove(completedTask);
                        }
                    },
                    (activeTasks, activeTasksLock),
                    CancellationToken.None,
                    TaskContinuationOptions.ExecuteSynchronously,
                    TaskScheduler.Default);
            }
        }
        finally
        {
            Task[] pendingTasks;
            lock (activeTasksLock)
            {
                pendingTasks = activeTasks.ToArray();
            }

            if (pendingTasks.Length > 0)
            {
                await Task.WhenAll(pendingTasks).ConfigureAwait(false);
            }
        }
    }

    private async Task ServeHttp2Async(
        Stream transportStream,
        Func<Stream, CancellationToken, Task> handler,
        CancellationToken cancellationToken)
    {
        await using var session = await RuntimeHttp2ServerSession
            .AcceptAfterPrefaceHeadAsync(transportStream, cancellationToken)
            .ConfigureAwait(false);

        var activeTasks = new List<Task>();
        var activeTasksLock = new object();
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                RuntimeHttp2ServerSession.AcceptedRequest? acceptedRequest;
                try
                {
                    acceptedRequest = await session.AcceptRequestAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }

                if (acceptedRequest is null)
                {
                    break;
                }

                var task = HandleHttp2RequestAsync(acceptedRequest, handler, cancellationToken);
                lock (activeTasksLock)
                {
                    activeTasks.Add(task);
                }

                _ = task.ContinueWith(
                    static (completedTask, state) =>
                    {
                        var tuple = ((List<Task> Tasks, object SyncRoot))state!;
                        lock (tuple.SyncRoot)
                        {
                            tuple.Tasks.Remove(completedTask);
                        }
                    },
                    (activeTasks, activeTasksLock),
                    CancellationToken.None,
                    TaskContinuationOptions.ExecuteSynchronously,
                    TaskScheduler.Default);
            }
        }
        finally
        {
            Task[] pendingTasks;
            lock (activeTasksLock)
            {
                pendingTasks = activeTasks.ToArray();
            }

            if (pendingTasks.Length > 0)
            {
                await Task.WhenAll(pendingTasks).ConfigureAwait(false);
            }
        }
    }

    private async Task HandleHttp2RequestAsync(
        RuntimeHttp2ServerSession.AcceptedRequest acceptedRequest,
        Func<Stream, CancellationToken, Task> handler,
        CancellationToken cancellationToken)
    {
        await using var requestContext = new Http2RequestContext(acceptedRequest);
        try
        {
            if (DecodedRequestHeadersExceedLimit(requestContext.Headers))
            {
                await requestContext
                    .WriteEarlyResponseAsync(
                        431,
                        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
                        cancellationToken)
                    .ConfigureAwait(false);
                return;
            }

            await HandleRequestAsync(requestContext, handler, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch
        {
            if (!requestContext.ResponseStarted)
            {
                try
                {
                    await requestContext
                        .WriteHeadersOnlyAsync(
                            500,
                            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
                            CancellationToken.None)
                        .ConfigureAwait(false);
                }
                catch
                {
                }
            }
        }
    }

    private async Task HandleHttp3RequestAsync(
        RuntimeHttp3ServerSession.AcceptedRequest acceptedRequest,
        Func<Stream, CancellationToken, Task> handler,
        CancellationToken cancellationToken)
    {
        await using var requestContext = new Http3RequestContext(acceptedRequest);
        try
        {
            if (DecodedRequestHeadersExceedLimit(requestContext.Headers))
            {
                await requestContext
                    .WriteEarlyResponseAsync(
                        431,
                        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
                        cancellationToken)
                    .ConfigureAwait(false);
                return;
            }

            await HandleRequestAsync(requestContext, handler, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch
        {
            if (!requestContext.ResponseStarted)
            {
                try
                {
                    await requestContext
                        .WriteHeadersOnlyAsync(
                            500,
                            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
                            CancellationToken.None)
                        .ConfigureAwait(false);
                }
                catch
                {
                }
            }
        }
    }

    private async Task HandleRequestAsync(
        ISplitHttpRequestContext request,
        Func<Stream, CancellationToken, Task> handler,
        CancellationToken cancellationToken)
    {
        var responseHeaders = BuildBaseResponseHeaders(request.Method, request.Headers);
        ApplyResponsePadding(responseHeaders);

        if (!IsValidHttpHost(request.Host, _options.Host) ||
            !RuntimeSplitHttpRequestMetadata.MatchesPathPrefix(request.Path, _options.Path))
        {
            await request.WriteEarlyResponseAsync(404, responseHeaders, cancellationToken).ConfigureAwait(false);
            return;
        }

        if (string.Equals(request.Method, "OPTIONS", StringComparison.OrdinalIgnoreCase))
        {
            await request.WriteEarlyResponseAsync(200, responseHeaders, cancellationToken).ConfigureAwait(false);
            return;
        }

        if (!TryValidateRequestPadding(request, out var paddingErrorStatusCode))
        {
            await request.WriteEarlyResponseAsync(paddingErrorStatusCode, responseHeaders, cancellationToken).ConfigureAwait(false);
            return;
        }

        var (sessionId, seqValue) = RuntimeSplitHttpRequestMetadata.ExtractFromRequest(
            request.Target,
            request.Headers,
            _options.Path,
            _options.SessionPlacement,
            _options.SessionKey,
            _options.SeqPlacement,
            _options.SeqKey);

        if (sessionId.Length == 0 &&
            !string.Equals(_options.Mode, "auto", StringComparison.Ordinal) &&
            !string.Equals(_options.Mode, "stream-one", StringComparison.Ordinal) &&
            !string.Equals(_options.Mode, "stream-up", StringComparison.Ordinal))
        {
            await request.WriteEarlyResponseAsync(400, responseHeaders, cancellationToken).ConfigureAwait(false);
            return;
        }

        RuntimeSplitHttpServerSession? session = null;
        if (sessionId.Length > 0)
        {
            session = _sessions.GetOrCreate(sessionId);
        }

        var isUplinkRequest = string.Equals(request.Method, "GET", StringComparison.OrdinalIgnoreCase)
            ? seqValue.Length > 0
            : true;

        if (isUplinkRequest && sessionId.Length > 0)
        {
            if (seqValue.Length == 0)
            {
                await HandleStreamUpUploadAsync(request, session!, responseHeaders, cancellationToken).ConfigureAwait(false);
                return;
            }

            await HandlePacketUploadAsync(request, session!, seqValue, responseHeaders, cancellationToken).ConfigureAwait(false);
            return;
        }

        if (string.Equals(request.Method, "GET", StringComparison.OrdinalIgnoreCase) || sessionId.Length == 0)
        {
            await HandleDownlinkAsync(request, session, sessionId, responseHeaders, handler, cancellationToken).ConfigureAwait(false);
            return;
        }

        await request.WriteEarlyResponseAsync(405, responseHeaders, cancellationToken).ConfigureAwait(false);
    }

    private bool DecodedRequestHeadersExceedLimit(IReadOnlyDictionary<string, string> headers)
    {
        ArgumentNullException.ThrowIfNull(headers);

        // HTTP/2 and HTTP/3 only expose decoded header fields here, so enforce the
        // configured budget against the logical header list instead of raw wire bytes.
        long totalBytes = 2;
        foreach (var header in headers)
        {
            totalBytes += Encoding.UTF8.GetByteCount(header.Key);
            totalBytes += Encoding.UTF8.GetByteCount(header.Value);
            totalBytes += 4;
            if (totalBytes > _serverMaxHeaderBytes)
            {
                return true;
            }
        }

        return false;
    }

    private async Task HandleDownlinkAsync(
        ISplitHttpRequestContext request,
        RuntimeSplitHttpServerSession? session,
        string sessionId,
        IReadOnlyDictionary<string, string> baseHeaders,
        Func<Stream, CancellationToken, Task> handler,
        CancellationToken cancellationToken)
    {
        if (session is not null)
        {
            session.MarkFullyConnected();
        }

        var responseHeaders = CloneHeaders(baseHeaders);
        responseHeaders["X-Accel-Buffering"] = "no";
        responseHeaders["Cache-Control"] = "no-store";
        if (!_options.NoSseHeader)
        {
            responseHeaders["Content-Type"] = "text/event-stream";
        }

        var responseBody = await request
            .OpenResponseBodyAsync(200, responseHeaders, cancellationToken)
            .ConfigureAwait(false);

        await using var reader = session is null
            ? request.Body
            : new SplitHttpUploadQueueReadStream(session.UploadQueue);
        await using var applicationStream = new SplitHttpApplicationStream(reader, responseBody);
        try
        {
            await handler(applicationStream, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            if (sessionId.Length > 0)
            {
                _sessions.TryRemove(sessionId);
            }
        }
    }

    private async Task HandleStreamUpUploadAsync(
        ISplitHttpRequestContext request,
        RuntimeSplitHttpServerSession session,
        IReadOnlyDictionary<string, string> baseHeaders,
        CancellationToken cancellationToken)
    {
        if (!string.Equals(_options.Mode, "auto", StringComparison.Ordinal) &&
            !string.Equals(_options.Mode, "stream-up", StringComparison.Ordinal))
        {
            await request.WriteEarlyResponseAsync(400, baseHeaders, cancellationToken).ConfigureAwait(false);
            return;
        }

        var uploadStream = new SplitHttpUploadRequestStream(request.Body);
        try
        {
            await session.UploadQueue.PushStreamAsync(uploadStream, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            await uploadStream.DisposeAsync().ConfigureAwait(false);
            await request.WriteEarlyResponseAsync(409, baseHeaders, cancellationToken).ConfigureAwait(false);
            return;
        }

        var responseHeaders = CloneHeaders(baseHeaders);
        responseHeaders["X-Accel-Buffering"] = "no";
        responseHeaders["Cache-Control"] = "no-store";

        await using var responseBody = await request
            .OpenResponseBodyAsync(200, responseHeaders, cancellationToken)
            .ConfigureAwait(false);
        uploadStream.AttachResponseBody(responseBody);

        using var keepAliveCts = new CancellationTokenSource();
        var keepAliveTask = StartStreamUpKeepAliveLoop(uploadStream, request.Headers, keepAliveCts.Token);
        try
        {
            // Keep the upload response open until the shared session tears down,
            // matching xray-core's stream-up request lifetime.
            var completed = await Task.WhenAny(
                    uploadStream.CloseTask,
                    InboundServerRuntimeSupport.WaitForCancellationAsync(cancellationToken))
                .ConfigureAwait(false);
            if (completed != uploadStream.CloseTask)
            {
                await uploadStream.DisposeAsync().ConfigureAwait(false);
            }

            try
            {
                await completed.ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
            }
        }
        finally
        {
            keepAliveCts.Cancel();
            if (keepAliveTask is not null)
            {
                try
                {
                    await keepAliveTask.ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                }
            }
        }
    }

    private async Task HandlePacketUploadAsync(
        ISplitHttpRequestContext request,
        RuntimeSplitHttpServerSession session,
        string seqValue,
        IReadOnlyDictionary<string, string> baseHeaders,
        CancellationToken cancellationToken)
    {
        if (!string.Equals(_options.Mode, "auto", StringComparison.Ordinal) &&
            !string.Equals(_options.Mode, "packet-up", StringComparison.Ordinal))
        {
            await request.WriteEarlyResponseAsync(400, baseHeaders, cancellationToken).ConfigureAwait(false);
            return;
        }

        var dataPlacement = ResolveInboundUplinkDataPlacement(_options.UplinkDataPlacement);
        var dataKey = ResolveInboundUplinkDataKey(_options.UplinkDataPlacement, _options.UplinkDataKey);

        byte[] headerPayload;
        try
        {
            headerPayload = ReadHeaderPayload(request.Headers, dataKey, dataPlacement);
        }
        catch (FormatException)
        {
            await request.WriteEarlyResponseAsync(400, baseHeaders, cancellationToken).ConfigureAwait(false);
            return;
        }

        byte[] cookiePayload;
        try
        {
            cookiePayload = ReadCookiePayload(request.Headers, dataKey, dataPlacement);
        }
        catch (FormatException)
        {
            await request.WriteEarlyResponseAsync(400, baseHeaders, cancellationToken).ConfigureAwait(false);
            return;
        }

        var bodyPayload = await ReadBodyPayloadAsync(
                request.Body,
                dataPlacement,
                (int)Math.Min(int.MaxValue, (long)GetMaximum(_scMaxEachPostBytes) + 1L),
                cancellationToken)
            .ConfigureAwait(false);

        var payload = CombinePayload(headerPayload, cookiePayload, bodyPayload);
        if (payload.Length > GetMaximum(_scMaxEachPostBytes))
        {
            await request.WriteEarlyResponseAsync(413, baseHeaders, cancellationToken).ConfigureAwait(false);
            return;
        }

        if (!ulong.TryParse(seqValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out var sequence))
        {
            await request.WriteEarlyResponseAsync(500, baseHeaders, cancellationToken).ConfigureAwait(false);
            return;
        }

        try
        {
            await session.UploadQueue.PushPayloadAsync(payload, sequence, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            await request.WriteEarlyResponseAsync(500, baseHeaders, cancellationToken).ConfigureAwait(false);
            return;
        }

        var responseHeaders = CloneHeaders(baseHeaders);
        if (bodyPayload.Length == 0)
        {
            responseHeaders["Cache-Control"] = "no-store";
        }

        await request.WriteHeadersOnlyAsync(200, responseHeaders, cancellationToken).ConfigureAwait(false);
    }

    private Task? StartStreamUpKeepAliveLoop(
        SplitHttpUploadRequestStream uploadStream,
        IReadOnlyDictionary<string, string> requestHeaders,
        CancellationToken cancellationToken)
    {
        if (!requestHeaders.TryGetValue("Referer", out var referer) ||
            string.IsNullOrWhiteSpace(referer) ||
            _scStreamUpServerSecs.To <= 0)
        {
            return null;
        }

        return Task.Run(async () =>
        {
            while (!uploadStream.IsClosed)
            {
                var padding = new byte[Math.Max(1, RuntimeSplitHttpClientConnector.GetRandomRangeValue(_xPaddingBytes))];
                Array.Fill(padding, (byte)'X');

                try
                {
                    await uploadStream.WriteAsync(padding, CancellationToken.None).ConfigureAwait(false);
                }
                catch
                {
                    break;
                }

                await Task.Delay(
                        TimeSpan.FromSeconds(RuntimeSplitHttpClientConnector.GetRandomRangeValue(_scStreamUpServerSecs)),
                        cancellationToken)
                    .ConfigureAwait(false);
            }
        }, cancellationToken);
    }

    private bool TryValidateRequestPadding(ISplitHttpRequestContext request, out int errorStatusCode)
    {
        errorStatusCode = 400;
        var (paddingValue, _) = ExtractRequestPadding(request);
        return IsPaddingValid(paddingValue, _xPaddingBytes, _options.XPaddingMethod);
    }

    private (string Value, string Placement) ExtractRequestPadding(ISplitHttpRequestContext request)
    {
        if (!_options.XPaddingObfsMode)
        {
            if (request.Headers.TryGetValue(DefaultNonObfsRequestPaddingHeader, out var referer) &&
                Uri.TryCreate(referer, UriKind.RelativeOrAbsolute, out var refererUri))
            {
                var refererValue = GetQueryValue(refererUri.Query, DefaultNonObfsRequestPaddingKey);
                if (refererValue.Length > 0)
                {
                    return (refererValue, "queryInHeader");
                }
            }

            var targetQuerySeparator = request.Target.IndexOf('?');
            var targetQuery = targetQuerySeparator >= 0 ? request.Target[(targetQuerySeparator + 1)..] : string.Empty;
            var queryValue = GetQueryValue(targetQuery, DefaultNonObfsRequestPaddingKey);
            if (queryValue.Length > 0)
            {
                return (queryValue, "query");
            }

            return (string.Empty, string.Empty);
        }

        if (string.Equals(_options.XPaddingPlacement, "cookie", StringComparison.Ordinal) &&
            request.Headers.TryGetValue("Cookie", out var cookieHeader))
        {
            var cookieValue = GetCookieValue(cookieHeader, _options.XPaddingKey);
            if (cookieValue.Length > 0)
            {
                return (cookieValue, "cookie");
            }
        }

        if (request.Headers.TryGetValue(_options.XPaddingHeader, out var headerValue) &&
            headerValue.Length > 0)
        {
            if (string.Equals(_options.XPaddingPlacement, "header", StringComparison.Ordinal))
            {
                return (headerValue, "header");
            }

            if (Uri.TryCreate(headerValue, UriKind.RelativeOrAbsolute, out var headerUri))
            {
                var queryValue = GetQueryValue(headerUri.Query, _options.XPaddingKey);
                if (queryValue.Length > 0)
                {
                    return (queryValue, "queryInHeader");
                }
            }
        }

        var separator = request.Target.IndexOf('?');
        var query = separator >= 0 ? request.Target[(separator + 1)..] : string.Empty;
        return (GetQueryValue(query, _options.XPaddingKey), "query");
    }

    private Dictionary<string, string> BuildBaseResponseHeaders(
        string requestMethod,
        IReadOnlyDictionary<string, string> requestHeaders)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (!requestHeaders.TryGetValue("Origin", out var origin) || string.IsNullOrWhiteSpace(origin))
        {
            headers["Access-Control-Allow-Origin"] = "*";
        }
        else
        {
            headers["Access-Control-Allow-Origin"] = origin;
        }

        if (ShouldAllowCredentials())
        {
            headers["Access-Control-Allow-Credentials"] = "true";
        }

        if (string.Equals(requestMethod, "OPTIONS", StringComparison.OrdinalIgnoreCase))
        {
            headers["Access-Control-Allow-Methods"] = requestHeaders.TryGetValue("Access-Control-Request-Method", out var requestedMethod) &&
                                                     !string.IsNullOrWhiteSpace(requestedMethod)
                ? requestedMethod
                : "*";
            headers["Access-Control-Allow-Headers"] = requestHeaders.TryGetValue("Access-Control-Request-Headers", out var requestedHeaders) &&
                                                     !string.IsNullOrWhiteSpace(requestedHeaders)
                ? requestedHeaders
                : "*";
        }

        return headers;
    }

    private bool ShouldAllowCredentials()
        => string.Equals(_options.SessionPlacement, "cookie", StringComparison.Ordinal) ||
           string.Equals(_options.SeqPlacement, "cookie", StringComparison.Ordinal) ||
           string.Equals(_options.XPaddingPlacement, "cookie", StringComparison.Ordinal) ||
           string.Equals(ResolveInboundUplinkDataPlacement(_options.UplinkDataPlacement), "cookie", StringComparison.Ordinal);

    private void ApplyResponsePadding(IDictionary<string, string> headers)
    {
        var paddingLength = RuntimeSplitHttpClientConnector.GetRandomRangeValue(_xPaddingBytes);
        if (paddingLength <= 0)
        {
            return;
        }

        var paddingMethod = string.Equals(_options.XPaddingMethod, "tokenish", StringComparison.Ordinal)
            ? "tokenish"
            : "repeat-x";
        var paddingValue = GeneratePadding(paddingMethod, paddingLength);

        if (!_options.XPaddingObfsMode)
        {
            headers[DefaultNonObfsResponsePaddingHeader] = paddingValue;
            return;
        }

        switch (_options.XPaddingPlacement)
        {
            case "header":
                headers[_options.XPaddingHeader] = paddingValue;
                break;
            case "cookie":
                headers["Set-Cookie"] = $"{_options.XPaddingKey}={paddingValue}; Path=/";
                break;
            case "queryInHeader":
                headers[_options.XPaddingHeader] =
                    "?" + Uri.EscapeDataString(_options.XPaddingKey) + "=" + Uri.EscapeDataString(paddingValue);
                break;
        }
    }

    private async Task<ParsedHttpRequest> ReadRequestAsync(Stream transportStream, CancellationToken cancellationToken)
    {
        var budget = new HeaderReadBudget(_serverMaxHeaderBytes);
        var requestLine = await ReadLineAsync(
                transportStream,
                budget,
                "Unexpected EOF while reading SplitHTTP request line.",
                cancellationToken)
            .ConfigureAwait(false);
        var parts = requestLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3)
        {
            throw new InvalidDataException("SplitHTTP inbound received an invalid request line.");
        }

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        while (true)
        {
            var line = await ReadLineAsync(
                    transportStream,
                    budget,
                    "Unexpected EOF while reading SplitHTTP request headers.",
                    cancellationToken)
                .ConfigureAwait(false);
            if (line.Length == 0)
            {
                break;
            }

            var separator = line.IndexOf(':');
            if (separator <= 0)
            {
                continue;
            }

            headers[line[..separator].Trim()] = line[(separator + 1)..].Trim();
        }

        var target = parts[1];
        var querySeparator = target.IndexOf('?');
        var path = querySeparator >= 0 ? target[..querySeparator] : target;

        return new ParsedHttpRequest(
            Method: parts[0].Trim(),
            Target: target,
            Version: parts[2].Trim(),
            Path: path,
            Host: headers.TryGetValue("Host", out var host) ? host : string.Empty,
            Headers: headers,
            Body: CreateRequestBodyStream(transportStream, headers));
    }

    private static async Task<string> ReadLineAsync(
        Stream stream,
        HeaderReadBudget budget,
        string eofMessage,
        CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream(128);
        var oneByte = new byte[1];

        while (true)
        {
            budget.Consume(1);
            var read = await stream.ReadAsync(oneByte.AsMemory(0, 1), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException(eofMessage);
            }

            if (oneByte[0] == '\n')
            {
                var bytes = buffer.ToArray();
                if (bytes.Length > 0 && bytes[^1] == '\r')
                {
                    Array.Resize(ref bytes, bytes.Length - 1);
                }

                return Encoding.ASCII.GetString(bytes);
            }

            buffer.WriteByte(oneByte[0]);
        }
    }

    private static Stream CreateRequestBodyStream(
        Stream transportStream,
        IReadOnlyDictionary<string, string> headers)
    {
        if (headers.TryGetValue("Transfer-Encoding", out var transferEncoding) &&
            transferEncoding.Contains("chunked", StringComparison.OrdinalIgnoreCase))
        {
            return new SplitHttpChunkedReadStream(transportStream);
        }

        if (headers.TryGetValue("Content-Length", out var contentLengthText))
        {
            if (!long.TryParse(contentLengthText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var contentLength) ||
                contentLength < 0)
            {
                throw new InvalidDataException("SplitHTTP inbound received an invalid Content-Length header.");
            }

            return contentLength == 0
                ? Stream.Null
                : new SplitHttpContentLengthReadStream(transportStream, contentLength);
        }

        return Stream.Null;
    }

    private static async Task<SplitHttpChunkedWriteStream> OpenChunkedResponseAsync(
        Stream transportStream,
        int statusCode,
        IReadOnlyDictionary<string, string> headers,
        CancellationToken cancellationToken)
    {
        var responseHeaders = CloneHeaders(headers);
        responseHeaders["Transfer-Encoding"] = "chunked";
        var bytes = BuildResponseHead(statusCode, responseHeaders);
        await transportStream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
        await transportStream.FlushAsync(cancellationToken).ConfigureAwait(false);
        return new SplitHttpChunkedWriteStream(transportStream);
    }

    private static async Task WriteHeadersOnlyAsync(
        Stream transportStream,
        int statusCode,
        IReadOnlyDictionary<string, string> headers,
        CancellationToken cancellationToken)
    {
        var responseHeaders = CloneHeaders(headers);
        responseHeaders["Content-Length"] = "0";
        var bytes = BuildResponseHead(statusCode, responseHeaders);
        await transportStream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
        await transportStream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task TryWriteHeadersOnlyAsync(
        Stream transportStream,
        int statusCode,
        IReadOnlyDictionary<string, string> headers,
        CancellationToken cancellationToken)
    {
        try
        {
            await WriteHeadersOnlyAsync(transportStream, statusCode, headers, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
        }
    }

    private static async Task WriteEarlyResponseAsync(
        Stream transportStream,
        Stream requestBody,
        int statusCode,
        IReadOnlyDictionary<string, string> headers,
        CancellationToken cancellationToken)
    {
        await TryDrainRequestBodyAsync(requestBody, cancellationToken).ConfigureAwait(false);
        await WriteHeadersOnlyAsync(transportStream, statusCode, headers, cancellationToken).ConfigureAwait(false);
    }

    private static async Task TryDrainRequestBodyAsync(
        Stream requestBody,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestBody);

        try
        {
            var buffer = new byte[1024];
            while (await requestBody.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false) != 0)
            {
            }
        }
        catch
        {
        }
    }

    private static async Task TryDrainRequestHeadersAsync(
        Stream transportStream,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transportStream);

        var buffer = new byte[512];
        var pattern = new byte[] { (byte)'\r', (byte)'\n', (byte)'\r', (byte)'\n' };
        var matched = 0;
        var remaining = HeaderDrainLimitBytes;

        try
        {
            while (remaining > 0)
            {
                var read = await transportStream.ReadAsync(
                        buffer.AsMemory(0, Math.Min(buffer.Length, remaining)),
                        cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0)
                {
                    return;
                }

                remaining -= read;
                for (var index = 0; index < read; index++)
                {
                    if (buffer[index] == pattern[matched])
                    {
                        matched++;
                        if (matched == pattern.Length)
                        {
                            return;
                        }

                        continue;
                    }

                    matched = buffer[index] == pattern[0] ? 1 : 0;
                }
            }
        }
        catch
        {
        }
    }

    private static byte[] BuildResponseHead(
        int statusCode,
        IReadOnlyDictionary<string, string> headers)
    {
        var builder = new StringBuilder(256);
        builder.Append("HTTP/1.1 ");
        builder.Append(statusCode.ToString(CultureInfo.InvariantCulture));
        builder.Append(' ');
        builder.Append(GetReasonPhrase(statusCode));
        builder.Append("\r\n");

        foreach (var (name, value) in headers)
        {
            if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            builder.Append(name.Trim());
            builder.Append(": ");
            builder.Append(value.Trim());
            builder.Append("\r\n");
        }

        builder.Append("\r\n");
        return Encoding.ASCII.GetBytes(builder.ToString());
    }

    private static string GetReasonPhrase(int statusCode)
        => statusCode switch
        {
            200 => "OK",
            400 => "Bad Request",
            404 => "Not Found",
            405 => "Method Not Allowed",
            409 => "Conflict",
            413 => "Request Entity Too Large",
            431 => "Request Header Fields Too Large",
            500 => "Internal Server Error",
            _ => "OK"
        };

    private static bool IsValidHttpHost(string requestHost, string configuredHost)
    {
        if (string.IsNullOrWhiteSpace(configuredHost))
        {
            return true;
        }

        if (string.IsNullOrWhiteSpace(requestHost))
        {
            return false;
        }

        var requested = requestHost.Trim().ToLowerInvariant();
        var configured = configuredHost.Trim().ToLowerInvariant();
        if (requested.Contains(':') &&
            Uri.CheckHostName(configured) != UriHostNameType.Unknown &&
            Uri.TryCreate("tcp://" + requested, UriKind.Absolute, out var hostWithPort))
        {
            return string.Equals(hostWithPort.Host, configured, StringComparison.Ordinal);
        }

        return string.Equals(requested, configured, StringComparison.Ordinal);
    }

    private static RuntimeInt32Range NormalizeXPaddingBytes(RuntimeInt32Range value)
    {
        if (value.To <= 0)
        {
            return new RuntimeInt32Range
            {
                From = DefaultXPaddingBytesFrom,
                To = DefaultXPaddingBytesTo
            };
        }

        var from = value.From <= 0 ? value.To : value.From;
        var to = value.To;
        if (to < from)
        {
            (from, to) = (to, from);
        }

        return new RuntimeInt32Range
        {
            From = from,
            To = to
        };
    }

    private static RuntimeInt32Range NormalizeScStreamUpServerSecs(RuntimeInt32Range value)
    {
        if (value.To <= 0)
        {
            return new RuntimeInt32Range
            {
                From = DefaultScStreamUpServerSecsFrom,
                To = DefaultScStreamUpServerSecsTo
            };
        }

        return new RuntimeInt32Range
        {
            From = value.From,
            To = value.To
        };
    }

    private static int GetMaximum(RuntimeInt32Range range)
        => Math.Max(range.From, range.To);

    private static string ResolveInboundUplinkDataPlacement(string value)
        => string.IsNullOrWhiteSpace(value)
            ? "body"
            : value.Trim().ToLowerInvariant();

    private static string ResolveInboundUplinkDataKey(string placement, string configuredKey)
    {
        if (!string.IsNullOrWhiteSpace(configuredKey))
        {
            return configuredKey.Trim();
        }

        return ResolveInboundUplinkDataPlacement(placement) switch
        {
            "cookie" => "x_data",
            "header" or "auto" => "X-Data",
            _ => string.Empty
        };
    }

    private static byte[] ReadHeaderPayload(
        IReadOnlyDictionary<string, string> headers,
        string key,
        string placement)
    {
        if (!string.Equals(placement, "auto", StringComparison.Ordinal) &&
            !string.Equals(placement, "header", StringComparison.Ordinal))
        {
            return Array.Empty<byte>();
        }

        var builder = new StringBuilder();
        for (var index = 0; ; index++)
        {
            if (!headers.TryGetValue(
                    key + "-" + index.ToString(CultureInfo.InvariantCulture),
                    out var value) ||
                string.IsNullOrEmpty(value))
            {
                break;
            }

            builder.Append(value);
        }

        return builder.Length == 0 ? Array.Empty<byte>() : DecodeBase64Url(builder.ToString());
    }

    private static byte[] ReadCookiePayload(
        IReadOnlyDictionary<string, string> headers,
        string key,
        string placement)
    {
        if (!string.Equals(placement, "auto", StringComparison.Ordinal) &&
            !string.Equals(placement, "cookie", StringComparison.Ordinal))
        {
            return Array.Empty<byte>();
        }

        if (!headers.TryGetValue("Cookie", out var cookieHeader) || string.IsNullOrWhiteSpace(cookieHeader))
        {
            return Array.Empty<byte>();
        }

        var builder = new StringBuilder();
        for (var index = 0; ; index++)
        {
            var cookieValue = GetCookieValue(
                cookieHeader,
                key + "_" + index.ToString(CultureInfo.InvariantCulture));
            if (cookieValue.Length == 0)
            {
                break;
            }

            builder.Append(cookieValue);
        }

        return builder.Length == 0 ? Array.Empty<byte>() : DecodeBase64Url(builder.ToString());
    }

    private static async Task<byte[]> ReadBodyPayloadAsync(
        Stream requestBody,
        string placement,
        int limit,
        CancellationToken cancellationToken)
    {
        if (!string.Equals(placement, "auto", StringComparison.Ordinal) &&
            !string.Equals(placement, "body", StringComparison.Ordinal))
        {
            return Array.Empty<byte>();
        }

        using var buffer = new MemoryStream();
        var rented = new byte[Math.Min(8192, Math.Max(1024, limit))];
        while (buffer.Length < limit)
        {
            var read = await requestBody.ReadAsync(
                    rented.AsMemory(0, Math.Min(rented.Length, limit - (int)buffer.Length)),
                    cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            buffer.Write(rented, 0, read);
        }

        return buffer.ToArray();
    }

    private static byte[] CombinePayload(byte[] headerPayload, byte[] cookiePayload, byte[] bodyPayload)
    {
        var totalLength = headerPayload.Length + cookiePayload.Length + bodyPayload.Length;
        if (totalLength == 0)
        {
            return Array.Empty<byte>();
        }

        var payload = new byte[totalLength];
        var offset = 0;
        headerPayload.CopyTo(payload, offset);
        offset += headerPayload.Length;
        cookiePayload.CopyTo(payload, offset);
        offset += cookiePayload.Length;
        bodyPayload.CopyTo(payload, offset);
        return payload;
    }

    private static byte[] DecodeBase64Url(string value)
    {
        var normalized = value.Replace('-', '+').Replace('_', '/');
        var padding = normalized.Length % 4;
        if (padding > 0)
        {
            normalized = normalized.PadRight(normalized.Length + (4 - padding), '=');
        }

        return Convert.FromBase64String(normalized);
    }

    private static string GetQueryValue(string query, string key)
    {
        if (string.IsNullOrWhiteSpace(query) || string.IsNullOrWhiteSpace(key))
        {
            return string.Empty;
        }

        var normalizedQuery = query.StartsWith("?", StringComparison.Ordinal)
            ? query[1..]
            : query;
        foreach (var segment in normalizedQuery.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = segment.IndexOf('=');
            var currentKey = separator >= 0 ? segment[..separator] : segment;
            if (!string.Equals(Uri.UnescapeDataString(currentKey), key, StringComparison.Ordinal))
            {
                continue;
            }

            var currentValue = separator >= 0 ? segment[(separator + 1)..] : string.Empty;
            return Uri.UnescapeDataString(currentValue);
        }

        return string.Empty;
    }

    private static string GetCookieValue(string cookieHeader, string key)
    {
        if (string.IsNullOrWhiteSpace(cookieHeader) || string.IsNullOrWhiteSpace(key))
        {
            return string.Empty;
        }

        foreach (var segment in cookieHeader.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = segment.Trim();
            if (trimmed.Length == 0)
            {
                continue;
            }

            var separator = trimmed.IndexOf('=');
            var currentKey = separator >= 0 ? trimmed[..separator].Trim() : trimmed;
            if (!string.Equals(currentKey, key, StringComparison.Ordinal))
            {
                continue;
            }

            return separator >= 0 ? trimmed[(separator + 1)..].Trim() : string.Empty;
        }

        return string.Empty;
    }

    private static bool IsPaddingValid(string paddingValue, RuntimeInt32Range range, string method)
    {
        if (string.IsNullOrEmpty(paddingValue))
        {
            return false;
        }

        var from = Math.Min(range.From, range.To);
        var to = Math.Max(range.From, range.To);
        if (string.Equals(method, "tokenish", StringComparison.Ordinal))
        {
            int encodedLength;
            try
            {
                encodedLength = RuntimeHpackHuffman.GetBase62EncodedLength(paddingValue);
            }
            catch (ArgumentOutOfRangeException)
            {
                return false;
            }

            return encodedLength >= Math.Max(0, from - TokenishValidationTolerance) &&
                   encodedLength <= to + TokenishValidationTolerance;
        }

        return paddingValue.Length >= from && paddingValue.Length <= to;
    }

    private static string GeneratePadding(string method, int length)
    {
        if (length <= 0)
        {
            return string.Empty;
        }

        if (!string.Equals(method, "tokenish", StringComparison.Ordinal))
        {
            return new string('X', length);
        }

        var tokenish = GenerateTokenishPadding(length);
        return tokenish.Length == 0 ? new string('X', length) : tokenish;
    }

    private static string GenerateTokenishPadding(int targetHuffmanBytes)
    {
        var characterCount = Math.Max(1, (int)Math.Ceiling(targetHuffmanBytes / 0.8d));
        string randomBase62;
        try
        {
            randomBase62 = GenerateRandomBase62String(characterCount);
        }
        catch (CryptographicException)
        {
            return string.Empty;
        }

        var builder = new StringBuilder(randomBase62);
        var adjustChar = 'X';
        for (var iteration = 0; iteration < 150; iteration++)
        {
            var currentLength = RuntimeHpackHuffman.GetBase62EncodedLength(builder.ToString());
            var diff = currentLength - targetHuffmanBytes;
            if (Math.Abs(diff) <= TokenishValidationTolerance)
            {
                return builder.ToString();
            }

            if (diff < 0)
            {
                builder.Append(adjustChar);
                adjustChar = adjustChar == 'X' ? 'Z' : 'X';
                continue;
            }

            if (builder.Length <= 1)
            {
                return builder.ToString();
            }

            builder.Length--;
        }

        return builder.ToString();
    }

    private static string GenerateRandomBase62String(int characterCount)
    {
        var buffer = new char[characterCount];
        for (var index = 0; index < buffer.Length; index++)
        {
            buffer[index] = XPaddingBase62Charset[RandomNumberGenerator.GetInt32(XPaddingBase62Charset.Length)];
        }

        return new string(buffer);
    }

    private static Dictionary<string, string> CloneHeaders(IReadOnlyDictionary<string, string> source)
        => source.ToDictionary(static pair => pair.Key, static pair => pair.Value, StringComparer.OrdinalIgnoreCase);

    private interface ISplitHttpRequestContext : IAsyncDisposable
    {
        string Method { get; }

        string Target { get; }

        string Version { get; }

        string Path { get; }

        string Host { get; }

        IReadOnlyDictionary<string, string> Headers { get; }

        Stream Body { get; }

        bool ResponseStarted { get; }

        Task WriteEarlyResponseAsync(
            int statusCode,
            IReadOnlyDictionary<string, string> headers,
            CancellationToken cancellationToken);

        Task WriteHeadersOnlyAsync(
            int statusCode,
            IReadOnlyDictionary<string, string> headers,
            CancellationToken cancellationToken);

        Task<Stream> OpenResponseBodyAsync(
            int statusCode,
            IReadOnlyDictionary<string, string> headers,
            CancellationToken cancellationToken);
    }

    private sealed class Http11RequestContext : ISplitHttpRequestContext
    {
        private readonly Stream _transportStream;
        private readonly ParsedHttpRequest _request;
        private int _responseStarted;

        public Http11RequestContext(Stream transportStream, ParsedHttpRequest request)
        {
            _transportStream = transportStream ?? throw new ArgumentNullException(nameof(transportStream));
            _request = request ?? throw new ArgumentNullException(nameof(request));
        }

        public string Method => _request.Method;

        public string Target => _request.Target;

        public string Version => _request.Version;

        public string Path => _request.Path;

        public string Host => _request.Host;

        public IReadOnlyDictionary<string, string> Headers => _request.Headers;

        public Stream Body => _request.Body;

        public bool ResponseStarted => Volatile.Read(ref _responseStarted) != 0;

        public async Task WriteEarlyResponseAsync(
            int statusCode,
            IReadOnlyDictionary<string, string> headers,
            CancellationToken cancellationToken)
        {
            Interlocked.Exchange(ref _responseStarted, 1);
            await RuntimeSplitHttpInboundBridge
                .WriteEarlyResponseAsync(_transportStream, _request.Body, statusCode, headers, cancellationToken)
                .ConfigureAwait(false);
        }

        public async Task WriteHeadersOnlyAsync(
            int statusCode,
            IReadOnlyDictionary<string, string> headers,
            CancellationToken cancellationToken)
        {
            Interlocked.Exchange(ref _responseStarted, 1);
            await RuntimeSplitHttpInboundBridge
                .WriteHeadersOnlyAsync(_transportStream, statusCode, headers, cancellationToken)
                .ConfigureAwait(false);
        }

        public async Task<Stream> OpenResponseBodyAsync(
            int statusCode,
            IReadOnlyDictionary<string, string> headers,
            CancellationToken cancellationToken)
        {
            Interlocked.Exchange(ref _responseStarted, 1);
            return await RuntimeSplitHttpInboundBridge
                .OpenChunkedResponseAsync(_transportStream, statusCode, headers, cancellationToken)
                .ConfigureAwait(false);
        }

        public ValueTask DisposeAsync() => _request.DisposeAsync();
    }

    private sealed class Http2RequestContext : ISplitHttpRequestContext
    {
        private readonly RuntimeHttp2ServerSession.AcceptedRequest _request;

        public Http2RequestContext(RuntimeHttp2ServerSession.AcceptedRequest request)
        {
            _request = request ?? throw new ArgumentNullException(nameof(request));
        }

        public string Method => _request.Method;

        public string Target => _request.Target;

        public string Version => "HTTP/2.0";

        public string Path => _request.Path;

        public string Host => _request.Host;

        public IReadOnlyDictionary<string, string> Headers => _request.Headers;

        public Stream Body => _request.Body;

        public bool ResponseStarted => _request.ResponseStarted;

        public async Task WriteEarlyResponseAsync(
            int statusCode,
            IReadOnlyDictionary<string, string> headers,
            CancellationToken cancellationToken)
        {
            await _request.WriteHeadersOnlyAsync(statusCode, headers, cancellationToken).ConfigureAwait(false);
            await RuntimeSplitHttpInboundBridge.TryDrainRequestBodyAsync(_request.Body, cancellationToken).ConfigureAwait(false);
        }

        public Task WriteHeadersOnlyAsync(
            int statusCode,
            IReadOnlyDictionary<string, string> headers,
            CancellationToken cancellationToken)
            => _request.WriteHeadersOnlyAsync(statusCode, headers, cancellationToken);

        public Task<Stream> OpenResponseBodyAsync(
            int statusCode,
            IReadOnlyDictionary<string, string> headers,
            CancellationToken cancellationToken)
            => _request.OpenResponseBodyAsync(statusCode, headers, cancellationToken);

        public ValueTask DisposeAsync() => _request.DisposeAsync();
    }

    private sealed class Http3RequestContext : ISplitHttpRequestContext
    {
        private readonly RuntimeHttp3ServerSession.AcceptedRequest _request;

        public Http3RequestContext(RuntimeHttp3ServerSession.AcceptedRequest request)
        {
            _request = request ?? throw new ArgumentNullException(nameof(request));
        }

        public string Method => _request.Method;

        public string Target => _request.Target;

        public string Version => "HTTP/3";

        public string Path => _request.Path;

        public string Host => _request.Host;

        public IReadOnlyDictionary<string, string> Headers => _request.Headers;

        public Stream Body => _request.Body;

        public bool ResponseStarted => _request.ResponseStarted;

        public async Task WriteEarlyResponseAsync(
            int statusCode,
            IReadOnlyDictionary<string, string> headers,
            CancellationToken cancellationToken)
        {
            await _request.WriteHeadersOnlyAsync(statusCode, headers, cancellationToken).ConfigureAwait(false);
            await RuntimeSplitHttpInboundBridge.TryDrainRequestBodyAsync(_request.Body, cancellationToken).ConfigureAwait(false);
        }

        public Task WriteHeadersOnlyAsync(
            int statusCode,
            IReadOnlyDictionary<string, string> headers,
            CancellationToken cancellationToken)
            => _request.WriteHeadersOnlyAsync(statusCode, headers, cancellationToken);

        public Task<Stream> OpenResponseBodyAsync(
            int statusCode,
            IReadOnlyDictionary<string, string> headers,
            CancellationToken cancellationToken)
            => _request.OpenResponseBodyAsync(statusCode, headers, cancellationToken);

        public ValueTask DisposeAsync() => _request.DisposeAsync();
    }

    private sealed record ParsedHttpRequest(
        string Method,
        string Target,
        string Version,
        string Path,
        string Host,
        IReadOnlyDictionary<string, string> Headers,
        Stream Body)
        : IAsyncDisposable
    {
        public ValueTask DisposeAsync() => Body.DisposeAsync();
    }

    private sealed class HeaderReadBudget
    {
        private int _remaining;

        public HeaderReadBudget(int maximum)
        {
            _remaining = maximum;
        }

        public void Consume(int count)
        {
            _remaining -= count;
            if (_remaining < 0)
            {
                throw new SplitHttpRequestHeaderTooLargeException();
            }
        }
    }

    private sealed class SplitHttpRequestHeaderTooLargeException : Exception;

    private sealed class SplitHttpChunkedReadStream : Stream
    {
        private readonly Stream _inner;
        private long _remainingInChunk;
        private bool _completed;

        public SplitHttpChunkedReadStream(Stream inner)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() => throw new NotSupportedException();

        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public override int Read(byte[] buffer, int offset, int count)
            => ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_completed || buffer.Length == 0)
            {
                return 0;
            }

            if (_remainingInChunk == 0)
            {
                var chunkHeader = await RuntimeInternetHttpUtilities
                    .ReadHttpLineAsync(_inner, "Unexpected EOF while reading SplitHTTP request chunk header.", cancellationToken)
                    .ConfigureAwait(false);
                var separator = chunkHeader.IndexOf(';');
                var sizeText = separator >= 0 ? chunkHeader[..separator] : chunkHeader;
                if (!long.TryParse(sizeText.Trim(), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out _remainingInChunk) ||
                    _remainingInChunk < 0)
                {
                    throw new InvalidDataException("SplitHTTP inbound received an invalid chunk length.");
                }

                if (_remainingInChunk == 0)
                {
                    while (true)
                    {
                        var trailerLine = await RuntimeInternetHttpUtilities
                            .ReadHttpLineAsync(_inner, "Unexpected EOF while reading SplitHTTP request trailers.", cancellationToken)
                            .ConfigureAwait(false);
                        if (trailerLine.Length == 0)
                        {
                            break;
                        }
                    }

                    _completed = true;
                    return 0;
                }
            }

            var readLength = (int)Math.Min(buffer.Length, _remainingInChunk);
            var read = await _inner.ReadAsync(buffer[..readLength], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException("Unexpected EOF while reading SplitHTTP request payload.");
            }

            _remainingInChunk -= read;
            if (_remainingInChunk == 0)
            {
                var crlf = new byte[2];
                await ReadExactAsync(_inner, crlf, cancellationToken).ConfigureAwait(false);
                if (crlf[0] != '\r' || crlf[1] != '\n')
                {
                    throw new InvalidDataException("SplitHTTP request chunk payload was not terminated by CRLF.");
                }
            }

            return read;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }

    private sealed class SplitHttpContentLengthReadStream : Stream
    {
        private readonly Stream _inner;
        private long _remaining;

        public SplitHttpContentLengthReadStream(Stream inner, long remaining)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _remaining = remaining;
        }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() => throw new NotSupportedException();

        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public override int Read(byte[] buffer, int offset, int count)
            => ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_remaining <= 0 || buffer.Length == 0)
            {
                return 0;
            }

            var readLength = (int)Math.Min(buffer.Length, _remaining);
            var read = await _inner.ReadAsync(buffer[..readLength], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException("Unexpected EOF while reading SplitHTTP request body.");
            }

            _remaining -= read;
            return read;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }

    private sealed class SplitHttpChunkedWriteStream : Stream
    {
        private static readonly byte[] ChunkTerminator = Encoding.ASCII.GetBytes("\r\n");
        private static readonly byte[] FinalChunk = Encoding.ASCII.GetBytes("0\r\n\r\n");

        private readonly Stream _inner;
        private readonly SemaphoreSlim _writeLock = new(1, 1);
        private int _completed;
        private int _disposed;

        public SplitHttpChunkedWriteStream(Stream inner)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        }

        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
            => FlushAsync(CancellationToken.None).GetAwaiter().GetResult();

        public override Task FlushAsync(CancellationToken cancellationToken)
            => _inner.FlushAsync(cancellationToken);

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
            => WriteAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (buffer.Length == 0 || Volatile.Read(ref _completed) != 0)
            {
                return;
            }

            await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (Volatile.Read(ref _completed) != 0)
                {
                    return;
                }

                var chunkHeader = Encoding.ASCII.GetBytes(buffer.Length.ToString("X", CultureInfo.InvariantCulture) + "\r\n");
                await _inner.WriteAsync(chunkHeader, cancellationToken).ConfigureAwait(false);
                await _inner.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
                await _inner.WriteAsync(ChunkTerminator, cancellationToken).ConfigureAwait(false);
                await _inner.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _writeLock.Release();
            }
        }

        public async ValueTask CompleteAsync()
        {
            if (Interlocked.Exchange(ref _completed, 1) != 0)
            {
                return;
            }

            await _writeLock.WaitAsync(CancellationToken.None).ConfigureAwait(false);
            try
            {
                await _inner.WriteAsync(FinalChunk, CancellationToken.None).ConfigureAwait(false);
                await _inner.FlushAsync(CancellationToken.None).ConfigureAwait(false);
            }
            finally
            {
                _writeLock.Release();
            }
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                DisposeAsync().AsTask().GetAwaiter().GetResult();
            }

            base.Dispose(disposing);
        }

        public override async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            try
            {
                await CompleteAsync().ConfigureAwait(false);
            }
            finally
            {
                _writeLock.Dispose();
            }
        }
    }

    private sealed class SplitHttpApplicationStream : Stream
    {
        private readonly Stream _reader;
        private readonly Stream _writer;

        public SplitHttpApplicationStream(Stream reader, Stream writer)
        {
            _reader = reader ?? throw new ArgumentNullException(nameof(reader));
            _writer = writer ?? throw new ArgumentNullException(nameof(writer));
        }

        public override bool CanRead => _reader.CanRead;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() => _writer.Flush();

        public override Task FlushAsync(CancellationToken cancellationToken) => _writer.FlushAsync(cancellationToken);

        public override int Read(byte[] buffer, int offset, int count)
            => _reader.Read(buffer, offset, count);

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => _reader.ReadAsync(buffer, cancellationToken);

        public override void Write(byte[] buffer, int offset, int count)
            => _writer.Write(buffer, offset, count);

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => _writer.WriteAsync(buffer, cancellationToken);

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                DisposeAsync().AsTask().GetAwaiter().GetResult();
            }

            base.Dispose(disposing);
        }

        public override async ValueTask DisposeAsync()
        {
            Exception? readerException = null;
            try
            {
                await _reader.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                readerException = ex;
            }

            try
            {
                await _writer.DisposeAsync().ConfigureAwait(false);
            }
            catch when (readerException is not null)
            {
            }

            if (readerException is not null)
            {
                ExceptionDispatchInfo.Capture(readerException).Throw();
            }
        }
    }

    private sealed class SplitHttpUploadRequestStream : Stream
    {
        private readonly Stream _reader;
        private readonly TaskCompletionSource<bool> _readerCompleted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource<bool> _closed = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private Stream? _responseBody;
        private Func<ValueTask>? _completeResponseAsync;
        private int _disposed;
        private bool _readerEnded;

        public SplitHttpUploadRequestStream(Stream reader)
        {
            _reader = reader ?? throw new ArgumentNullException(nameof(reader));
        }

        public Task ReaderCompletedTask => _readerCompleted.Task;

        public Task CloseTask => _closed.Task;

        public bool IsClosed => Volatile.Read(ref _disposed) != 0;

        public void AttachResponseBody(Stream responseBody)
        {
            ArgumentNullException.ThrowIfNull(responseBody);
            if (Interlocked.CompareExchange(ref _responseBody, responseBody, null) is not null)
            {
                throw new InvalidOperationException("SplitHTTP upload response body is already attached.");
            }

            _completeResponseAsync = responseBody.DisposeAsync;

            if (IsClosed)
            {
                Interlocked.Exchange(ref _completeResponseAsync, null);
                _ = responseBody.DisposeAsync();
            }
        }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => !IsClosed;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() => _responseBody?.Flush();

        public override Task FlushAsync(CancellationToken cancellationToken)
            => _responseBody?.FlushAsync(cancellationToken) ?? Task.CompletedTask;

        public override int Read(byte[] buffer, int offset, int count)
            => ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_readerEnded || buffer.Length == 0)
            {
                return 0;
            }

            try
            {
                var read = await _reader.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    _readerEnded = true;
                    _readerCompleted.TrySetResult(true);
                }

                return read;
            }
            catch (Exception ex)
            {
                _readerEnded = true;
                _readerCompleted.TrySetResult(true);
                ExceptionDispatchInfo.Capture(ex).Throw();
                throw;
            }
        }

        public override void Write(byte[] buffer, int offset, int count)
            => WriteAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var responseBody = _responseBody ?? throw new InvalidOperationException("SplitHTTP upload response body is not attached yet.");
            return responseBody.WriteAsync(buffer, cancellationToken);
        }

        public async ValueTask CompleteResponseAsync()
        {
            var completeResponseAsync = Interlocked.Exchange(ref _completeResponseAsync, null);
            if (completeResponseAsync is null)
            {
                return;
            }

            await completeResponseAsync().ConfigureAwait(false);
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                DisposeAsync().AsTask().GetAwaiter().GetResult();
            }

            base.Dispose(disposing);
        }

        public override async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            try
            {
                await CompleteResponseAsync().ConfigureAwait(false);
            }
            finally
            {
                _closed.TrySetResult(true);
            }
        }
    }

    private sealed class SplitHttpUploadQueueReadStream : Stream
    {
        private readonly RuntimeSplitHttpUploadQueue _queue;

        public SplitHttpUploadQueueReadStream(RuntimeSplitHttpUploadQueue queue)
        {
            _queue = queue ?? throw new ArgumentNullException(nameof(queue));
        }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() => throw new NotSupportedException();

        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public override int Read(byte[] buffer, int offset, int count)
            => ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => _queue.ReadAsync(buffer, cancellationToken);

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public override ValueTask DisposeAsync() => _queue.DisposeAsync();
    }

    private static async ValueTask ReadExactAsync(
        Stream stream,
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            var current = await stream.ReadAsync(buffer[read..], cancellationToken).ConfigureAwait(false);
            if (current == 0)
            {
                throw new EndOfStreamException("Unexpected EOF while reading SplitHTTP payload.");
            }

            read += current;
        }
    }
}
