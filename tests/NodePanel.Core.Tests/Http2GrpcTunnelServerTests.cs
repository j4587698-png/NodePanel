using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Threading.Channels;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

[CollectionDefinition(Http2GrpcTunnelServerTestCollection.CollectionName, DisableParallelization = true)]
public sealed class Http2GrpcTunnelServerTestCollection
{
    public const string CollectionName = "HTTP/2 gRPC tunnel tests";
}

[Collection(Http2GrpcTunnelServerTestCollection.CollectionName)]
[Trait("Category", "Interop")]
public sealed class Http2GrpcTunnelServerTests
{
    private static readonly TimeSpan GoHelperTestTimeout = TimeSpan.FromSeconds(90);

    [Fact]
    public async Task AcceptAsync_roundtrips_with_http2_grpc_client()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var disposeGate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var serverTask = AcceptAndRoundtripAsync(listener, disposeGate.Task, lifetimeCts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, lifetimeCts.Token);

        await using var stream = await Http2GrpcTunnel.OpenAsync(
            client.GetStream(),
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.Grpc, RuntimeInternetSecurityTypes.Tls),
            new TestGrpcInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerName = "edge.example.com",
                GrpcServiceName = "/unit/test/Tun|TunMulti",
                GrpcUserAgent = "UnitGrpc/1.0"
            },
            lifetimeCts.Token);

        await stream.WriteAsync("client-hunk"u8.ToArray(), lifetimeCts.Token);
        await stream.FlushAsync(lifetimeCts.Token);

        var response = new byte["server-hunk".Length];
        await ReadExactAsync(stream, response, lifetimeCts.Token);
        disposeGate.TrySetResult();

        var accepted = await serverTask;
        Assert.Equal("/unit/test/Tun", accepted.MethodPath);
        Assert.False(accepted.MultiMode);
        Assert.Equal("client-hunk", accepted.RequestText);
        Assert.Equal("server-hunk", Encoding.ASCII.GetString(response));
        Assert.Equal("application/grpc", accepted.Headers["content-type"]);
        Assert.Equal("trailers", accepted.Headers["te"]);
        Assert.Equal("UnitGrpc/1.0", accepted.Headers["user-agent"]);
    }

    [Fact]
    public async Task AcceptAsync_roundtrips_with_grpc_go_hunk_client()
    {
        if (!TryGetGoExecutablePath(out var goExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(GoHelperTestTimeout);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var workspaceRoot = FindWorkspaceRoot();
        var helperPath = Path.Combine(
            workspaceRoot,
            "xray-core",
            ".codex-probes",
            "grpcgo-hunk-client",
            "main.go");
        Assert.True(File.Exists(helperPath), $"Missing grpc-go helper probe: {helperPath}");

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = AcceptAndRoundtripAsync(
            listener,
            Task.CompletedTask,
            lifetimeCts.Token,
            "/probe/test/Tun|TunMulti");

        using var process = new Process
        {
            StartInfo = CreateGoHelperStartInfo(
                goExecutable,
                workspaceRoot,
                helperPath,
                port.ToString())
        };

        Assert.True(process.Start(), "Failed to start grpc-go helper process.");
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();

        await process.WaitForExitAsync(lifetimeCts.Token);
        var stdout = await stdoutTask;
        var stderr = await stderrTask;
        var accepted = await serverTask;

        Assert.True(
            process.ExitCode == 0,
            $"grpc-go helper exit code: {process.ExitCode}{Environment.NewLine}stdout:{Environment.NewLine}{stdout}{Environment.NewLine}stderr:{Environment.NewLine}{stderr}");
        Assert.Contains("ok", stdout, StringComparison.Ordinal);
        Assert.True(string.IsNullOrWhiteSpace(stderr), $"grpc-go stderr: {stderr}");
        Assert.Equal("/probe/test/Tun", accepted.MethodPath);
        Assert.False(accepted.MultiMode);
        Assert.Equal("client-hunk", accepted.RequestText);
    }

    [Fact]
    public async Task AcceptAsync_roundtrips_with_grpc_go_hunk_client_split_across_two_messages()
    {
        if (!TryGetGoExecutablePath(out var goExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(GoHelperTestTimeout);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var workspaceRoot = FindWorkspaceRoot();
        var helperPath = Path.Combine(
            workspaceRoot,
            "xray-core",
            ".codex-probes",
            "grpcgo-hunk-split-client",
            "main.go");
        Assert.True(File.Exists(helperPath), $"Missing grpc-go split helper probe: {helperPath}");

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = AcceptAndRoundtripAsync(
            listener,
            Task.CompletedTask,
            lifetimeCts.Token,
            "/probe/test/Tun|TunMulti");

        using var process = new Process
        {
            StartInfo = CreateGoHelperStartInfo(
                goExecutable,
                workspaceRoot,
                helperPath,
                port.ToString())
        };

        Assert.True(process.Start(), "Failed to start grpc-go split helper process.");
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();

        await process.WaitForExitAsync(lifetimeCts.Token);
        var stdout = await stdoutTask;
        var stderr = await stderrTask;
        var accepted = await serverTask;

        Assert.True(
            process.ExitCode == 0,
            $"grpc-go split helper exit code: {process.ExitCode}{Environment.NewLine}stdout:{Environment.NewLine}{stdout}{Environment.NewLine}stderr:{Environment.NewLine}{stderr}");
        Assert.Contains("ok", stdout, StringComparison.Ordinal);
        Assert.True(string.IsNullOrWhiteSpace(stderr), $"grpc-go split helper stderr: {stderr}");
        Assert.Equal("/probe/test/Tun", accepted.MethodPath);
        Assert.False(accepted.MultiMode);
        Assert.Equal("client-hunk", accepted.RequestText);
    }

    [Fact]
    public async Task AcceptAsync_roundtrips_with_xray_like_grpc_go_hunk_client_split_across_two_messages()
    {
        if (!TryGetGoExecutablePath(out var goExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(GoHelperTestTimeout);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var workspaceRoot = FindWorkspaceRoot();
        var helperPath = Path.Combine(
            workspaceRoot,
            "xray-core",
            ".codex-probes",
            "grpcgo-hunk-split-client",
            "main.go");
        Assert.True(File.Exists(helperPath), $"Missing grpc-go split helper probe: {helperPath}");

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = AcceptAndRoundtripAsync(
            listener,
            Task.CompletedTask,
            lifetimeCts.Token,
            "/trojan/plain/Tun|TunMulti");

        using var process = new Process
        {
            StartInfo = CreateGoHelperStartInfo(
                goExecutable,
                workspaceRoot,
                helperPath,
                port.ToString(),
                "trojan/plain")
        };

        Assert.True(process.Start(), "Failed to start xray-like grpc-go split helper process.");
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();

        await process.WaitForExitAsync(lifetimeCts.Token);
        var stdout = await stdoutTask;
        var stderr = await stderrTask;
        var accepted = await serverTask;

        Assert.True(
            process.ExitCode == 0,
            $"xray-like grpc-go split helper exit code: {process.ExitCode}{Environment.NewLine}stdout:{Environment.NewLine}{stdout}{Environment.NewLine}stderr:{Environment.NewLine}{stderr}");
        Assert.Contains("ok", stdout, StringComparison.Ordinal);
        Assert.True(string.IsNullOrWhiteSpace(stderr), $"xray-like grpc-go split helper stderr: {stderr}");
        Assert.Equal("/trojan/plain/Tun", accepted.MethodPath);
        Assert.False(accepted.MultiMode);
        Assert.Equal("client-hunk", accepted.RequestText);
    }

    [Fact]
    public async Task AcceptAsync_accepts_url_escaped_service_name_sent_by_xray_process_client()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = AcceptAndReadAllAsync(
            listener,
            new RuntimeGrpcTransportOptions
            {
                ServiceName = "/trojan/plain/Tun|TunMulti",
                MultiMode = false
            },
            lifetimeCts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, lifetimeCts.Token);
        await using var stream = client.GetStream();

        await WriteClientPrefaceAsync(stream, lifetimeCts.Token);
        await WriteGrpcHeadersAsync(stream, "/trojan%2Fplain/Tun", lifetimeCts.Token);
        await WriteGrpcDataAsync(
            stream,
            EncodeGrpcMessage(EncodeHunk("escaped-service-name"u8.ToArray())),
            endStream: true,
            lifetimeCts.Token);

        var accepted = await serverTask;
        Assert.Equal("/trojan/plain/Tun", accepted.MethodPath);
        Assert.False(accepted.MultiMode);
        Assert.Equal("escaped-service-name", accepted.RequestText);
    }

    [Fact]
    public async Task AcceptAsync_uses_request_path_to_enable_tunmulti_decoder()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = AcceptAndReadAllAsync(
            listener,
            new RuntimeGrpcTransportOptions
            {
                ServiceName = "/unit/test/Tun|TunMulti",
                MultiMode = false
            },
            lifetimeCts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, lifetimeCts.Token);
        await using var stream = client.GetStream();

        await WriteClientPrefaceAsync(stream, lifetimeCts.Token);
        await WriteGrpcHeadersAsync(stream, "/unit/test/TunMulti", lifetimeCts.Token);
        await WriteGrpcDataAsync(
            stream,
            EncodeGrpcMessage(
                EncodeMultiHunk("multi-"u8.ToArray(), "payload"u8.ToArray())),
            endStream: true,
            lifetimeCts.Token);

        var accepted = await serverTask;
        Assert.Equal("/unit/test/TunMulti", accepted.MethodPath);
        Assert.True(accepted.MultiMode);
        Assert.Equal("multi-payload", accepted.RequestText);
    }

    [Fact]
    public async Task AcceptAsync_accepts_hpack_huffman_encoded_request_headers()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = AcceptAndReadAllAsync(
            listener,
            new RuntimeGrpcTransportOptions
            {
                ServiceName = "/unit/test/Tun|TunMulti",
                MultiMode = false
            },
            lifetimeCts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, lifetimeCts.Token);
        await using var stream = client.GetStream();

        await WriteClientPrefaceAsync(stream, lifetimeCts.Token);
        await WriteFrameAsync(
            stream,
            Http2TestFrameTypes.Headers,
            Http2TestFrameFlags.EndHeaders,
            streamId: 1,
            payload: BuildGrpcHeaderBlockWithHuffmanValues(),
            cancellationToken: lifetimeCts.Token);
        await WriteGrpcDataAsync(
            stream,
            EncodeGrpcMessage(EncodeHunk("huffman-request"u8.ToArray())),
            endStream: true,
            lifetimeCts.Token);

        var accepted = await serverTask;
        Assert.Equal("/unit/test/Tun", accepted.MethodPath);
        Assert.False(accepted.MultiMode);
        Assert.Equal("huffman-request", accepted.RequestText);
        Assert.Equal("application/grpc", accepted.Headers["content-type"]);
        Assert.Equal("trailers", accepted.Headers["te"]);
        Assert.Equal("RawGrpc/1.0", accepted.Headers["user-agent"]);
    }

    [Fact]
    public async Task AcceptAsync_rejects_request_when_grpc_content_type_is_missing()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = AcceptAndReadAllAsync(
            listener,
            new RuntimeGrpcTransportOptions
            {
                ServiceName = "/unit/test/Tun|TunMulti",
                MultiMode = false
            },
            lifetimeCts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, lifetimeCts.Token);
        await using var stream = client.GetStream();

        await WriteClientPrefaceAsync(stream, lifetimeCts.Token);
        await WriteGrpcHeadersAsync(
            stream,
            "/unit/test/Tun",
            lifetimeCts.Token,
            contentType: null);

        var exception = await Assert.ThrowsAsync<InvalidDataException>(async () => await serverTask);
        Assert.Contains("content-type", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AcceptAsync_rejects_request_when_grpc_content_type_is_invalid()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = AcceptAndReadAllAsync(
            listener,
            new RuntimeGrpcTransportOptions
            {
                ServiceName = "/unit/test/Tun|TunMulti",
                MultiMode = false
            },
            lifetimeCts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, lifetimeCts.Token);
        await using var stream = client.GetStream();

        await WriteClientPrefaceAsync(stream, lifetimeCts.Token);
        await WriteGrpcHeadersAsync(
            stream,
            "/unit/test/Tun",
            lifetimeCts.Token,
            contentType: "application/json");

        var exception = await Assert.ThrowsAsync<InvalidDataException>(async () => await serverTask);
        Assert.Contains("content-type", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AcceptAsync_accepts_grpc_content_type_with_suffix_and_parameters()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = AcceptAndReadAllAsync(
            listener,
            new RuntimeGrpcTransportOptions
            {
                ServiceName = "/unit/test/Tun|TunMulti",
                MultiMode = false
            },
            lifetimeCts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, lifetimeCts.Token);
        await using var stream = client.GetStream();

        await WriteClientPrefaceAsync(stream, lifetimeCts.Token);
        await WriteGrpcHeadersAsync(
            stream,
            "/unit/test/Tun",
            lifetimeCts.Token,
            contentType: "application/grpc+proto; charset=utf-8");
        await WriteGrpcDataAsync(
            stream,
            EncodeGrpcMessage(EncodeHunk("grpc-content-type"u8.ToArray())),
            endStream: true,
            lifetimeCts.Token);

        var accepted = await serverTask;
        Assert.Equal("/unit/test/Tun", accepted.MethodPath);
        Assert.Equal("grpc-content-type", accepted.RequestText);
        Assert.Equal("application/grpc+proto; charset=utf-8", accepted.Headers["content-type"]);
    }

    [Fact]
    public async Task AcceptAsync_sends_keepalive_ping_and_fails_when_ack_is_missing()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = AcceptAndExpectKeepAliveTimeoutAsync(listener, lifetimeCts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, lifetimeCts.Token);
        await using var stream = client.GetStream();

        await WriteClientPrefaceAsync(stream, lifetimeCts.Token);
        await WriteGrpcHeadersAsync(stream, "/unit/test/Tun", lifetimeCts.Token);

        var ping = await ReadUntilPingAsync(stream, lifetimeCts.Token);
        Assert.Equal(Http2TestFrameTypes.Ping, ping.Type);
        Assert.Equal(0, ping.StreamId);
        Assert.Equal(8, ping.Payload.Length);

        await serverTask;
    }

    [Fact]
    public async Task ServeAsync_accepts_second_stream_before_first_stream_finishes()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var results = Channel.CreateUnbounded<string>();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = ServeAndCaptureRequestsAsync(listener, results.Writer, lifetimeCts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, lifetimeCts.Token);
        await using var stream = client.GetStream();

        await WriteClientPrefaceAsync(stream, lifetimeCts.Token);
        await WriteGrpcHeadersAsync(stream, "/unit/test/Tun", lifetimeCts.Token, streamId: 1);
        await WriteGrpcDataAsync(
            stream,
            EncodeGrpcMessage(EncodeHunk("stream-"u8.ToArray())),
            endStream: false,
            lifetimeCts.Token,
            streamId: 1);

        await WriteGrpcHeadersAsync(stream, "/unit/test/Tun", lifetimeCts.Token, streamId: 3);
        await WriteGrpcDataAsync(
            stream,
            EncodeGrpcMessage(EncodeHunk("second"u8.ToArray())),
            endStream: true,
            lifetimeCts.Token,
            streamId: 3);

        var secondResult = await results.Reader.ReadAsync(lifetimeCts.Token);
        Assert.Equal("second", secondResult);

        await WriteGrpcDataAsync(
            stream,
            EncodeGrpcMessage(EncodeHunk("one"u8.ToArray())),
            endStream: true,
            lifetimeCts.Token,
            streamId: 1);

        var firstResult = await results.Reader.ReadAsync(lifetimeCts.Token);
        Assert.Equal("stream-one", firstResult);

        lifetimeCts.Cancel();
        await serverTask;
    }

    [Fact]
    public async Task ServeAsync_completes_normally_when_client_closes_transport_after_streams_finish()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var results = Channel.CreateUnbounded<string>();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = ServeAndCaptureRequestsAsync(listener, results.Writer, lifetimeCts.Token);

        using (var client = new TcpClient())
        {
            await client.ConnectAsync(IPAddress.Loopback, port, lifetimeCts.Token);
            await using var stream = client.GetStream();

            await WriteClientPrefaceAsync(stream, lifetimeCts.Token);
            await WriteGrpcHeadersAsync(stream, "/unit/test/Tun", lifetimeCts.Token);
            await WriteGrpcDataAsync(
                stream,
                EncodeGrpcMessage(EncodeHunk("graceful-close"u8.ToArray())),
                endStream: true,
                lifetimeCts.Token);

            var result = await results.Reader.ReadAsync(lifetimeCts.Token);
            Assert.Equal("graceful-close", result);

            client.Client.Shutdown(SocketShutdown.Send);
        }

        await serverTask;
    }

    [Fact]
    public async Task AcceptAsync_writes_grpc_response_headers_and_success_trailers()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = AcceptAndReadAllAsync(
            listener,
            new RuntimeGrpcTransportOptions
            {
                ServiceName = "/unit/test/Tun|TunMulti"
            },
            lifetimeCts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, lifetimeCts.Token);
        await using var stream = client.GetStream();

        await WriteClientPrefaceAsync(stream, lifetimeCts.Token);
        await WriteGrpcHeadersAsync(stream, "/unit/test/Tun", lifetimeCts.Token);
        await WriteGrpcDataAsync(
            stream,
            EncodeGrpcMessage(EncodeHunk("trailers-ok"u8.ToArray())),
            endStream: true,
            lifetimeCts.Token);

        var responseFramesTask = ReadResponseFramesUntilStreamEndAsync(stream, streamId: 1, lifetimeCts.Token);
        var accepted = await serverTask;
        Assert.Equal("trailers-ok", accepted.RequestText);

        var responseFrames = await responseFramesTask;
        var headerFrames = responseFrames
            .Where(frame => frame.Type == Http2TestFrameTypes.Headers && frame.StreamId == 1)
            .ToArray();

        Assert.Equal(2, headerFrames.Length);
        Assert.False((headerFrames[0].Flags & Http2TestFrameFlags.EndStream) == Http2TestFrameFlags.EndStream);

        var responseHeaders = DecodeHeaderBlock(headerFrames[0].Payload);
        Assert.Equal("200", responseHeaders[":status"]);
        Assert.Equal("application/grpc", responseHeaders["content-type"]);

        Assert.True((headerFrames[1].Flags & Http2TestFrameFlags.EndStream) == Http2TestFrameFlags.EndStream);
        var responseTrailers = DecodeHeaderBlock(headerFrames[1].Payload);
        Assert.Equal("0", responseTrailers["grpc-status"]);
    }

    [Fact]
    public async Task AcceptAsync_writes_success_trailers_without_reset_when_client_keeps_request_stream_open()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = AcceptAndRoundtripAsync(listener, Task.CompletedTask, lifetimeCts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, lifetimeCts.Token);
        await using var stream = client.GetStream();

        await WriteClientPrefaceAsync(stream, lifetimeCts.Token);
        await WriteGrpcHeadersAsync(stream, "/unit/test/Tun", lifetimeCts.Token);
        await WriteGrpcDataAsync(
            stream,
            EncodeGrpcMessage(EncodeHunk("client-open"u8.ToArray())),
            endStream: false,
            lifetimeCts.Token);

        var responseFrames = await ReadResponseFramesUntilStreamTerminalAsync(stream, streamId: 1, lifetimeCts.Token);
        var accepted = await serverTask;

        Assert.Equal("client-open", accepted.RequestText);
        Assert.DoesNotContain(
            responseFrames,
            static frame => frame.Type == Http2TestFrameTypes.RstStream && frame.StreamId == 1);

        var headerFrames = responseFrames
            .Where(frame => frame.Type == Http2TestFrameTypes.Headers && frame.StreamId == 1)
            .ToArray();

        Assert.Equal(2, headerFrames.Length);
        Assert.False((headerFrames[0].Flags & Http2TestFrameFlags.EndStream) == Http2TestFrameFlags.EndStream);
        Assert.True((headerFrames[1].Flags & Http2TestFrameFlags.EndStream) == Http2TestFrameFlags.EndStream);

        var responseHeaders = DecodeHeaderBlock(headerFrames[0].Payload);
        Assert.Equal("200", responseHeaders[":status"]);
        Assert.Equal("application/grpc", responseHeaders["content-type"]);

        var responseTrailers = DecodeHeaderBlock(headerFrames[1].Payload);
        Assert.Equal("0", responseTrailers["grpc-status"]);
    }

    [Fact]
    public async Task ServeAsync_writes_internal_grpc_status_trailer_when_handler_throws()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = ServeAndFailAfterReadingRequestAsync(listener, lifetimeCts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, lifetimeCts.Token);
        await using var stream = client.GetStream();

        await WriteClientPrefaceAsync(stream, lifetimeCts.Token);
        await WriteGrpcHeadersAsync(stream, "/unit/test/Tun", lifetimeCts.Token);
        await WriteGrpcDataAsync(
            stream,
            EncodeGrpcMessage(EncodeHunk("trailers-error"u8.ToArray())),
            endStream: true,
            lifetimeCts.Token);

        var responseFrames = await ReadResponseFramesUntilStreamEndAsync(stream, streamId: 1, lifetimeCts.Token);
        var headerFrames = responseFrames
            .Where(frame => frame.Type == Http2TestFrameTypes.Headers && frame.StreamId == 1)
            .ToArray();

        Assert.Equal(2, headerFrames.Length);
        Assert.True((headerFrames[1].Flags & Http2TestFrameFlags.EndStream) == Http2TestFrameFlags.EndStream);

        var responseTrailers = DecodeHeaderBlock(headerFrames[1].Payload);
        Assert.Equal("13", responseTrailers["grpc-status"]);

        lifetimeCts.Cancel();
        await serverTask;
    }

    private static async Task<AcceptedGrpcExchange> AcceptAndRoundtripAsync(
        TcpListener listener,
        Task waitBeforeDispose,
        CancellationToken cancellationToken,
        string serviceName = "/unit/test/Tun|TunMulti")
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var transport = client.GetStream();
        await using var accepted = await Http2GrpcTunnelServer.AcceptAsync(
            transport,
            new RuntimeGrpcTransportOptions
            {
                ServiceName = serviceName
            },
            cancellationToken);

        var request = new byte["client-hunk".Length];
        await ReadExactAsync(accepted.Stream, request, cancellationToken);
        await accepted.Stream.WriteAsync("server-hunk"u8.ToArray(), cancellationToken);
        await accepted.Stream.FlushAsync(cancellationToken);

        await waitBeforeDispose.WaitAsync(cancellationToken);

        return new AcceptedGrpcExchange(
            accepted.MethodPath,
            accepted.MultiMode,
            accepted.RequestHeaders,
            Encoding.ASCII.GetString(request));
    }

    private static async Task<AcceptedGrpcExchange> AcceptAndReadAllAsync(
        TcpListener listener,
        RuntimeGrpcTransportOptions options,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var transport = client.GetStream();
        await using var accepted = await Http2GrpcTunnelServer.AcceptAsync(transport, options, cancellationToken);

        var request = await ReadToEndAsync(accepted.Stream, cancellationToken);
        return new AcceptedGrpcExchange(
            accepted.MethodPath,
            accepted.MultiMode,
            accepted.RequestHeaders,
            Encoding.ASCII.GetString(request));
    }

    private static async Task AcceptAndExpectKeepAliveTimeoutAsync(
        TcpListener listener,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var transport = client.GetStream();
        await using var accepted = await Http2GrpcTunnelServer.AcceptAsync(
            transport,
            new RuntimeGrpcTransportOptions
            {
                ServiceName = "/unit/test/Tun|TunMulti",
                IdleTimeoutSeconds = 1,
                HealthCheckTimeoutSeconds = 1
            },
            cancellationToken);

        var buffer = new byte[1];
        var exception = await Assert.ThrowsAsync<IOException>(async () =>
            _ = await accepted.Stream.ReadAsync(buffer, cancellationToken));
        Assert.Contains("PING acknowledgement timed out", exception.Message, StringComparison.Ordinal);
    }

    private static async Task ServeAndCaptureRequestsAsync(
        TcpListener listener,
        ChannelWriter<string> results,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var transport = client.GetStream();

        try
        {
            await Http2GrpcTunnelServer.ServeAsync(
                transport,
                new RuntimeGrpcTransportOptions
                {
                    ServiceName = "/unit/test/Tun|TunMulti"
                },
                async (stream, token) =>
                {
                    var payload = await ReadToEndAsync(stream, token);
                    await results.WriteAsync(Encoding.ASCII.GetString(payload), token);
                },
                onHandlerError: null,
                cancellationToken);
        }
        finally
        {
            results.TryComplete();
        }
    }

    private static async Task ServeAndFailAfterReadingRequestAsync(
        TcpListener listener,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var transport = client.GetStream();

        await Http2GrpcTunnelServer.ServeAsync(
            transport,
            new RuntimeGrpcTransportOptions
            {
                ServiceName = "/unit/test/Tun|TunMulti"
            },
            async (stream, token) =>
            {
                _ = await ReadToEndAsync(stream, token);
                throw new InvalidOperationException("grpc handler failed");
            },
            onHandlerError: null,
            cancellationToken);
    }

    private static async Task WriteClientPrefaceAsync(Stream stream, CancellationToken cancellationToken)
    {
        await stream.WriteAsync("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8.ToArray(), cancellationToken);
        await WriteFrameAsync(
            stream,
            Http2TestFrameTypes.Settings,
            Http2TestFrameFlags.None,
            streamId: 0,
            payload: Array.Empty<byte>(),
            cancellationToken);
    }

    private static async Task<Http2TestFrame> ReadUntilPingAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            var frame = await ReadFrameAsync(stream, cancellationToken);
            if (frame.Type == Http2TestFrameTypes.Ping)
            {
                return frame;
            }
        }
    }

    private static async Task WriteGrpcHeadersAsync(
        Stream stream,
        string methodPath,
        CancellationToken cancellationToken,
        int streamId = 1,
        string? contentType = "application/grpc")
    {
        await WriteFrameAsync(
            stream,
            Http2TestFrameTypes.Headers,
            Http2TestFrameFlags.EndHeaders,
            streamId,
            payload: BuildGrpcHeaderBlock(methodPath, contentType),
            cancellationToken);
    }

    private static async Task WriteGrpcDataAsync(
        Stream stream,
        byte[] payload,
        bool endStream,
        CancellationToken cancellationToken,
        int streamId = 1)
    {
        await WriteFrameAsync(
            stream,
            Http2TestFrameTypes.Data,
            endStream ? Http2TestFrameFlags.EndStream : Http2TestFrameFlags.None,
            streamId,
            payload,
            cancellationToken);
    }

    private static async Task WriteFrameAsync(
        Stream stream,
        byte type,
        Http2TestFrameFlags flags,
        int streamId,
        byte[] payload,
        CancellationToken cancellationToken)
    {
        var header = new byte[9];
        header[0] = (byte)((payload.Length >> 16) & 0xFF);
        header[1] = (byte)((payload.Length >> 8) & 0xFF);
        header[2] = (byte)(payload.Length & 0xFF);
        header[3] = type;
        header[4] = (byte)flags;
        header[5] = (byte)((streamId >> 24) & 0x7F);
        header[6] = (byte)((streamId >> 16) & 0xFF);
        header[7] = (byte)((streamId >> 8) & 0xFF);
        header[8] = (byte)(streamId & 0xFF);

        await stream.WriteAsync(header, cancellationToken);
        if (payload.Length > 0)
        {
            await stream.WriteAsync(payload, cancellationToken);
        }

        await stream.FlushAsync(cancellationToken);
    }

    private static async Task<Http2TestFrame> ReadFrameAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var header = new byte[9];
        await ReadExactAsync(stream, header, cancellationToken);

        var length = (header[0] << 16) | (header[1] << 8) | header[2];
        var payload = new byte[length];
        if (length > 0)
        {
            await ReadExactAsync(stream, payload, cancellationToken);
        }

        return new Http2TestFrame(
            header[3],
            (Http2TestFrameFlags)header[4],
            ((header[5] & 0x7F) << 24) |
            (header[6] << 16) |
            (header[7] << 8) |
            header[8],
            payload);
    }

    private static async Task<IReadOnlyList<Http2TestFrame>> ReadResponseFramesUntilStreamEndAsync(
        Stream stream,
        int streamId,
        CancellationToken cancellationToken)
    {
        var frames = new List<Http2TestFrame>();
        while (true)
        {
            var frame = await ReadFrameAsync(stream, cancellationToken);
            frames.Add(frame);
            if (frame.StreamId == streamId &&
                (frame.Flags & Http2TestFrameFlags.EndStream) == Http2TestFrameFlags.EndStream &&
                (frame.Type == Http2TestFrameTypes.Headers || frame.Type == Http2TestFrameTypes.Data))
            {
                return frames;
            }
        }
    }

    private static async Task<IReadOnlyList<Http2TestFrame>> ReadResponseFramesUntilStreamTerminalAsync(
        Stream stream,
        int streamId,
        CancellationToken cancellationToken)
    {
        var frames = new List<Http2TestFrame>();
        while (true)
        {
            var frame = await ReadFrameAsync(stream, cancellationToken);
            frames.Add(frame);
            if (frame.StreamId != streamId)
            {
                continue;
            }

            if (frame.Type == Http2TestFrameTypes.RstStream)
            {
                return frames;
            }

            if ((frame.Flags & Http2TestFrameFlags.EndStream) == Http2TestFrameFlags.EndStream &&
                (frame.Type == Http2TestFrameTypes.Headers || frame.Type == Http2TestFrameTypes.Data))
            {
                return frames;
            }
        }
    }

    private static byte[] BuildGrpcHeaderBlock(
        string methodPath,
        string? contentType = "application/grpc")
    {
        using var buffer = new MemoryStream(256);
        WriteLiteralHeaderFieldWithoutIndexing(buffer, nameIndex: 2, name: null, value: "POST");
        WriteLiteralHeaderFieldWithoutIndexing(buffer, nameIndex: 1, name: null, value: "edge.example.com");
        WriteLiteralHeaderFieldWithoutIndexing(buffer, nameIndex: 7, name: null, value: "https");
        WriteLiteralHeaderFieldWithoutIndexing(buffer, nameIndex: 4, name: null, value: methodPath);
        if (!string.IsNullOrEmpty(contentType))
        {
            WriteLiteralHeaderFieldWithoutIndexing(buffer, nameIndex: 31, name: null, value: contentType);
        }

        WriteLiteralHeaderFieldWithoutIndexing(buffer, nameIndex: 0, name: "te", value: "trailers");
        WriteLiteralHeaderFieldWithoutIndexing(buffer, nameIndex: 58, name: null, value: "RawGrpc/1.0");
        return buffer.ToArray();
    }

    private static byte[] BuildGrpcHeaderBlockWithHuffmanValues()
    {
        return
        [
            0x02, 0x84, 0xD7, 0xAB, 0x76, 0xFF,
            0x01, 0x8C, 0x2C, 0x93, 0x15, 0x72, 0xF9, 0x1D, 0x35, 0xD0, 0x55, 0xC8, 0x7A, 0x7F,
            0x07, 0x84, 0x9D, 0x29, 0xAD, 0x1F,
            0x04, 0x8A, 0x62, 0xDA, 0x8C, 0x96, 0x12, 0x54, 0x25, 0x8D, 0xF6, 0xD5,
            0x0F, 0x10, 0x8B, 0x1D, 0x75, 0xD0, 0x62, 0x0D, 0x26, 0x3D, 0x4C, 0x4D, 0x65, 0x64,
            0x00, 0x02, 0x74, 0x65, 0x86, 0x4D, 0x83, 0x35, 0x05, 0xB1, 0x1F,
            0x0F, 0x2B, 0x89, 0xDA, 0x3F, 0x18, 0xAC, 0xAC, 0x8C, 0x05, 0x70, 0x7F
        ];
    }

    private static IReadOnlyDictionary<string, string> DecodeHeaderBlock(byte[] headerBlock)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var offset = 0;

        while (offset < headerBlock.Length)
        {
            var first = headerBlock[offset];
            if ((first & 0x80) != 0)
            {
                var index = ReadHpackInteger(headerBlock, ref offset, 7);
                if (TryResolveIndexedHeader(index, out var indexedName, out var indexedValue))
                {
                    headers[indexedName] = indexedValue;
                }

                continue;
            }

            if ((first & 0xE0) == 0x20)
            {
                _ = ReadHpackInteger(headerBlock, ref offset, 5);
                continue;
            }

            var nameIndex = ReadHpackInteger(headerBlock, ref offset, (first & 0x40) != 0 ? 6 : 4);
            var name = nameIndex == 0
                ? ReadHpackString(headerBlock, ref offset)
                : ResolveIndexedHeaderName(nameIndex);
            var value = ReadHpackString(headerBlock, ref offset);
            if (!string.IsNullOrWhiteSpace(name))
            {
                headers[name] = value;
            }
        }

        return headers;
    }

    private static void WriteLiteralHeaderFieldWithoutIndexing(
        MemoryStream buffer,
        int nameIndex,
        string? name,
        string value)
    {
        WriteInteger(buffer, nameIndex, prefixBits: 4, prefixMask: 0x00);
        if (nameIndex == 0)
        {
            WriteString(buffer, name ?? string.Empty);
        }

        WriteString(buffer, value);
    }

    private static void WriteInteger(MemoryStream buffer, int value, int prefixBits, byte prefixMask)
    {
        var maxPrefixValue = (1 << prefixBits) - 1;
        if (value < maxPrefixValue)
        {
            buffer.WriteByte((byte)(prefixMask | value));
            return;
        }

        buffer.WriteByte((byte)(prefixMask | maxPrefixValue));
        var remaining = value - maxPrefixValue;
        while (remaining >= 128)
        {
            buffer.WriteByte((byte)((remaining % 128) + 128));
            remaining /= 128;
        }

        buffer.WriteByte((byte)remaining);
    }

    private static void WriteString(MemoryStream buffer, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        WriteInteger(buffer, bytes.Length, prefixBits: 7, prefixMask: 0x00);
        buffer.Write(bytes, 0, bytes.Length);
    }

    private static byte[] EncodeGrpcMessage(byte[] messagePayload)
    {
        var frame = new byte[5 + messagePayload.Length];
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(1, 4), (uint)messagePayload.Length);
        Buffer.BlockCopy(messagePayload, 0, frame, 5, messagePayload.Length);
        return frame;
    }

    private static byte[] EncodeHunk(byte[] payload)
    {
        using var buffer = new MemoryStream(payload.Length + 8);
        WriteVarint(buffer, 0x0A);
        WriteVarint(buffer, payload.Length);
        if (payload.Length > 0)
        {
            buffer.Write(payload, 0, payload.Length);
        }

        return buffer.ToArray();
    }

    private static byte[] EncodeMultiHunk(params byte[][] payloads)
    {
        using var buffer = new MemoryStream();
        foreach (var payload in payloads)
        {
            WriteVarint(buffer, 0x0A);
            WriteVarint(buffer, payload.Length);
            if (payload.Length > 0)
            {
                buffer.Write(payload, 0, payload.Length);
            }
        }

        return buffer.ToArray();
    }

    private static void WriteVarint(Stream stream, int value)
    {
        uint remaining = checked((uint)value);
        while (remaining >= 0x80)
        {
            stream.WriteByte((byte)((remaining & 0x7F) | 0x80));
            remaining >>= 7;
        }

        stream.WriteByte((byte)remaining);
    }

    private static bool TryResolveIndexedHeader(
        int index,
        out string name,
        out string value)
    {
        switch (index)
        {
            case 8:
                name = ":status";
                value = "200";
                return true;
            case 31:
                name = "content-type";
                value = string.Empty;
                return true;
            default:
                name = string.Empty;
                value = string.Empty;
                return false;
        }
    }

    private static string ResolveIndexedHeaderName(int index)
        => TryResolveIndexedHeader(index, out var name, out _)
            ? name
            : string.Empty;

    private static int ReadHpackInteger(byte[] buffer, ref int offset, int prefixBits)
    {
        if (offset >= buffer.Length)
        {
            throw new InvalidDataException("HPACK integer exceeded the available header block bytes.");
        }

        var maxPrefixValue = (1 << prefixBits) - 1;
        var value = buffer[offset] & maxPrefixValue;
        offset++;

        if (value < maxPrefixValue)
        {
            return value;
        }

        var shift = 0;
        while (true)
        {
            if (offset >= buffer.Length)
            {
                throw new InvalidDataException("HPACK integer exceeded the available header block bytes.");
            }

            var next = buffer[offset++];
            value += (next & 0x7F) << shift;
            if ((next & 0x80) == 0)
            {
                return value;
            }

            shift += 7;
        }
    }

    private static string ReadHpackString(byte[] buffer, ref int offset)
    {
        if (offset >= buffer.Length)
        {
            throw new InvalidDataException("HPACK string literal exceeded the available header block bytes.");
        }

        var huffmanEncoded = (buffer[offset] & 0x80) != 0;
        if (huffmanEncoded)
        {
            throw new NotSupportedException("HPACK Huffman-encoded strings are not supported by this test.");
        }

        var length = ReadHpackInteger(buffer, ref offset, 7);
        if (length < 0 || offset + length > buffer.Length)
        {
            throw new InvalidDataException("HPACK string literal exceeded the available header block bytes.");
        }

        var value = Encoding.ASCII.GetString(buffer, offset, length);
        offset += length;
        return value;
    }

    private static async Task<byte[]> ReadToEndAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        var readBuffer = new byte[256];
        while (true)
        {
            var read = await stream.ReadAsync(readBuffer, cancellationToken);
            if (read == 0)
            {
                return buffer.ToArray();
            }

            buffer.Write(readBuffer, 0, read);
        }
    }

    private static async Task ReadExactAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            var count = await stream.ReadAsync(buffer.AsMemory(read, buffer.Length - read), cancellationToken);
            if (count == 0)
            {
                throw new EndOfStreamException("Unexpected EOF while reading test payload.");
            }

            read += count;
        }
    }

    private static bool TryGetGoExecutablePath(out string path)
    {
        var toolsDirectory = Path.Combine(FindWorkspaceRoot(), ".codex-build", "tools");
        if (Directory.Exists(toolsDirectory))
        {
            path = Directory
                .EnumerateFiles(toolsDirectory, "go.exe", SearchOption.AllDirectories)
                .Where(static candidate =>
                    candidate.EndsWith(
                        $"{Path.DirectorySeparatorChar}go{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}go.exe",
                        StringComparison.OrdinalIgnoreCase))
                .Where(IsCompleteGoExecutablePath)
                .OrderByDescending(static candidate => candidate.Contains("-full", StringComparison.OrdinalIgnoreCase))
                .ThenByDescending(static candidate => candidate, StringComparer.OrdinalIgnoreCase)
                .FirstOrDefault() ?? string.Empty;
            if (!string.IsNullOrWhiteSpace(path))
            {
                return true;
            }
        }

        var tool = OperatingSystem.IsWindows() ? "where.exe" : "which";
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = tool,
                Arguments = "go",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            }
        };

        if (!process.Start())
        {
            path = string.Empty;
            return false;
        }

        var output = process.StandardOutput.ReadLine();
        process.WaitForExit();
        path = string.IsNullOrWhiteSpace(output) ? string.Empty : output.Trim();
        return process.ExitCode == 0 &&
               !string.IsNullOrWhiteSpace(path) &&
               IsCompleteGoExecutablePath(path);
    }

    private static ProcessStartInfo CreateGoHelperStartInfo(
        string goExecutable,
        string workspaceRoot,
        string helperPath,
        params string[] arguments)
    {
        var codexBuildDirectory = Path.Combine(workspaceRoot, ".codex-build");
        var goCacheDirectory = Path.Combine(codexBuildDirectory, "go-cache");
        var goModuleCacheDirectory = Path.Combine(codexBuildDirectory, "go-mod");
        var goRootDirectory = GetGoRootDirectory(goExecutable);
        Directory.CreateDirectory(goCacheDirectory);
        Directory.CreateDirectory(goModuleCacheDirectory);

        var startInfo = new ProcessStartInfo
        {
            FileName = goExecutable,
            WorkingDirectory = Path.Combine(workspaceRoot, "xray-core"),
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        startInfo.ArgumentList.Add("run");
        startInfo.ArgumentList.Add(helperPath);
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        startInfo.Environment["GOROOT"] = goRootDirectory;
        startInfo.Environment["GOCACHE"] = goCacheDirectory;
        startInfo.Environment["GOMODCACHE"] = goModuleCacheDirectory;
        return startInfo;
    }

    private static bool IsCompleteGoExecutablePath(string candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate) || !File.Exists(candidate))
        {
            return false;
        }

        var goRootDirectory = GetGoRootDirectory(candidate);
        return File.Exists(Path.Combine(goRootDirectory, "src", "fmt", "print.go")) &&
               File.Exists(Path.Combine(goRootDirectory, "src", "errors", "errors.go"));
    }

    private static string GetGoRootDirectory(string goExecutable)
    {
        var binDirectory = Path.GetDirectoryName(goExecutable);
        return binDirectory is null
            ? string.Empty
            : Path.GetFullPath(Path.Combine(binDirectory, ".."));
    }

    private static string FindWorkspaceRoot()
    {
        if (TryFindWorkspaceRoot(AppContext.BaseDirectory, out var root) ||
            TryFindWorkspaceRoot(Directory.GetCurrentDirectory(), out root))
        {
            return root;
        }

        throw new DirectoryNotFoundException("Could not locate the Xray-core workspace root.");
    }

    private static bool TryFindWorkspaceRoot(string startPath, out string root)
    {
        for (var directory = new DirectoryInfo(startPath); directory is not null; directory = directory.Parent)
        {
            if (Directory.Exists(Path.Combine(directory.FullName, "Xray-dotnet")) &&
                Directory.Exists(Path.Combine(directory.FullName, "xray-core")))
            {
                root = directory.FullName;
                return true;
            }
        }

        root = string.Empty;
        return false;
    }

    private sealed record AcceptedGrpcExchange(
        string MethodPath,
        bool MultiMode,
        IReadOnlyDictionary<string, string> Headers,
        string RequestText);

    private readonly record struct Http2TestFrame(
        byte Type,
        Http2TestFrameFlags Flags,
        int StreamId,
        byte[] Payload);

    private sealed record TestGrpcInternetOptions : IRuntimeInternetOptions
    {
        public string ServerHost { get; init; } = string.Empty;

        public string ServerName { get; init; } = string.Empty;

        public string Fingerprint { get; init; } = string.Empty;

        public string TransportProtocol => RuntimeInternetTransportProtocols.Grpc;

        public string SecurityType { get; init; } = RuntimeInternetSecurityTypes.Tls;

        public RuntimeRealityOptions RealityOptions { get; init; } = RuntimeRealityOptions.Empty;

        public string WebSocketPath => "/";

        public IReadOnlyDictionary<string, string> WebSocketHeaders { get; init; }
            = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public int WebSocketHeartbeatPeriodSeconds => 0;

        public string SplitHttpHost { get; init; } = string.Empty;

        public string SplitHttpPath { get; init; } = "/";

        public IReadOnlyDictionary<string, string> SplitHttpHeaders { get; init; }
            = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public string SplitHttpMode { get; init; } = string.Empty;

        public bool SplitHttpNoGrpcHeader => false;

        public RuntimeInt32Range SplitHttpXPaddingBytes => RuntimeInt32Range.Empty;

        public bool SplitHttpXPaddingObfsMode => false;

        public string SplitHttpXPaddingKey => string.Empty;

        public string SplitHttpXPaddingHeader => string.Empty;

        public string SplitHttpXPaddingPlacement => string.Empty;

        public string SplitHttpXPaddingMethod => string.Empty;

        public string SplitHttpUplinkHttpMethod => string.Empty;

        public string SplitHttpSessionPlacement => string.Empty;

        public string SplitHttpSessionKey => string.Empty;

        public string SplitHttpSeqPlacement => string.Empty;

        public string SplitHttpSeqKey => string.Empty;

        public string SplitHttpUplinkDataPlacement => string.Empty;

        public string SplitHttpUplinkDataKey => string.Empty;

        public RuntimeInt32Range SplitHttpUplinkChunkSize => RuntimeInt32Range.Empty;

        public RuntimeInt32Range SplitHttpScMaxEachPostBytes => RuntimeInt32Range.Empty;

        public RuntimeInt32Range SplitHttpScMinPostsIntervalMs => RuntimeInt32Range.Empty;

        public int SplitHttpScMaxBufferedPosts => 0;

        public RuntimeSplitHttpXmuxOptions SplitHttpXmux => RuntimeSplitHttpXmuxOptions.Empty;

        public RuntimeSplitHttpDownloadOptions? SplitHttpDownloadSettings => null;

        public IReadOnlyList<string> ApplicationProtocols { get; init; } = Array.Empty<string>();

        public RuntimeQuicOptions QuicOptions => RuntimeQuicOptions.Empty;

        public string GrpcServiceName { get; init; } = string.Empty;

        public string GrpcAuthority { get; init; } = string.Empty;

        public bool GrpcMultiMode { get; init; }

        public string GrpcUserAgent { get; init; } = string.Empty;

        public int GrpcIdleTimeoutSeconds { get; init; }

        public int GrpcHealthCheckTimeoutSeconds { get; init; }

        public bool GrpcPermitWithoutStream { get; init; }

        public int GrpcInitialWindowSize { get; init; }

        public bool SkipCertificateValidation => true;

        public RemoteCertificateValidationCallback? CertificateValidationCallback => null;

        public SslProtocols EnabledSslProtocols => SslProtocols.Tls12 | SslProtocols.Tls13;
    }

    [Flags]
    private enum Http2TestFrameFlags : byte
    {
        None = 0,
        Ack = 0x1,
        EndStream = 0x1,
        EndHeaders = 0x4
    }

    private static class Http2TestFrameTypes
    {
        public const byte Data = 0x0;
        public const byte Headers = 0x1;
        public const byte Ping = 0x6;
        public const byte RstStream = 0x3;
        public const byte Settings = 0x4;
    }
}
