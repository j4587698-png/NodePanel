using System.Net;
using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class TrojanInboundConnectionHandlerTests
{
    [Fact]
    public async Task HandleAsync_rejects_new_ip_when_device_limit_is_reached()
    {
        var sessionRegistry = new SessionRegistry();
        var dispatcher = new BlockingDispatcher(new PendingDuplexStream());
        var rateLimiterRegistry = new RateLimiterRegistry();
        var trafficRegistry = new TrafficRegistry();
        var handler = new TrojanInboundConnectionHandler(
            dispatcher,
            new TrojanHandshakeReader(),
            new TrojanUdpAssociateRelay(
                dispatcher,
                rateLimiterRegistry,
                trafficRegistry,
                new TrojanUdpPacketReader(),
                new TrojanUdpPacketWriter()),
            new TrojanMuxInboundServer(
                dispatcher,
                rateLimiterRegistry,
                trafficRegistry),
            new TrojanFallbackRelayService(new RelayService()),
            sessionRegistry,
            new RelayService(),
            rateLimiterRegistry,
            trafficRegistry);

        var payload = new TrojanHandshakeWriter().Build("demo-password", TrojanCommand.Connect, "example.com", 443);
        var usersByHash = TestTrojanConnectionOptions.CreateUsersWithDeviceLimit(("user-a", "demo-password", 0, 1));

        using var firstConnectionCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var firstTask = handler.HandleAsync(
            new PayloadThenPendingStream(payload),
            new TestTrojanConnectionOptions
            {
                RemoteEndPoint = new IPEndPoint(IPAddress.Parse("203.0.113.10"), 50001),
                UsersByHash = usersByHash
            },
            firstConnectionCts.Token);

        await dispatcher.DispatchCalled.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(1, sessionRegistry.ActiveSessions);

        var exception = await Assert.ThrowsAsync<UnauthorizedAccessException>(() => handler.HandleAsync(
            new MemoryStream(payload, writable: false),
            new TestTrojanConnectionOptions
            {
                RemoteEndPoint = new IPEndPoint(IPAddress.Parse("203.0.113.11"), 50002),
                UsersByHash = usersByHash
            },
            CancellationToken.None));

        Assert.Contains("device limit", exception.Message, StringComparison.OrdinalIgnoreCase);

        firstConnectionCts.Cancel();
        await firstTask;

        Assert.Equal(0, sessionRegistry.ActiveSessions);
    }

    private sealed class BlockingDispatcher : IDispatcher
    {
        private readonly Stream _remoteStream;

        public BlockingDispatcher(Stream remoteStream)
        {
            _remoteStream = remoteStream;
        }

        public TaskCompletionSource<bool> DispatchCalled { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public ValueTask<Stream> DispatchTcpAsync(
            DispatchContext context,
            DispatchDestination destination,
            CancellationToken cancellationToken)
        {
            DispatchCalled.TrySetResult(true);
            return ValueTask.FromResult(_remoteStream);
        }

        public ValueTask<IOutboundUdpTransport> DispatchUdpAsync(DispatchContext context, CancellationToken cancellationToken)
            => throw new NotSupportedException();
    }

    private sealed class PayloadThenPendingStream : Stream
    {
        private readonly byte[] _payload;
        private int _position;

        public PayloadThenPendingStream(byte[] payload)
        {
            _payload = payload;
        }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => _payload.Length;

        public override long Position
        {
            get => _position;
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
            => throw new NotSupportedException();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_position < _payload.Length)
            {
                var count = Math.Min(buffer.Length, _payload.Length - _position);
                _payload.AsMemory(_position, count).CopyTo(buffer);
                _position += count;
                return count;
            }

            await Task.Delay(Timeout.Infinite, cancellationToken).ConfigureAwait(false);
            return 0;
        }

        public override long Seek(long offset, SeekOrigin origin)
            => throw new NotSupportedException();

        public override void SetLength(long value)
            => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
            => throw new NotSupportedException();
    }

    private sealed class PendingDuplexStream : Stream
    {
        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
            => throw new NotSupportedException();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await Task.Delay(Timeout.Infinite, cancellationToken).ConfigureAwait(false);
            return 0;
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => ValueTask.CompletedTask;

        public override long Seek(long offset, SeekOrigin origin)
            => throw new NotSupportedException();

        public override void SetLength(long value)
            => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
        {
        }
    }
}
