using System.Collections.Concurrent;
using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

public sealed class TrojanOutboundHandler : IOutboundHandler, IAsyncDisposable
{
    private readonly TrojanOutboundClient _client;
    private readonly IDnsResolver _dnsResolver;
    private readonly ConcurrentDictionary<string, TrojanMuxOutboundMultiplexState> _multiplexStates = new(StringComparer.OrdinalIgnoreCase);
    private readonly IServiceProvider? _serviceProvider;
    private readonly ITrojanOutboundSettingsProvider _settingsProvider;
    private readonly TrojanUdpPacketReader _udpPacketReader;
    private readonly TrojanUdpPacketWriter _udpPacketWriter;

    public TrojanOutboundHandler(
        TrojanOutboundClient client,
        ITrojanOutboundSettingsProvider settingsProvider,
        TrojanUdpPacketReader udpPacketReader,
        TrojanUdpPacketWriter udpPacketWriter,
        IServiceProvider? serviceProvider = null,
        IDnsResolver? dnsResolver = null)
    {
        _client = client;
        _settingsProvider = settingsProvider;
        _udpPacketReader = udpPacketReader;
        _udpPacketWriter = udpPacketWriter;
        _serviceProvider = serviceProvider;
        _dnsResolver = dnsResolver ?? SystemDnsResolver.Instance;
    }

    public string Protocol => OutboundProtocols.Trojan;

    public async ValueTask<Stream> OpenTcpAsync(
        DispatchContext context,
        DispatchDestination destination,
        CancellationToken cancellationToken)
    {
        if (destination.Network != DispatchNetwork.Tcp)
        {
            throw new NotSupportedException($"Trojan outbound does not support TCP open for network '{destination.Network}'.");
        }

        var settings = ResolveSettings(context);
        var resolvedDestination = await OutboundTargetStrategyResolver.ResolveAsync(
            context,
            destination,
            settings.TargetStrategy,
            _dnsResolver,
            cancellationToken).ConfigureAwait(false);
        if (TryResolveMultiplexState(settings, out var multiplexState) &&
            multiplexState.CanUseTcp)
        {
            return await multiplexState.OpenTcpAsync(
                context,
                resolvedDestination,
                CreateMuxConnectionFactory(settings),
                cancellationToken).ConfigureAwait(false);
        }

        var connection = await _client.ConnectAsync(
            CreateClientOptions(
                settings,
                context,
                TrojanCommand.Connect,
                resolvedDestination,
                CreateTransportStreamFactory(settings, context)),
            cancellationToken).ConfigureAwait(false);
        return new TrojanClientStream(connection);
    }

    public ValueTask<IOutboundUdpTransport> OpenUdpAsync(
        DispatchContext context,
        CancellationToken cancellationToken)
    {
        var settings = ResolveSettings(context);
        var transportStreamFactory = CreateTransportStreamFactory(settings, context);
        Func<IOutboundUdpTransport> createDirectTransport = () => new TrojanUdpTransport(
            _client,
            _udpPacketReader,
            _udpPacketWriter,
            settings,
            context,
            transportStreamFactory,
            _dnsResolver);

        if (TryResolveMultiplexState(settings, out var multiplexState) &&
            multiplexState.CanUseUdp)
        {
            return ValueTask.FromResult<IOutboundUdpTransport>(
                new TrojanAdaptiveUdpTransport(
                    createDirectTransport,
                    () => multiplexState.CreateUdpTransport(
                        context,
                        settings.TargetStrategy,
                        CreateMuxConnectionFactory(settings),
                        _dnsResolver),
                    multiplexState.Udp443Mode));
        }

        return ValueTask.FromResult(createDirectTransport());
    }

    private TrojanOutboundSettings ResolveSettings(DispatchContext context)
    {
        if (_settingsProvider.TryResolve(context, out var settings))
        {
            return settings;
        }

        throw new InvalidOperationException("Trojan outbound settings could not be resolved for the current dispatch context.");
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var state in _multiplexStates.Values)
        {
            await state.DisposeAsync().ConfigureAwait(false);
        }

        _multiplexStates.Clear();
    }

    private static TrojanClientOptions CreateClientOptions(
        TrojanOutboundSettings settings,
        DispatchContext context,
        TrojanCommand command,
        DispatchDestination destination,
        Func<CancellationToken, ValueTask<Stream>>? transportStreamFactory)
        => new()
        {
            SourceEndPoint = context.SourceEndPoint,
            LocalEndPoint = context.LocalEndPoint,
            Via = settings.Via,
            ViaCidr = settings.ViaCidr,
            ServerHost = settings.ServerHost,
            ServerPort = settings.ServerPort,
            ServerName = settings.ServerName,
            Transport = MapTransport(settings.Transport),
            WebSocketPath = settings.WebSocketPath,
            WebSocketHeaders = settings.WebSocketHeaders,
            WebSocketEarlyDataBytes = settings.WebSocketEarlyDataBytes,
            WebSocketHeartbeatPeriodSeconds = settings.WebSocketHeartbeatPeriodSeconds,
            ApplicationProtocols = settings.ApplicationProtocols,
            Password = settings.Password,
            Command = command,
            TargetHost = destination.Host,
            TargetPort = destination.Port,
            ConnectTimeoutSeconds = ResolveTimeout(settings.ConnectTimeoutSeconds, context.ConnectTimeoutSeconds),
            HandshakeTimeoutSeconds = ResolveTimeout(settings.HandshakeTimeoutSeconds, context.ConnectTimeoutSeconds),
            SkipCertificateValidation = settings.SkipCertificateValidation,
            TransportStreamFactory = transportStreamFactory
        };

    private Func<CancellationToken, ValueTask<Stream>>? CreateTransportStreamFactory(
        TrojanOutboundSettings settings,
        DispatchContext context)
    {
        if (string.IsNullOrWhiteSpace(settings.ProxyOutboundTag))
        {
            return null;
        }

        var dispatcher = ResolveDispatcher();
        var proxyContext = context with
        {
            OutboundTag = settings.ProxyOutboundTag,
            OriginalDestinationHost = settings.ServerHost,
            OriginalDestinationPort = settings.ServerPort
        };
        var proxyDestination = new DispatchDestination
        {
            Host = settings.ServerHost,
            Port = settings.ServerPort,
            Network = DispatchNetwork.Tcp
        };

        return token => dispatcher.DispatchTcpAsync(proxyContext, proxyDestination, token);
    }

    private Func<DispatchContext, CancellationToken, ValueTask<TrojanClientConnection>> CreateMuxConnectionFactory(
        TrojanOutboundSettings settings)
        => (dispatchContext, cancellationToken) => new ValueTask<TrojanClientConnection>(
            _client.ConnectAsync(
                CreateClientOptions(
                    settings,
                    dispatchContext,
                    TrojanCommand.Connect,
                    TrojanMuxProtocol.CreateMuxDestination(),
                    CreateTransportStreamFactory(settings, dispatchContext)),
                cancellationToken));

    private IDispatcher ResolveDispatcher()
        => _serviceProvider?.GetService(typeof(IDispatcher)) as IDispatcher
           ?? throw new InvalidOperationException("Trojan outbound proxy chaining requires an active dispatcher.");

    private bool TryResolveMultiplexState(
        TrojanOutboundSettings settings,
        out TrojanMuxOutboundMultiplexState state)
    {
        if (!settings.MultiplexSettings.Enabled)
        {
            state = default!;
            return false;
        }

        var signature = TrojanMuxSignature.FromSettings(settings);
        while (true)
        {
            if (_multiplexStates.TryGetValue(settings.Tag, out var existing))
            {
                if (existing.Signature == signature)
                {
                    state = existing;
                    return true;
                }

                var replacement = new TrojanMuxOutboundMultiplexState(signature);
                if (_multiplexStates.TryUpdate(settings.Tag, replacement, existing))
                {
                    _ = existing.DisposeAsync().AsTask();
                    state = replacement;
                    return true;
                }

                _ = replacement.DisposeAsync().AsTask();
                continue;
            }

            var created = new TrojanMuxOutboundMultiplexState(signature);
            if (_multiplexStates.TryAdd(settings.Tag, created))
            {
                state = created;
                return true;
            }

            _ = created.DisposeAsync().AsTask();
        }
    }

    private static TrojanClientTransportType MapTransport(string transport)
        => TrojanOutboundTransports.Normalize(transport) switch
        {
            TrojanOutboundTransports.Tcp => TrojanClientTransportType.Tcp,
            TrojanOutboundTransports.Tls => TrojanClientTransportType.Tls,
            TrojanOutboundTransports.Ws => TrojanClientTransportType.Ws,
            TrojanOutboundTransports.Wss => TrojanClientTransportType.Wss,
            _ => throw new NotSupportedException($"Unsupported trojan outbound transport: {transport}.")
        };

    private static int ResolveTimeout(int configuredTimeoutSeconds, int fallbackTimeoutSeconds)
    {
        if (configuredTimeoutSeconds > 0)
        {
            return configuredTimeoutSeconds;
        }

        return fallbackTimeoutSeconds > 0 ? fallbackTimeoutSeconds : 10;
    }

    private sealed class TrojanClientStream : Stream
    {
        private readonly TrojanClientConnection _connection;

        public TrojanClientStream(TrojanClientConnection connection)
        {
            _connection = connection;
        }

        private Stream InnerStream => _connection.Stream;

        public override bool CanRead => InnerStream.CanRead;

        public override bool CanSeek => InnerStream.CanSeek;

        public override bool CanWrite => InnerStream.CanWrite;

        public override long Length => InnerStream.Length;

        public override long Position
        {
            get => InnerStream.Position;
            set => InnerStream.Position = value;
        }

        public override int ReadTimeout
        {
            get => InnerStream.ReadTimeout;
            set => InnerStream.ReadTimeout = value;
        }

        public override int WriteTimeout
        {
            get => InnerStream.WriteTimeout;
            set => InnerStream.WriteTimeout = value;
        }

        public override bool CanTimeout => InnerStream.CanTimeout;

        public override void Flush() => InnerStream.Flush();

        public override Task FlushAsync(CancellationToken cancellationToken) => InnerStream.FlushAsync(cancellationToken);

        public override int Read(byte[] buffer, int offset, int count) => InnerStream.Read(buffer, offset, count);

        public override int Read(Span<byte> buffer) => InnerStream.Read(buffer);

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => InnerStream.ReadAsync(buffer, cancellationToken);

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => InnerStream.ReadAsync(buffer, offset, count, cancellationToken);

        public override long Seek(long offset, SeekOrigin origin) => InnerStream.Seek(offset, origin);

        public override void SetLength(long value) => InnerStream.SetLength(value);

        public override void Write(byte[] buffer, int offset, int count) => InnerStream.Write(buffer, offset, count);

        public override void Write(ReadOnlySpan<byte> buffer) => InnerStream.Write(buffer);

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => InnerStream.WriteAsync(buffer, cancellationToken);

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => InnerStream.WriteAsync(buffer, offset, count, cancellationToken);

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _connection.DisposeAsync().AsTask().GetAwaiter().GetResult();
            }

            base.Dispose(disposing);
        }

        public override ValueTask DisposeAsync() => _connection.DisposeAsync();
    }

    private sealed class TrojanUdpTransport : IOutboundUdpTransport
    {
        private readonly TrojanOutboundClient _client;
        private readonly SemaphoreSlim _connectLock = new(1, 1);
        private readonly DispatchContext _context;
        private readonly CancellationTokenSource _disposeCts = new();
        private readonly TaskCompletionSource<TrojanClientConnection> _connectionTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly IDnsResolver _dnsResolver;
        private readonly TrojanOutboundSettings _settings;
        private readonly Func<CancellationToken, ValueTask<Stream>>? _transportStreamFactory;
        private readonly TrojanUdpPacketReader _udpPacketReader;
        private readonly TrojanUdpPacketWriter _udpPacketWriter;
        private readonly SemaphoreSlim _writeLock = new(1, 1);

        private TrojanClientConnection? _connection;
        private int _disposed;

        public TrojanUdpTransport(
            TrojanOutboundClient client,
            TrojanUdpPacketReader udpPacketReader,
            TrojanUdpPacketWriter udpPacketWriter,
            TrojanOutboundSettings settings,
            DispatchContext context,
            Func<CancellationToken, ValueTask<Stream>>? transportStreamFactory,
            IDnsResolver dnsResolver)
        {
            _client = client;
            _udpPacketReader = udpPacketReader;
            _udpPacketWriter = udpPacketWriter;
            _settings = settings;
            _context = context;
            _transportStreamFactory = transportStreamFactory;
            _dnsResolver = dnsResolver;
        }

        public async ValueTask SendAsync(
            DispatchDestination destination,
            ReadOnlyMemory<byte> payload,
            CancellationToken cancellationToken)
        {
            ThrowIfDisposed();
            if (destination.Network != DispatchNetwork.Udp)
            {
                throw new NotSupportedException($"Trojan outbound does not support UDP send for network '{destination.Network}'.");
            }

            var resolvedDestination = await OutboundTargetStrategyResolver.ResolveAsync(
                _context,
                destination,
                _settings.TargetStrategy,
                _dnsResolver,
                cancellationToken).ConfigureAwait(false);
            var connection = await EnsureConnectedAsync(resolvedDestination, cancellationToken).ConfigureAwait(false);
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _disposeCts.Token);

            await _writeLock.WaitAsync(linkedCts.Token).ConfigureAwait(false);
            try
            {
                await _udpPacketWriter.WriteAsync(
                    connection.Stream,
                    new TrojanUdpPacket
                    {
                        DestinationHost = resolvedDestination.Host,
                        DestinationPort = resolvedDestination.Port,
                        Payload = payload.ToArray()
                    },
                    linkedCts.Token).ConfigureAwait(false);
                await connection.Stream.FlushAsync(linkedCts.Token).ConfigureAwait(false);
            }
            finally
            {
                _writeLock.Release();
            }
        }

        public async ValueTask<DispatchDatagram?> ReceiveAsync(CancellationToken cancellationToken)
        {
            ThrowIfDisposed();
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _disposeCts.Token);

            var connection = await WaitForConnectionAsync(linkedCts.Token).ConfigureAwait(false);
            var packet = await _udpPacketReader.ReadAsync(connection.Stream, linkedCts.Token).ConfigureAwait(false);
            if (packet is null)
            {
                return null;
            }

            return new DispatchDatagram
            {
                SourceHost = packet.DestinationHost,
                SourcePort = packet.DestinationPort,
                Payload = packet.Payload
            };
        }

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            _disposeCts.Cancel();
            _connectionTcs.TrySetCanceled(_disposeCts.Token);

            if (_connection is not null)
            {
                await _connection.DisposeAsync().ConfigureAwait(false);
            }

            _writeLock.Dispose();
            _connectLock.Dispose();
            _disposeCts.Dispose();
        }

        private async ValueTask<TrojanClientConnection> EnsureConnectedAsync(
            DispatchDestination destination,
            CancellationToken cancellationToken)
        {
            if (_connectionTcs.Task.IsCompletedSuccessfully)
            {
                return await _connectionTcs.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            }

            await _connectLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (_connectionTcs.Task.IsCompletedSuccessfully)
                {
                    return await _connectionTcs.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
                }

                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _disposeCts.Token);
                var connection = await _client.ConnectAsync(
                    CreateClientOptions(
                        _settings,
                        _context,
                        TrojanCommand.Associate,
                        destination,
                        _transportStreamFactory),
                    linkedCts.Token).ConfigureAwait(false);
                _connection = connection;
                _connectionTcs.TrySetResult(connection);
                return connection;
            }
            catch (Exception ex)
            {
                _connectionTcs.TrySetException(ex);
                throw;
            }
            finally
            {
                _connectLock.Release();
            }
        }

        private ValueTask<TrojanClientConnection> WaitForConnectionAsync(CancellationToken cancellationToken)
            => new(_connectionTcs.Task.WaitAsync(cancellationToken));

        private void ThrowIfDisposed()
        {
            if (Volatile.Read(ref _disposed) != 0)
            {
                throw new ObjectDisposedException(nameof(TrojanUdpTransport));
            }
        }
    }
}
