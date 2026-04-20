using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;

namespace NodePanel.Core.Runtime;

public sealed class DnsOutboundHandler : IOutboundHandler
{
    private readonly IOutboundCommonSettingsProvider? _commonSettingsProvider;
    private readonly IDnsResolver _dnsResolver;
    private readonly IRuntimeOutboundSettingsProvider? _runtimeSettingsProvider;
    private readonly IServiceProvider? _serviceProvider;

    public DnsOutboundHandler(
        IOutboundCommonSettingsProvider? commonSettingsProvider = null,
        IRuntimeOutboundSettingsProvider? runtimeSettingsProvider = null,
        IServiceProvider? serviceProvider = null,
        IDnsResolver? dnsResolver = null)
    {
        _commonSettingsProvider = commonSettingsProvider;
        _runtimeSettingsProvider = runtimeSettingsProvider;
        _serviceProvider = serviceProvider;
        _dnsResolver = dnsResolver ?? SystemDnsResolver.Instance;
    }

    public string Protocol => OutboundProtocols.Dns;

    public ValueTask<Stream> OpenTcpAsync(
        DispatchContext context,
        DispatchDestination destination,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(destination);
        if (destination.Network != DispatchNetwork.Tcp)
        {
            throw new NotSupportedException($"DNS outbound does not support TCP open for network '{destination.Network}'.");
        }

        var settings = ResolveSettings(context);
        return ValueTask.FromResult<Stream>(new DnsTcpOutboundStream(
            new DnsRequestProcessor(context, settings, _dnsResolver, _serviceProvider),
            destination));
    }

    public ValueTask<IOutboundUdpTransport> OpenUdpAsync(
        DispatchContext context,
        CancellationToken cancellationToken)
    {
        var settings = ResolveSettings(context);
        return ValueTask.FromResult<IOutboundUdpTransport>(new DnsUdpTransport(
            new DnsRequestProcessor(context, settings, _dnsResolver, _serviceProvider)));
    }

    private DnsResolvedSettings ResolveSettings(DispatchContext context)
    {
        var commonSettings = CreateDefaultCommonSettings(context);
        if (_commonSettingsProvider is not null)
        {
            if (!_commonSettingsProvider.TryResolve(context, out commonSettings) ||
                !string.Equals(commonSettings.Protocol, OutboundProtocols.Dns, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("DNS outbound common settings could not be resolved for the current dispatch context.");
            }
        }

        var runtimeSettings = new RuntimeDnsOutboundOptions
        {
            Tag = commonSettings.Tag
        };

        if (_runtimeSettingsProvider is not null &&
            _runtimeSettingsProvider.TryResolve(context, out IRuntimeOutboundOptions resolvedOptions))
        {
            if (!string.Equals(
                    OutboundProtocols.Normalize(resolvedOptions.Protocol),
                    OutboundProtocols.Dns,
                    StringComparison.Ordinal))
            {
                throw new InvalidOperationException("DNS outbound settings could not be resolved for the current dispatch context.");
            }

            if (resolvedOptions is not RuntimeDnsOutboundOptions dnsOptions)
            {
                throw new InvalidOperationException("DNS outbound runtime settings are invalid.");
            }

            runtimeSettings = dnsOptions;
        }

        return new DnsResolvedSettings
        {
            Common = commonSettings,
            Outbound = runtimeSettings
        };
    }

    private static OutboundCommonSettings CreateDefaultCommonSettings(DispatchContext context)
        => new()
        {
            Tag = string.IsNullOrWhiteSpace(context.OutboundTag)
                ? OutboundProtocols.Dns
                : context.OutboundTag.Trim(),
            Protocol = OutboundProtocols.Dns
        };

    private sealed record DnsResolvedSettings
    {
        public required OutboundCommonSettings Common { get; init; }

        public required RuntimeDnsOutboundOptions Outbound { get; init; }
    }

    private sealed record DnsOutboundResponse
    {
        public required DispatchDestination Source { get; init; }

        public required byte[] Payload { get; init; }
    }

    private sealed class DnsRequestProcessor : IAsyncDisposable
    {
        private readonly DispatchContext _context;
        private readonly IDnsResolver _dnsResolver;
        private readonly DnsResolvedSettings _settings;
        private readonly IServiceProvider? _serviceProvider;
        private readonly SemaphoreSlim _tcpExchangeSync = new(1, 1);

        private Stream? _tcpExchangeStream;
        private DispatchDestination? _tcpExchangeTarget;
        private int _disposed;

        public DnsRequestProcessor(
            DispatchContext context,
            DnsResolvedSettings settings,
            IDnsResolver dnsResolver,
            IServiceProvider? serviceProvider)
        {
            _context = context;
            _settings = settings;
            _dnsResolver = dnsResolver;
            _serviceProvider = serviceProvider;
        }

        public async ValueTask<DnsOutboundResponse?> ProcessAsync(
            DispatchDestination destination,
            ReadOnlyMemory<byte> payload,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(destination);

            if (!DnsOutboundProtocolCodec.TryParseQuery(payload.Span, out var query))
            {
                throw new InvalidDataException("DNS outbound received an invalid query payload.");
            }

            if (IsBlockedQueryType(query.Type))
            {
                return CreateBlockedQueryTypeResponse(query, destination);
            }

            if (query.IsIpQuery)
            {
                return await ResolveIpQueryAsync(query, destination, cancellationToken).ConfigureAwait(false);
            }

            return await CreateNonIpResponseAsync(query, destination, cancellationToken, payload).ConfigureAwait(false);
        }

        private bool IsBlockedQueryType(ushort queryType)
            => _settings.Outbound.BlockTypes.Contains(queryType);

        private DnsOutboundResponse? CreateBlockedQueryTypeResponse(
            DnsOutboundQuery query,
            DispatchDestination destination)
        {
            return DnsOutboundNonIpQueryModes.Normalize(_settings.Outbound.NonIpQuery) ==
                   DnsOutboundNonIpQueryModes.Reject
                ? CreateResponse(
                    ResolveResponseSource(destination),
                    DnsOutboundProtocolCodec.BuildRefusedResponse(query))
                : null;
        }

        private async ValueTask<DnsOutboundResponse?> ResolveIpQueryAsync(
            DnsOutboundQuery query,
            DispatchDestination destination,
            CancellationToken cancellationToken)
        {
            try
            {
                var resolver = DispatchDnsResolution.ResolveResolver(_context, _dnsResolver);
                var lookup = await resolver.LookupAsync(
                    query.Domain,
                    CreateLookupOptions(query.Type),
                    cancellationToken).ConfigureAwait(false);
                if (lookup.ResponseCode != DnsResponseCodes.Success)
                {
                    return CreateResponse(
                        ResolveResponseSource(destination),
                        DnsOutboundProtocolCodec.BuildErrorResponse(query, lookup.ResponseCode));
                }

                var filtered = FilterAddresses(lookup.Addresses, query.Type);
                return CreateResponse(
                    ResolveResponseSource(destination),
                    DnsOutboundProtocolCodec.BuildResponse(query, filtered, ttl: lookup.TtlSeconds));
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                var responseCode = DnsResolverExtensions.GetResponseCode(ex);
                return responseCode == DnsResponseCodes.Success
                    ? null
                    : CreateResponse(
                        ResolveResponseSource(destination),
                        DnsOutboundProtocolCodec.BuildErrorResponse(query, responseCode));
            }
        }

        private async ValueTask<DnsOutboundResponse?> CreateNonIpResponseAsync(
            DnsOutboundQuery query,
            DispatchDestination destination,
            CancellationToken cancellationToken,
            ReadOnlyMemory<byte> payload = default)
        {
            return DnsOutboundNonIpQueryModes.Normalize(_settings.Outbound.NonIpQuery) switch
            {
                DnsOutboundNonIpQueryModes.Drop => null,
                DnsOutboundNonIpQueryModes.Reject => CreateResponse(
                    ResolveResponseSource(destination),
                    DnsOutboundProtocolCodec.BuildRefusedResponse(query)),
                _ => await ForwardAsync(destination, payload, cancellationToken).ConfigureAwait(false)
            };
        }

        private async ValueTask<DnsOutboundResponse?> ForwardAsync(
            DispatchDestination destination,
            ReadOnlyMemory<byte> payload,
            CancellationToken cancellationToken)
        {
            var target = ResolveTargetDestination(destination);
            var resolvedTarget = await OutboundTargetStrategyResolver.ResolveAsync(
                _context,
                target,
                _settings.Common.TargetStrategy,
                _dnsResolver,
                cancellationToken).ConfigureAwait(false);

            var responsePayload = resolvedTarget.Network switch
            {
                DispatchNetwork.Tcp => await ForwardTcpAsync(resolvedTarget, payload, cancellationToken).ConfigureAwait(false),
                _ => await ForwardUdpAsync(resolvedTarget, payload, cancellationToken).ConfigureAwait(false)
            };

            return responsePayload is null
                ? null
                : CreateResponse(resolvedTarget, responsePayload);
        }

        private async Task<byte[]?> ForwardUdpAsync(
            DispatchDestination destination,
            ReadOnlyMemory<byte> payload,
            CancellationToken cancellationToken)
        {
            if (!string.IsNullOrWhiteSpace(_settings.Common.ProxyOutboundTag))
            {
                await using var transport = await ResolveDispatcher().DispatchUdpAsync(
                    CreateProxyContext(_context, destination, _settings.Common.ProxyOutboundTag),
                    cancellationToken).ConfigureAwait(false);
                await transport.SendAsync(destination, payload, cancellationToken).ConfigureAwait(false);
                var datagram = await transport.ReceiveAsync(cancellationToken).ConfigureAwait(false);
                return datagram?.Payload;
            }

            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            linkedCts.CancelAfter(TimeSpan.FromSeconds(Math.Max(1, _context.ConnectTimeoutSeconds)));
            var endPoints = await OutboundSocketDialer.ResolveTcpEndPointsAsync(
                _context,
                destination.Host,
                destination.Port,
                AddressFamily.Unspecified,
                _dnsResolver,
                linkedCts.Token).ConfigureAwait(false);
            var remoteEndPoint = endPoints[0];
            using var socket = OutboundSocketDialer.CreateUdpSocket(
                _context,
                _settings.Common.Via,
                _settings.Common.ViaCidr,
                remoteEndPoint.AddressFamily);

            await socket.SendToAsync(payload, SocketFlags.None, remoteEndPoint, linkedCts.Token).ConfigureAwait(false);

            var buffer = new byte[65535];
            var placeholder = remoteEndPoint.AddressFamily == AddressFamily.InterNetworkV6
                ? new IPEndPoint(IPAddress.IPv6Any, 0)
                : new IPEndPoint(IPAddress.Any, 0);
            var response = await socket.ReceiveFromAsync(
                buffer.AsMemory(0, buffer.Length),
                SocketFlags.None,
                placeholder,
                linkedCts.Token).ConfigureAwait(false);
            return buffer.AsSpan(0, response.ReceivedBytes).ToArray();
        }

        private async Task<byte[]?> ForwardTcpAsync(
            DispatchDestination destination,
            ReadOnlyMemory<byte> payload,
            CancellationToken cancellationToken)
        {
            ThrowIfDisposed();
            await _tcpExchangeSync.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var stream = await GetOrOpenTcpExchangeStreamAsync(destination, cancellationToken).ConfigureAwait(false);
                try
                {
                    return await ExchangeTcpAsync(stream, payload, cancellationToken).ConfigureAwait(false);
                }
                catch
                {
                    await DisposeCachedTcpExchangeStreamAsync().ConfigureAwait(false);
                    throw;
                }
            }
            finally
            {
                _tcpExchangeSync.Release();
            }
        }

        private static async Task<byte[]> ExchangeTcpAsync(
            Stream stream,
            ReadOnlyMemory<byte> payload,
            CancellationToken cancellationToken)
        {
            await stream.WriteAsync(DnsOutboundProtocolCodec.FrameTcpMessage(payload.Span), cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

            var lengthBytes = new byte[2];
            await stream.ReadExactlyAsync(lengthBytes.AsMemory(0, 2), cancellationToken).ConfigureAwait(false);
            var responseLength = BinaryPrimitives.ReadUInt16BigEndian(lengthBytes);
            var response = new byte[responseLength];
            await stream.ReadExactlyAsync(response.AsMemory(0, response.Length), cancellationToken).ConfigureAwait(false);
            return response;
        }

        private DispatchDestination ResolveTargetDestination(DispatchDestination destination)
        {
            var network = string.IsNullOrWhiteSpace(_settings.Outbound.ServerNetwork)
                ? destination.Network
                : _settings.Outbound.ServerNetwork == RoutingNetworks.Tcp
                    ? DispatchNetwork.Tcp
                    : DispatchNetwork.Udp;
            var host = string.IsNullOrWhiteSpace(_settings.Outbound.ServerHost)
                ? destination.Host
                : _settings.Outbound.ServerHost;
            var port = _settings.Outbound.ServerPort > 0
                ? _settings.Outbound.ServerPort
                : destination.Port;

            return destination with
            {
                Host = host,
                Port = port,
                Network = network
            };
        }

        private DispatchDestination ResolveResponseSource(DispatchDestination destination)
        {
            var target = ResolveTargetDestination(destination);
            return target with
            {
                Host = string.IsNullOrWhiteSpace(target.Host) ? destination.Host : target.Host,
                Port = target.Port > 0 ? target.Port : destination.Port
            };
        }

        private IDispatcher ResolveDispatcher()
            => _serviceProvider?.GetService(typeof(IDispatcher)) as IDispatcher
               ?? throw new InvalidOperationException("DNS outbound proxy chaining requires an active dispatcher.");

        private static DnsOutboundResponse CreateResponse(DispatchDestination source, byte[] payload)
            => new()
            {
                Source = source,
                Payload = payload
            };

        private static IReadOnlyList<IPAddress> FilterAddresses(IReadOnlyList<IPAddress> addresses, ushort queryType)
        {
            return addresses
                .Where(address => queryType switch
                {
                    DnsOutboundProtocolCodec.TypeA => address.AddressFamily == AddressFamily.InterNetwork,
                    DnsOutboundProtocolCodec.TypeAAAA => address.AddressFamily == AddressFamily.InterNetworkV6,
                    _ => false
                })
                .Select(static address => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address)
                .Distinct()
                .ToArray();
        }

        private static DispatchContext CreateProxyContext(
            DispatchContext context,
            DispatchDestination destination,
            string outboundTag)
            => context with
            {
                OutboundTag = outboundTag,
                OriginalDestinationHost = string.IsNullOrWhiteSpace(context.OriginalDestinationHost)
                    ? destination.Host
                    : context.OriginalDestinationHost,
                OriginalDestinationPort = context.OriginalDestinationPort > 0
                    ? context.OriginalDestinationPort
                    : destination.Port
            };

        private static DnsLookupOptions CreateLookupOptions(ushort queryType)
            => queryType switch
            {
                DnsOutboundProtocolCodec.TypeA => new DnsLookupOptions
                {
                    IPv4Enable = true,
                    IPv6Enable = false,
                    FakeEnable = true
                },
                DnsOutboundProtocolCodec.TypeAAAA => new DnsLookupOptions
                {
                    IPv4Enable = false,
                    IPv6Enable = true,
                    FakeEnable = true
                },
                _ => DnsLookupOptions.Default
            };

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            await _tcpExchangeSync.WaitAsync().ConfigureAwait(false);
            try
            {
                await DisposeCachedTcpExchangeStreamAsync().ConfigureAwait(false);
            }
            finally
            {
                _tcpExchangeSync.Release();
                _tcpExchangeSync.Dispose();
            }
        }

        private async Task<Stream> GetOrOpenTcpExchangeStreamAsync(
            DispatchDestination destination,
            CancellationToken cancellationToken)
        {
            if (_tcpExchangeStream is not null &&
                _tcpExchangeTarget == destination)
            {
                return _tcpExchangeStream;
            }

            await DisposeCachedTcpExchangeStreamAsync().ConfigureAwait(false);
            _tcpExchangeStream = await OpenTcpExchangeStreamAsync(destination, cancellationToken).ConfigureAwait(false);
            _tcpExchangeTarget = destination;
            return _tcpExchangeStream;
        }

        private async Task<Stream> OpenTcpExchangeStreamAsync(
            DispatchDestination destination,
            CancellationToken cancellationToken)
        {
            if (!string.IsNullOrWhiteSpace(_settings.Common.ProxyOutboundTag))
            {
                return await ResolveDispatcher().DispatchTcpAsync(
                    CreateProxyContext(_context, destination, _settings.Common.ProxyOutboundTag),
                    destination,
                    cancellationToken).ConfigureAwait(false);
            }

            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            linkedCts.CancelAfter(TimeSpan.FromSeconds(Math.Max(1, _context.ConnectTimeoutSeconds)));
            var endPoints = await OutboundSocketDialer.ResolveTcpEndPointsAsync(
                _context,
                destination.Host,
                destination.Port,
                AddressFamily.Unspecified,
                _dnsResolver,
                linkedCts.Token).ConfigureAwait(false);
            return await OutboundSocketDialer.OpenTcpStreamAsync(
                _context,
                _settings.Common.Via,
                _settings.Common.ViaCidr,
                endPoints,
                linkedCts.Token).ConfigureAwait(false);
        }

        private async Task DisposeCachedTcpExchangeStreamAsync()
        {
            var stream = _tcpExchangeStream;
            _tcpExchangeStream = null;
            _tcpExchangeTarget = null;

            if (stream is null)
            {
                return;
            }

            await stream.DisposeAsync().ConfigureAwait(false);
        }

        private void ThrowIfDisposed()
        {
            if (Volatile.Read(ref _disposed) != 0)
            {
                throw new ObjectDisposedException(nameof(DnsRequestProcessor));
            }
        }
    }

    private sealed class DnsUdpTransport : IOutboundUdpTransport
    {
        private readonly CancellationTokenSource _disposeCts = new();
        private readonly DnsRequestProcessor _processor;
        private readonly Channel<DispatchDatagram> _responses = Channel.CreateUnbounded<DispatchDatagram>(
            new UnboundedChannelOptions
            {
                SingleReader = true,
                SingleWriter = false
            });
        private int _disposed;

        public DnsUdpTransport(DnsRequestProcessor processor)
        {
            _processor = processor;
        }

        public async ValueTask SendAsync(
            DispatchDestination destination,
            ReadOnlyMemory<byte> payload,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(destination);
            ThrowIfDisposed();
            if (destination.Network != DispatchNetwork.Udp)
            {
                throw new NotSupportedException($"DNS outbound UDP transport does not support destination network '{destination.Network}'.");
            }

            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _disposeCts.Token);
            var response = await _processor.ProcessAsync(destination, payload, linkedCts.Token).ConfigureAwait(false);
            if (response is null)
            {
                return;
            }

            await _responses.Writer.WriteAsync(
                new DispatchDatagram
                {
                    SourceHost = response.Source.Host,
                    SourcePort = response.Source.Port,
                    Payload = response.Payload
                },
                linkedCts.Token).ConfigureAwait(false);
        }

        public async ValueTask<DispatchDatagram?> ReceiveAsync(CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _disposeCts.Token);
            try
            {
                return await _responses.Reader.ReadAsync(linkedCts.Token).ConfigureAwait(false);
            }
            catch (ChannelClosedException)
            {
                return null;
            }
            catch (OperationCanceledException) when (_disposeCts.IsCancellationRequested)
            {
                return null;
            }
        }

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            _disposeCts.Cancel();
            _responses.Writer.TryComplete();
            await _processor.DisposeAsync().ConfigureAwait(false);
            _disposeCts.Dispose();
        }

        private void ThrowIfDisposed()
        {
            if (Volatile.Read(ref _disposed) != 0)
            {
                throw new ObjectDisposedException(nameof(DnsUdpTransport));
            }
        }
    }

    private sealed class DnsTcpOutboundStream : Stream
    {
        private readonly CancellationTokenSource _disposeCts = new();
        private readonly DispatchDestination _destination;
        private readonly DnsRequestProcessor _processor;
        private readonly Channel<byte[]> _responses = Channel.CreateUnbounded<byte[]>(
            new UnboundedChannelOptions
            {
                SingleReader = true,
                SingleWriter = false
            });
        private readonly object _readSync = new();
        private readonly object _writeSync = new();

        private byte[] _requestBuffer = new byte[512];
        private int _requestBufferLength;
        private byte[]? _responseBuffer;
        private int _responseOffset;
        private int _disposed;

        public DnsTcpOutboundStream(
            DnsRequestProcessor processor,
            DispatchDestination destination)
        {
            _processor = processor;
            _destination = destination;
        }

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

        public override Task FlushAsync(CancellationToken cancellationToken)
            => Task.CompletedTask;

        public override int Read(byte[] buffer, int offset, int count)
            => ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            if (buffer.Length == 0)
            {
                return 0;
            }

            var copied = CopyResponseBuffer(buffer.Span);
            if (copied > 0)
            {
                return copied;
            }

            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _disposeCts.Token);
            byte[] responseBytes;
            try
            {
                responseBytes = await _responses.Reader.ReadAsync(linkedCts.Token).ConfigureAwait(false);
            }
            catch (ChannelClosedException)
            {
                return 0;
            }
            catch (OperationCanceledException) when (_disposeCts.IsCancellationRequested)
            {
                return 0;
            }

            lock (_readSync)
            {
                _responseBuffer = responseBytes;
                _responseOffset = 0;
            }

            return CopyResponseBuffer(buffer.Span);
        }

        public override long Seek(long offset, SeekOrigin origin)
            => throw new NotSupportedException();

        public override void SetLength(long value)
            => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
            => WriteAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            var messages = AppendRequests(buffer.Span);
            if (messages.Count == 0)
            {
                return;
            }

            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _disposeCts.Token);
            for (var index = 0; index < messages.Count; index++)
            {
                var response = await _processor.ProcessAsync(_destination, messages[index], linkedCts.Token).ConfigureAwait(false);
                if (response is null)
                {
                    continue;
                }

                await _responses.Writer.WriteAsync(
                    DnsOutboundProtocolCodec.FrameTcpMessage(response.Payload),
                    linkedCts.Token).ConfigureAwait(false);
            }
        }

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

            _disposeCts.Cancel();
            _responses.Writer.TryComplete();
            await _processor.DisposeAsync().ConfigureAwait(false);
            _disposeCts.Dispose();
        }

        private List<byte[]> AppendRequests(ReadOnlySpan<byte> buffer)
        {
            lock (_writeSync)
            {
                EnsureRequestCapacity(buffer.Length);
                buffer.CopyTo(_requestBuffer.AsSpan(_requestBufferLength));
                _requestBufferLength += buffer.Length;

                var messages = new List<byte[]>();
                var offset = 0;
                while (_requestBufferLength - offset >= 2)
                {
                    var length = BinaryPrimitives.ReadUInt16BigEndian(_requestBuffer.AsSpan(offset, 2));
                    if (_requestBufferLength - offset < length + 2)
                    {
                        break;
                    }

                    messages.Add(_requestBuffer.AsSpan(offset + 2, length).ToArray());
                    offset += 2 + length;
                }

                if (offset > 0)
                {
                    _requestBuffer.AsSpan(offset, _requestBufferLength - offset).CopyTo(_requestBuffer);
                    _requestBufferLength -= offset;
                }

                return messages;
            }
        }

        private int CopyResponseBuffer(Span<byte> destination)
        {
            lock (_readSync)
            {
                if (_responseBuffer is null)
                {
                    return 0;
                }

                var available = _responseBuffer.Length - _responseOffset;
                if (available <= 0)
                {
                    _responseBuffer = null;
                    _responseOffset = 0;
                    return 0;
                }

                var count = Math.Min(destination.Length, available);
                _responseBuffer.AsSpan(_responseOffset, count).CopyTo(destination);
                _responseOffset += count;

                if (_responseOffset >= _responseBuffer.Length)
                {
                    _responseBuffer = null;
                    _responseOffset = 0;
                }

                return count;
            }
        }

        private void EnsureRequestCapacity(int additionalLength)
        {
            if (_requestBuffer.Length - _requestBufferLength >= additionalLength)
            {
                return;
            }

            var required = _requestBufferLength + additionalLength;
            var nextLength = _requestBuffer.Length;
            while (nextLength < required)
            {
                nextLength *= 2;
            }

            Array.Resize(ref _requestBuffer, nextLength);
        }

        private void ThrowIfDisposed()
        {
            if (Volatile.Read(ref _disposed) != 0)
            {
                throw new ObjectDisposedException(nameof(DnsTcpOutboundStream));
            }
        }
    }
}
