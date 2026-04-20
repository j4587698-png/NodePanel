using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;

namespace NodePanel.Core.Runtime;

internal sealed class SocksOutboundUdpTransport : IOutboundUdpTransport
{
    private readonly SemaphoreSlim _associationLock = new(1, 1);
    private readonly CancellationTokenSource _disposeCts = new();
    private readonly Channel<DispatchDatagram> _responseChannel = Channel.CreateUnbounded<DispatchDatagram>(
        new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false
        });
    private readonly DispatchContext _context;
    private readonly SocksOutboundHandler _handler;
    private readonly SocksResolvedSettings _settings;

    private Stream? _controlStream;
    private IOutboundUdpTransport? _innerTransport;
    private string _relayHost = string.Empty;
    private int _relayPort;
    private Task? _responseLoop;
    private Socket? _udpSocket;
    private int _disposed;

    public SocksOutboundUdpTransport(
        SocksOutboundHandler handler,
        DispatchContext context,
        SocksResolvedSettings settings)
    {
        _handler = handler;
        _context = context;
        _settings = settings;
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
            throw new NotSupportedException($"SOCKS outbound does not support UDP send for network '{destination.Network}'.");
        }

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _disposeCts.Token);
        var resolvedDestination = await OutboundTargetStrategyResolver.ResolveAsync(
            _context,
            destination,
            _settings.Common.TargetStrategy,
            _handler.DnsResolver,
            linkedCts.Token).ConfigureAwait(false);

        await EnsureAssociationAsync(resolvedDestination, linkedCts.Token).ConfigureAwait(false);

        var datagram = Socks5UdpPacketCodec.Encode(
            resolvedDestination.Host,
            resolvedDestination.Port,
            payload.Span);

        if (_udpSocket is not null)
        {
            await _udpSocket.SendAsync(datagram, SocketFlags.None, linkedCts.Token).ConfigureAwait(false);
            return;
        }

        if (_innerTransport is null)
        {
            throw new InvalidOperationException("SOCKS UDP association is not initialized.");
        }

        await _innerTransport.SendAsync(
            new DispatchDestination
            {
                Host = _relayHost,
                Port = _relayPort,
                Network = DispatchNetwork.Udp
            },
            datagram,
            linkedCts.Token).ConfigureAwait(false);
    }

    public async ValueTask<DispatchDatagram?> ReceiveAsync(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _disposeCts.Token);
        try
        {
            return await _responseChannel.Reader.ReadAsync(linkedCts.Token).ConfigureAwait(false);
        }
        catch (ChannelClosedException)
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

        if (_controlStream is not null)
        {
            await _controlStream.DisposeAsync().ConfigureAwait(false);
        }

        if (_innerTransport is not null)
        {
            await _innerTransport.DisposeAsync().ConfigureAwait(false);
        }

        if (_udpSocket is not null)
        {
            _udpSocket.Dispose();
        }

        if (_responseLoop is not null)
        {
            try
            {
                await _responseLoop.ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (_disposeCts.IsCancellationRequested)
            {
            }
        }

        _responseChannel.Writer.TryComplete();
        _associationLock.Dispose();
        _disposeCts.Dispose();
    }

    private async Task EnsureAssociationAsync(
        DispatchDestination initialDestination,
        CancellationToken cancellationToken)
    {
        if (_controlStream is not null)
        {
            return;
        }

        await _associationLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_controlStream is not null)
            {
                return;
            }

            using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _disposeCts.Token);
            handshakeCts.CancelAfter(TimeSpan.FromSeconds(SocksOutboundHandler.ResolveTimeout(
                _settings.Outbound.HandshakeTimeoutSeconds,
                _context.ConnectTimeoutSeconds)));

            var controlStream = await _handler.OpenServerTcpStreamAsync(_context, _settings, handshakeCts.Token).ConfigureAwait(false);
            try
            {
                await SocksOutboundHandler.PerformGreetingAsync(
                    controlStream,
                    _settings.Outbound,
                    handshakeCts.Token).ConfigureAwait(false);
                await SocksOutboundHandler.WriteRequestAsync(
                    controlStream,
                    Socks5ProtocolConstants.CommandUdpAssociate,
                    initialDestination,
                    handshakeCts.Token).ConfigureAwait(false);

                var reply = await SocksOutboundHandler.ReadReplyAsync(controlStream, handshakeCts.Token).ConfigureAwait(false);
                var relay = ResolveRelayDestination(reply, controlStream);

                if (string.IsNullOrWhiteSpace(_settings.Common.ProxyOutboundTag))
                {
                    await InitializeDirectSocketAsync(relay, handshakeCts.Token).ConfigureAwait(false);
                }
                else
                {
                    await InitializeChainedTransportAsync(relay, handshakeCts.Token).ConfigureAwait(false);
                }

                _controlStream = controlStream;
                _relayHost = relay.Host;
                _relayPort = relay.Port;
            }
            catch
            {
                await controlStream.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
        finally
        {
            _associationLock.Release();
        }
    }

    private async Task InitializeDirectSocketAsync(
        SocksAddress relay,
        CancellationToken cancellationToken)
    {
        var endPoints = await OutboundSocketDialer.ResolveTcpEndPointsAsync(
            _context,
            relay.Host,
            relay.Port,
            AddressFamily.Unspecified,
            _handler.DnsResolver,
            cancellationToken).ConfigureAwait(false);
        var endPoint = endPoints[0];
        var socket = OutboundSocketDialer.CreateUdpSocket(
            _context,
            _settings.Common.Via,
            _settings.Common.ViaCidr,
            endPoint.AddressFamily);

        try
        {
            await socket.ConnectAsync(endPoint, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            socket.Dispose();
            throw;
        }

        _udpSocket = socket;
        _responseLoop = Task.Run(() => RunSocketReceiveLoopAsync(socket), CancellationToken.None);
    }

    private async Task InitializeChainedTransportAsync(
        SocksAddress relay,
        CancellationToken cancellationToken)
    {
        var transport = await _handler.ResolveDispatcher().DispatchUdpAsync(
            SocksOutboundHandler.CreateProxyContext(
                _context,
                relay.Host,
                relay.Port,
                _settings.Common.ProxyOutboundTag),
            cancellationToken).ConfigureAwait(false);

        _innerTransport = transport;
        _responseLoop = Task.Run(() => RunChainedReceiveLoopAsync(transport), CancellationToken.None);
    }

    private async Task RunSocketReceiveLoopAsync(Socket socket)
    {
        var buffer = new byte[65535];
        try
        {
            while (!_disposeCts.IsCancellationRequested)
            {
                var received = await socket.ReceiveAsync(buffer, SocketFlags.None, _disposeCts.Token).ConfigureAwait(false);
                if (received == 0)
                {
                    break;
                }

                PublishDecodedDatagram(buffer.AsSpan(0, received));
            }
        }
        catch (OperationCanceledException) when (_disposeCts.IsCancellationRequested)
        {
        }
        catch (ObjectDisposedException)
        {
        }
        catch (SocketException) when (_disposeCts.IsCancellationRequested)
        {
        }
        finally
        {
            _responseChannel.Writer.TryComplete();
        }
    }

    private async Task RunChainedReceiveLoopAsync(IOutboundUdpTransport transport)
    {
        try
        {
            while (!_disposeCts.IsCancellationRequested)
            {
                var datagram = await transport.ReceiveAsync(_disposeCts.Token).ConfigureAwait(false);
                if (datagram is null)
                {
                    break;
                }

                PublishDecodedDatagram(datagram.Payload);
            }
        }
        catch (OperationCanceledException) when (_disposeCts.IsCancellationRequested)
        {
        }
        finally
        {
            _responseChannel.Writer.TryComplete();
        }
    }

    private void PublishDecodedDatagram(ReadOnlySpan<byte> payload)
    {
        Socks5UdpPacket packet;
        try
        {
            packet = Socks5UdpPacketCodec.Decode(payload);
        }
        catch (InvalidDataException)
        {
            return;
        }

        if (packet.Payload.Length == 0)
        {
            return;
        }

        _responseChannel.Writer.TryWrite(new DispatchDatagram
        {
            SourceHost = packet.Host,
            SourcePort = packet.Port,
            Payload = packet.Payload
        });
    }

    private SocksAddress ResolveRelayDestination(SocksReply reply, Stream controlStream)
    {
        if (!SocksOutboundHandler.IsAnyAddress(reply.Host))
        {
            return new SocksAddress
            {
                Host = reply.Host,
                Port = reply.Port
            };
        }

        if (SocksOutboundHandler.TryGetRemoteEndPoint(controlStream, out var remoteEndPoint))
        {
            return new SocksAddress
            {
                Host = remoteEndPoint.Address.ToString(),
                Port = reply.Port
            };
        }

        return new SocksAddress
        {
            Host = _settings.Outbound.ServerHost,
            Port = reply.Port
        };
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(SocksOutboundUdpTransport));
        }
    }
}
