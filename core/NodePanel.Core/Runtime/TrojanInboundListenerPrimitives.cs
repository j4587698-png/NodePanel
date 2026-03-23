using System.Net;
using System.Net.Sockets;

namespace NodePanel.Core.Runtime;

internal sealed class ListenerHandle : IDisposable
{
    private readonly TcpListener? _tcpListener;
    private readonly Socket? _unixListener;
    private readonly string? _unixPath;

    private ListenerHandle(TcpListener tcpListener)
    {
        _tcpListener = tcpListener;
    }

    private ListenerHandle(Socket unixListener, string unixPath)
    {
        _unixListener = unixListener;
        _unixPath = unixPath;
    }

    public static ListenerHandle Create(ListenerBinding binding)
    {
        if (!binding.IsUnix)
        {
            var listener = new TcpListener(IPAddress.Parse(binding.ListenAddress), binding.Port);
            listener.Start();
            return new ListenerHandle(listener);
        }

        var unixPath = binding.ListenAddress.Trim();
        if (string.IsNullOrWhiteSpace(unixPath))
        {
            throw new InvalidOperationException("UNIX listener path is empty.");
        }

        var directory = Path.GetDirectoryName(unixPath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        if (File.Exists(unixPath))
        {
            File.Delete(unixPath);
        }

        var listenerSocket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        try
        {
            listenerSocket.Bind(new UnixDomainSocketEndPoint(unixPath));
            listenerSocket.Listen(512);
            return new ListenerHandle(listenerSocket, unixPath);
        }
        catch
        {
            listenerSocket.Dispose();
            throw;
        }
    }

    public async Task<AcceptedConnection> AcceptAsync(CancellationToken cancellationToken)
    {
        if (_tcpListener is not null)
        {
            var tcpSocket = await _tcpListener.AcceptSocketAsync(cancellationToken).ConfigureAwait(false);
            return AcceptedConnection.FromTcpSocket(tcpSocket);
        }

        if (_unixListener is null)
        {
            throw new ObjectDisposedException(nameof(ListenerHandle));
        }

        var unixSocket = await _unixListener.AcceptAsync(cancellationToken).ConfigureAwait(false);
        return AcceptedConnection.FromUnixSocket(unixSocket, new IPEndPoint(IPAddress.Any, 0));
    }

    public void Stop()
    {
        try
        {
            _tcpListener?.Stop();
        }
        catch
        {
        }

        try
        {
            _unixListener?.Close();
        }
        catch
        {
        }

        if (!string.IsNullOrWhiteSpace(_unixPath) && File.Exists(_unixPath))
        {
            try
            {
                File.Delete(_unixPath);
            }
            catch
            {
            }
        }
    }

    public void Dispose() => Stop();
}

internal sealed class AcceptedConnection : IAsyncDisposable
{
    private readonly IDisposable? _owner;
    private readonly Socket? _socket;

    private AcceptedConnection(
        Stream stream,
        EndPoint? remoteEndPoint,
        EndPoint? localEndPoint,
        EndPoint? logRemoteEndPoint,
        Socket? socket,
        IDisposable? owner)
    {
        Stream = stream;
        RemoteEndPoint = remoteEndPoint;
        LocalEndPoint = localEndPoint;
        LogRemoteEndPoint = logRemoteEndPoint;
        _socket = socket;
        _owner = owner;
    }

    public Stream Stream { get; }

    public EndPoint? RemoteEndPoint { get; }

    public EndPoint? LocalEndPoint { get; }

    public EndPoint? LogRemoteEndPoint { get; }

    public Socket? Socket => _socket;

    public static AcceptedConnection FromTcpSocket(Socket socket)
        => new(
            new NetworkStream(socket, ownsSocket: true),
            socket.RemoteEndPoint,
            socket.LocalEndPoint,
            socket.RemoteEndPoint,
            socket,
            null);

    public static AcceptedConnection FromUnixSocket(Socket socket, EndPoint remotePlaceholder)
        => new(
            new NetworkStream(socket, ownsSocket: true),
            remotePlaceholder,
            socket.LocalEndPoint,
            socket.RemoteEndPoint,
            socket,
            null);

    public async ValueTask DisposeAsync()
    {
        await Stream.DisposeAsync().ConfigureAwait(false);
        _owner?.Dispose();
    }
}
