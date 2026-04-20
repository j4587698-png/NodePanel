using System.Net.Security;
using System.Net.WebSockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace NodePanel.Core.Runtime;

public sealed record RuntimeInternetSecurityState
{
    public static RuntimeInternetSecurityState None { get; } = new();

    public string SecurityType { get; init; } = RuntimeInternetSecurityTypes.None;

    public SslProtocols NegotiatedSslProtocol { get; init; } = SslProtocols.None;

    public string NegotiatedApplicationProtocol { get; init; } = string.Empty;

    public X509Certificate2? RemoteCertificate { get; init; }

    internal static RuntimeInternetSecurityState Create(
        string securityType,
        SslProtocols negotiatedSslProtocol,
        string? negotiatedApplicationProtocol = null,
        X509Certificate2? remoteCertificate = null)
        => new()
        {
            SecurityType = RuntimeInternetSecurityTypes.Normalize(securityType),
            NegotiatedSslProtocol = negotiatedSslProtocol,
            NegotiatedApplicationProtocol = string.IsNullOrWhiteSpace(negotiatedApplicationProtocol)
                ? string.Empty
                : negotiatedApplicationProtocol.Trim(),
            RemoteCertificate = remoteCertificate
        };

    internal static RuntimeInternetSecurityState Create(
        string securityType,
        SslStream sslStream,
        string? negotiatedApplicationProtocol = null)
    {
        ArgumentNullException.ThrowIfNull(sslStream);

        X509Certificate2? remoteCertificate = null;
        if (sslStream.IsAuthenticated &&
            sslStream.RemoteCertificate is not null)
        {
            remoteCertificate = sslStream.RemoteCertificate as X509Certificate2 ?? new X509Certificate2(sslStream.RemoteCertificate);
        }

        return Create(
            securityType,
            sslStream.SslProtocol,
            string.IsNullOrWhiteSpace(negotiatedApplicationProtocol)
                ? sslStream.IsAuthenticated
                    ? sslStream.NegotiatedApplicationProtocol.ToString()
                    : string.Empty
                : negotiatedApplicationProtocol,
            remoteCertificate);
    }
}

public abstract class RuntimeClientConnection : IAsyncDisposable
{
    private readonly RuntimeInternetConnectionContext _context;

    private protected RuntimeClientConnection(
        RuntimeInternetConnectionContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    public Stream Stream => _context.ApplicationStream;

    public SslStream? SslStream => _context.SslStream;

    public string SecurityType => SecurityState.SecurityType;

    public SslProtocols NegotiatedSslProtocol => SecurityState.NegotiatedSslProtocol;

    public string NegotiatedApplicationProtocol => SecurityState.NegotiatedApplicationProtocol;

    public bool UsesTlsLikeSemantics => RuntimeInternetSecurityTypes.UsesTlsLikeSemantics(SecurityType);

    public X509Certificate2? RemoteCertificate
        => SecurityState.RemoteCertificate is null
            ? null
            : new X509Certificate2(SecurityState.RemoteCertificate);

    internal RuntimeInternetSecurityState SecurityState => _context.SecurityState;

    public virtual async ValueTask DisposeAsync()
    {
        if (!ReferenceEquals(Stream, _context.TransportStream))
        {
            await Stream.DisposeAsync().ConfigureAwait(false);
        }

        _context.WebSocket?.Dispose();

        await _context.TransportStream.DisposeAsync().ConfigureAwait(false);
        SecurityState.RemoteCertificate?.Dispose();
    }

    protected void SetApplicationStream(Stream applicationStream)
    {
        ArgumentNullException.ThrowIfNull(applicationStream);
        _context.ReplaceApplicationStream(applicationStream);
    }
}

internal sealed class RuntimeConnectionStream : Stream
{
    private readonly RuntimeClientConnection _connection;

    public RuntimeConnectionStream(RuntimeClientConnection connection)
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
