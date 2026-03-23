using System.Text;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class PrefixedReadStreamTests
{
    [Fact]
    public async Task ReadAsync_returns_prefix_before_inner_stream()
    {
        using var innerStream = new RecordingDuplexStream(Encoding.ASCII.GetBytes("tail"));
        using var stream = new PrefixedReadStream(innerStream, Encoding.ASCII.GetBytes("head"));

        var firstBuffer = new byte[4];
        var secondBuffer = new byte[4];

        var firstRead = await stream.ReadAsync(firstBuffer);
        var secondRead = await stream.ReadAsync(secondBuffer);

        Assert.Equal(4, firstRead);
        Assert.Equal(4, secondRead);
        Assert.Equal("head", Encoding.ASCII.GetString(firstBuffer));
        Assert.Equal("tail", Encoding.ASCII.GetString(secondBuffer));
    }

    [Fact]
    public async Task WriteAsync_passes_through_to_inner_stream()
    {
        using var innerStream = new RecordingDuplexStream(Array.Empty<byte>());
        using var stream = new PrefixedReadStream(innerStream, Encoding.ASCII.GetBytes("head"));

        await stream.WriteAsync(Encoding.ASCII.GetBytes("payload"));
        await stream.FlushAsync();

        Assert.Equal("payload", innerStream.GetWrittenText());
    }

    private sealed class RecordingDuplexStream : Stream
    {
        private readonly MemoryStream _readStream;
        private readonly MemoryStream _writeStream = new();

        public RecordingDuplexStream(byte[] readBuffer)
        {
            _readStream = new MemoryStream(readBuffer, writable: false);
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

        public string GetWrittenText()
            => Encoding.ASCII.GetString(_writeStream.ToArray());

        public override void Flush()
            => _writeStream.Flush();

        public override Task FlushAsync(CancellationToken cancellationToken)
            => _writeStream.FlushAsync(cancellationToken);

        public override int Read(byte[] buffer, int offset, int count)
            => _readStream.Read(buffer, offset, count);

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => _readStream.ReadAsync(buffer, offset, count, cancellationToken);

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => _readStream.ReadAsync(buffer, cancellationToken);

        public override long Seek(long offset, SeekOrigin origin)
            => throw new NotSupportedException();

        public override void SetLength(long value)
            => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
            => _writeStream.Write(buffer, offset, count);

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => _writeStream.WriteAsync(buffer, offset, count, cancellationToken);

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => _writeStream.WriteAsync(buffer, cancellationToken);

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _readStream.Dispose();
                _writeStream.Dispose();
            }

            base.Dispose(disposing);
        }

        public override async ValueTask DisposeAsync()
        {
            await _readStream.DisposeAsync().ConfigureAwait(false);
            await _writeStream.DisposeAsync().ConfigureAwait(false);
            await base.DisposeAsync().ConfigureAwait(false);
        }
    }
}
