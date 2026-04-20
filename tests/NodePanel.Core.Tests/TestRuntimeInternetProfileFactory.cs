using System.Net.Security;
using System.Security.Authentication;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

internal static class TestRuntimeInternetProfileFactory
{
    public static RuntimeInternetProfile CreateWithFakeTls(string negotiatedApplicationProtocol = "http/1.1")
        => RuntimeInternetProfile.FromDefault(
            securityFactories:
            [
                new RecordingFakeTlsSecurityFactory(negotiatedApplicationProtocol)
            ],
            replaceExistingSecurityFactories: true);

    public static RuntimeInternetProfile CreateWithFakeTls(RecordingFakeTlsSecurityFactory securityFactory)
        => RuntimeInternetProfile.FromDefault(
            securityFactories:
            [
                securityFactory
            ],
            replaceExistingSecurityFactories: true);

    public static RuntimeInternetProfile CreateWithRecordingSecurity(RecordingPassThroughSecurityFactory securityFactory)
        => RuntimeInternetProfile.FromDefault(
            securityFactories:
            [
                securityFactory
            ],
            replaceExistingSecurityFactories: true);

    internal sealed class RecordingFakeTlsSecurityFactory : IRuntimeInternetSecurityFactory
    {
        private readonly string _defaultNegotiatedApplicationProtocol;

        public RecordingFakeTlsSecurityFactory(string negotiatedApplicationProtocol = "http/1.1")
        {
            _defaultNegotiatedApplicationProtocol = string.IsNullOrWhiteSpace(negotiatedApplicationProtocol)
                ? "http/1.1"
                : negotiatedApplicationProtocol.Trim();
        }

        public string Name => RuntimeInternetSecurityTypes.Tls;

        public RuntimeInternetStack ObservedStack { get; private set; }

        public IRuntimeInternetOptions? ObservedOptions { get; private set; }

        public IReadOnlyList<string> ObservedApplicationProtocols { get; private set; } = Array.Empty<string>();

        public string NegotiatedApplicationProtocol { get; private set; } = string.Empty;

        public ValueTask ApplyAsync(
            RuntimeInternetConnectionContext context,
            RuntimeInternetStack stack,
            IRuntimeInternetOptions options,
            CancellationToken cancellationToken)
        {
            ObservedStack = stack;
            ObservedOptions = options;
            var sslOptions = RuntimeInternetProfile.CreateClientAuthenticationOptions(stack, options);
            ObservedApplicationProtocols = sslOptions.ApplicationProtocols is { Count: > 0 }
                ? sslOptions.ApplicationProtocols.Select(static protocol => protocol.ToString()).ToArray()
                : Array.Empty<string>();
            NegotiatedApplicationProtocol = ObservedApplicationProtocols.Count > 0
                ? ObservedApplicationProtocols[0]
                : _defaultNegotiatedApplicationProtocol;

            var sslStream = new FakeTlsStream(context.TransportStream);
            context.SetTransportStream(
                sslStream,
                sslStream,
                NegotiatedApplicationProtocol,
                RuntimeInternetSecurityState.Create(
                    RuntimeInternetSecurityTypes.Tls,
                    sslStream,
                    NegotiatedApplicationProtocol));
            return ValueTask.CompletedTask;
        }
    }

    internal sealed class RecordingPassThroughSecurityFactory : IRuntimeInternetSecurityFactory
    {
        private readonly string _defaultNegotiatedApplicationProtocol;

        public RecordingPassThroughSecurityFactory(
            string name,
            string negotiatedApplicationProtocol = "http/1.1")
        {
            Name = RuntimeInternetSecurityTypes.Normalize(name);
            _defaultNegotiatedApplicationProtocol = string.IsNullOrWhiteSpace(negotiatedApplicationProtocol)
                ? "http/1.1"
                : negotiatedApplicationProtocol.Trim();
        }

        public string Name { get; }

        public RuntimeInternetStack ObservedStack { get; private set; }

        public IRuntimeInternetOptions? ObservedOptions { get; private set; }

        public IReadOnlyList<string> ObservedApplicationProtocols { get; private set; } = Array.Empty<string>();

        public string NegotiatedApplicationProtocol { get; private set; } = string.Empty;

        public ValueTask ApplyAsync(
            RuntimeInternetConnectionContext context,
            RuntimeInternetStack stack,
            IRuntimeInternetOptions options,
            CancellationToken cancellationToken)
        {
            ObservedStack = stack;
            ObservedOptions = options;
            var sslOptions = RuntimeInternetProfile.CreateClientAuthenticationOptions(stack, options);
            ObservedApplicationProtocols = sslOptions.ApplicationProtocols is { Count: > 0 }
                ? sslOptions.ApplicationProtocols.Select(static protocol => protocol.ToString()).ToArray()
                : Array.Empty<string>();
            NegotiatedApplicationProtocol = ObservedApplicationProtocols.Count > 0
                ? ObservedApplicationProtocols[0]
                : _defaultNegotiatedApplicationProtocol;

            if (RuntimeInternetSecurityTypes.UsesTlsLikeSemantics(Name))
            {
                var tlsLikeStream = new FakeTlsStream(context.TransportStream);
                context.SetTransportStream(
                    tlsLikeStream,
                    tlsLikeStream,
                    NegotiatedApplicationProtocol,
                    RuntimeInternetSecurityState.Create(
                        Name,
                        tlsLikeStream,
                        NegotiatedApplicationProtocol));
                return ValueTask.CompletedTask;
            }

            context.SetTransportStream(context.TransportStream, negotiatedApplicationProtocol: NegotiatedApplicationProtocol);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class FakeTlsStream : SslStream
    {
        private readonly Stream _innerStream;

        public FakeTlsStream(Stream innerStream)
            : base(innerStream, leaveInnerStreamOpen: false)
        {
            _innerStream = innerStream;
        }

        public override SslProtocols SslProtocol => SslProtocols.Tls13;

        public override bool CanRead => _innerStream.CanRead;

        public override bool CanSeek => false;

        public override bool CanWrite => _innerStream.CanWrite;

        public override bool CanTimeout => _innerStream.CanTimeout;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int ReadTimeout
        {
            get => _innerStream.ReadTimeout;
            set => _innerStream.ReadTimeout = value;
        }

        public override int WriteTimeout
        {
            get => _innerStream.WriteTimeout;
            set => _innerStream.WriteTimeout = value;
        }

        public override void Flush()
            => _innerStream.Flush();

        public override Task FlushAsync(CancellationToken cancellationToken)
            => _innerStream.FlushAsync(cancellationToken);

        public override int Read(byte[] buffer, int offset, int count)
            => _innerStream.Read(buffer, offset, count);

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => _innerStream.ReadAsync(buffer, cancellationToken);

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => _innerStream.ReadAsync(buffer, offset, count, cancellationToken);

        public override void Write(byte[] buffer, int offset, int count)
            => _innerStream.Write(buffer, offset, count);

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => _innerStream.WriteAsync(buffer, cancellationToken);

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => _innerStream.WriteAsync(buffer, offset, count, cancellationToken);

        public override long Seek(long offset, SeekOrigin origin)
            => throw new NotSupportedException();

        public override void SetLength(long value)
            => throw new NotSupportedException();
    }
}
