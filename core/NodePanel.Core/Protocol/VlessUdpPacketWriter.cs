namespace NodePanel.Core.Protocol;

public sealed class VlessUdpPacketWriter
{
    public async ValueTask WriteAsync(Stream stream, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        if (payload.Length > ushort.MaxValue)
        {
            throw new InvalidDataException($"VLESS UDP payload exceeds {ushort.MaxValue} bytes.");
        }

        var buffer = new byte[2 + payload.Length];
        TrojanProtocolCodec.WriteUInt16(buffer.AsSpan(0, 2), (ushort)payload.Length);
        payload.Span.CopyTo(buffer.AsSpan(2));
        await stream.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
    }
}
