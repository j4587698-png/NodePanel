using System.Buffers.Binary;

namespace NodePanel.Core.Protocol;

public sealed class VlessUdpPacketReader
{
    public async ValueTask<byte[]?> ReadAsync(Stream stream, CancellationToken cancellationToken)
    {
        var firstByte = await TrojanProtocolCodec.TryReadByteAsync(stream, cancellationToken).ConfigureAwait(false);
        if (firstByte is null)
        {
            return null;
        }

        var secondByte = await TrojanProtocolCodec.ReadByteAsync(stream, cancellationToken).ConfigureAwait(false);
        var payloadLength = BinaryPrimitives.ReadUInt16BigEndian([firstByte.Value, secondByte]);

        var payload = new byte[payloadLength];
        if (payload.Length > 0)
        {
            await TrojanProtocolCodec.ReadExactAsync(stream, payload, cancellationToken).ConfigureAwait(false);
        }

        return payload;
    }
}
