namespace NodePanel.Core.Protocol;

public sealed class TrojanUdpPacketReader
{
    public async ValueTask<TrojanUdpPacket?> ReadAsync(Stream stream, CancellationToken cancellationToken)
    {
        var destinationHost = await TrojanProtocolCodec.TryReadAddressAsync(stream, cancellationToken).ConfigureAwait(false);
        if (destinationHost is null)
        {
            return null;
        }

        var destinationPort = await TrojanProtocolCodec.ReadUInt16Async(stream, cancellationToken).ConfigureAwait(false);
        var payloadLength = await TrojanProtocolCodec.ReadUInt16Async(stream, cancellationToken).ConfigureAwait(false);
        if (payloadLength > TrojanProtocolCodec.MaxUdpPayloadLength)
        {
            throw new InvalidDataException($"Trojan UDP payload exceeds {TrojanProtocolCodec.MaxUdpPayloadLength} bytes.");
        }

        await TrojanProtocolCodec.ReadCrlfAsync(stream, cancellationToken).ConfigureAwait(false);

        var payload = new byte[payloadLength];
        if (payload.Length > 0)
        {
            await TrojanProtocolCodec.ReadExactAsync(stream, payload, cancellationToken).ConfigureAwait(false);
        }

        return new TrojanUdpPacket
        {
            DestinationHost = destinationHost,
            DestinationPort = destinationPort,
            Payload = payload
        };
    }
}
