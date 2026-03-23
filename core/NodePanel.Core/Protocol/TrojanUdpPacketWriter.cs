namespace NodePanel.Core.Protocol;

public sealed class TrojanUdpPacketWriter
{
    public async ValueTask WriteAsync(Stream stream, TrojanUdpPacket packet, CancellationToken cancellationToken)
    {
        if (packet.DestinationPort is <= 0 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(packet), packet.DestinationPort, "Destination port must be between 1 and 65535.");
        }

        if (packet.Payload.Length > TrojanProtocolCodec.MaxUdpPayloadLength)
        {
            throw new InvalidDataException($"Trojan UDP payload exceeds {TrojanProtocolCodec.MaxUdpPayloadLength} bytes.");
        }

        var buffer = new byte[TrojanProtocolCodec.UdpFrameOverhead + packet.Payload.Length];
        var offset = TrojanProtocolCodec.WriteAddressPort(buffer, packet.DestinationHost, packet.DestinationPort);
        TrojanProtocolCodec.WriteUInt16(buffer.AsSpan(offset, 2), (ushort)packet.Payload.Length);
        offset += 2;
        TrojanProtocolCodec.WriteCrlf(buffer.AsSpan(offset, 2));
        offset += 2;
        packet.Payload.CopyTo(buffer.AsSpan(offset));
        offset += packet.Payload.Length;

        await stream.WriteAsync(buffer.AsMemory(0, offset), cancellationToken).ConfigureAwait(false);
    }
}
