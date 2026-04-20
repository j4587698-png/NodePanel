using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class RuntimeKcpTests
{
    [Fact]
    public void RuntimeKcpPacketReader_returns_no_segments_for_empty_payload()
    {
        var segments = RuntimeKcpPacketReader.Read(Array.Empty<byte>());

        Assert.Empty(segments);
    }

    [Fact]
    public void RuntimeKcpDataSegment_roundtrips()
    {
        var segment = new RuntimeKcpDataSegment
        {
            Conversation = 1,
            Option = RuntimeKcpSegmentOption.Close,
            Timestamp = 3,
            Number = 4,
            SendingNext = 5
        };
        segment.SetPayload("abcd"u8.ToArray());

        var buffer = new byte[segment.ByteSize];
        segment.Serialize(buffer);

        var parsed = Assert.Single(RuntimeKcpPacketReader.Read(buffer));
        var roundTripped = Assert.IsType<RuntimeKcpDataSegment>(parsed);
        Assert.Equal(segment.Conversation, roundTripped.Conversation);
        Assert.Equal(segment.Option, roundTripped.Option);
        Assert.Equal(segment.Timestamp, roundTripped.Timestamp);
        Assert.Equal(segment.Number, roundTripped.Number);
        Assert.Equal(segment.SendingNext, roundTripped.SendingNext);
        Assert.Equal(segment.Payload.ToArray(), roundTripped.Payload.ToArray());
    }

    [Fact]
    public void RuntimeKcpAckSegment_roundtrips()
    {
        var segment = new RuntimeKcpAckSegment(limit: 128)
        {
            Conversation = 1,
            Option = RuntimeKcpSegmentOption.Close,
            ReceivingWindow = 2,
            ReceivingNext = 3,
            Timestamp = 10
        };
        segment.PutNumber(1);
        segment.PutNumber(3);
        segment.PutNumber(5);

        var buffer = new byte[segment.ByteSize];
        segment.Serialize(buffer);

        var parsed = Assert.Single(RuntimeKcpPacketReader.Read(buffer));
        var roundTripped = Assert.IsType<RuntimeKcpAckSegment>(parsed);
        Assert.Equal(segment.Conversation, roundTripped.Conversation);
        Assert.Equal(segment.Option, roundTripped.Option);
        Assert.Equal(segment.ReceivingWindow, roundTripped.ReceivingWindow);
        Assert.Equal(segment.ReceivingNext, roundTripped.ReceivingNext);
        Assert.Equal(segment.Timestamp, roundTripped.Timestamp);
        Assert.Equal(segment.Numbers, roundTripped.Numbers);
    }

    [Fact]
    public void RuntimeKcpCommandSegment_roundtrips()
    {
        var segment = new RuntimeKcpCommandSegment
        {
            Conversation = 1,
            SegmentCommand = RuntimeKcpCommand.Ping,
            Option = RuntimeKcpSegmentOption.Close,
            SendingNext = 11,
            ReceivingNext = 13,
            PeerRto = 15
        };

        var buffer = new byte[segment.ByteSize];
        segment.Serialize(buffer);

        var parsed = Assert.Single(RuntimeKcpPacketReader.Read(buffer));
        var roundTripped = Assert.IsType<RuntimeKcpCommandSegment>(parsed);
        Assert.Equal(segment.Conversation, roundTripped.Conversation);
        Assert.Equal(segment.Command, roundTripped.Command);
        Assert.Equal(segment.Option, roundTripped.Option);
        Assert.Equal(segment.SendingNext, roundTripped.SendingNext);
        Assert.Equal(segment.ReceivingNext, roundTripped.ReceivingNext);
        Assert.Equal(segment.PeerRto, roundTripped.PeerRto);
    }

    [Fact]
    public void RuntimeKcpPacketReader_detects_legacy_simple_auth_payload()
    {
        var segment = new RuntimeKcpDataSegment
        {
            Conversation = 7,
            Timestamp = 11,
            Number = 13,
            SendingNext = 17
        };
        segment.SetPayload("legacy-kcp"u8.ToArray());

        var rawPayload = new byte[segment.ByteSize];
        segment.Serialize(rawPayload);
        var legacyPayload = RuntimeKcpLegacySimpleAuth.Seal(rawPayload);

        var parsed = RuntimeKcpPacketReader.TryReadAny(
            legacyPayload,
            out var segments,
            out var wireFormat);

        Assert.True(parsed);
        Assert.Equal(RuntimeKcpWireFormat.LegacySimpleAuth, wireFormat);
        var roundTripped = Assert.IsType<RuntimeKcpDataSegment>(Assert.Single(segments));
        Assert.Equal(segment.Conversation, roundTripped.Conversation);
        Assert.Equal(segment.Timestamp, roundTripped.Timestamp);
        Assert.Equal(segment.Number, roundTripped.Number);
        Assert.Equal(segment.SendingNext, roundTripped.SendingNext);
        Assert.Equal(segment.Payload.ToArray(), roundTripped.Payload.ToArray());
    }

    [Fact]
    public void RuntimeKcpPacketReader_detects_modern_raw_payload()
    {
        var segment = new RuntimeKcpCommandSegment
        {
            Conversation = 5,
            SegmentCommand = RuntimeKcpCommand.Ping,
            SendingNext = 19,
            ReceivingNext = 23,
            PeerRto = 29
        };

        var rawPayload = new byte[segment.ByteSize];
        segment.Serialize(rawPayload);

        var parsed = RuntimeKcpPacketReader.TryReadAny(
            rawPayload,
            out var segments,
            out var wireFormat);

        Assert.True(parsed);
        Assert.Equal(RuntimeKcpWireFormat.ModernRaw, wireFormat);
        var roundTripped = Assert.IsType<RuntimeKcpCommandSegment>(Assert.Single(segments));
        Assert.Equal(segment.Conversation, roundTripped.Conversation);
        Assert.Equal(segment.Command, roundTripped.Command);
        Assert.Equal(segment.SendingNext, roundTripped.SendingNext);
        Assert.Equal(segment.ReceivingNext, roundTripped.ReceivingNext);
        Assert.Equal(segment.PeerRto, roundTripped.PeerRto);
    }

    [Fact]
    public async Task RuntimeKcpConnection_dual_sends_until_wire_format_is_observed()
    {
        var packets = new List<byte[]>();
        await using var connection = new RuntimeKcpConnection(
            conversation: 29,
            sendPacket: payload => packets.Add(payload.ToArray()));

        var outgoing = new RuntimeKcpCommandSegment
        {
            Conversation = 29,
            SegmentCommand = RuntimeKcpCommand.Ping,
            SendingNext = 3,
            ReceivingNext = 5,
            PeerRto = 7
        };

        Assert.True(connection.WriteSegment(outgoing));
        Assert.Equal(2, packets.Count);
        Assert.True(RuntimeKcpPacketReader.TryRead(
            packets[0],
            RuntimeKcpWireFormat.ModernRaw,
            out var modernSegments));
        Assert.True(RuntimeKcpPacketReader.TryRead(
            packets[1],
            RuntimeKcpWireFormat.LegacySimpleAuth,
            out var legacySegments));
        Assert.Single(modernSegments);
        Assert.Single(legacySegments);

        connection.InputSegments(
            [
                new RuntimeKcpCommandSegment
                {
                    Conversation = 29,
                    SegmentCommand = RuntimeKcpCommand.Ping,
                    SendingNext = 11,
                    ReceivingNext = 13,
                    PeerRto = 17
                }
            ],
            RuntimeKcpWireFormat.LegacySimpleAuth);

        Assert.Equal(RuntimeKcpWireFormat.LegacySimpleAuth, connection.WireFormat);

        packets.Clear();
        Assert.True(connection.WriteSegment(outgoing));
        var singlePacket = Assert.Single(packets);
        Assert.True(RuntimeKcpPacketReader.TryRead(
            singlePacket,
            RuntimeKcpWireFormat.LegacySimpleAuth,
            out var pinnedSegments));
        Assert.Single(pinnedSegments);
    }
}
