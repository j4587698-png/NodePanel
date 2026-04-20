using System.Text;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class RuntimeSplitHttpUploadQueueTests
{
    [Fact]
    public async Task ReadAsync_reorders_out_of_order_packet_payloads_by_sequence()
    {
        await using var queue = new RuntimeSplitHttpUploadQueue(maxPackets: 4);

        await queue.PushPayloadAsync(Encoding.ASCII.GetBytes("second"), sequence: 1, CancellationToken.None);

        var firstBuffer = new byte["first".Length];
        var pendingRead = queue.ReadAsync(firstBuffer, CancellationToken.None).AsTask();

        await Task.Delay(50);
        Assert.False(pendingRead.IsCompleted);

        await queue.PushPayloadAsync(Encoding.ASCII.GetBytes("first"), sequence: 0, CancellationToken.None);

        var firstRead = await pendingRead;
        Assert.Equal("first".Length, firstRead);
        Assert.Equal("first", Encoding.ASCII.GetString(firstBuffer));

        var secondBuffer = new byte["second".Length];
        var secondRead = await queue.ReadAsync(secondBuffer, CancellationToken.None);
        Assert.Equal("second".Length, secondRead);
        Assert.Equal("second", Encoding.ASCII.GetString(secondBuffer));

        queue.Complete();
        var eofBuffer = new byte[1];
        Assert.Equal(0, await queue.ReadAsync(eofBuffer, CancellationToken.None));
    }

    [Fact]
    public async Task ReadAsync_preserves_partial_packet_reads_without_advancing_sequence()
    {
        await using var queue = new RuntimeSplitHttpUploadQueue(maxPackets: 4);

        await queue.PushPayloadAsync(Encoding.ASCII.GetBytes("abcdef"), sequence: 0, CancellationToken.None);

        var firstBuffer = new byte[4];
        var firstRead = await queue.ReadAsync(firstBuffer, CancellationToken.None);
        Assert.Equal(4, firstRead);
        Assert.Equal("abcd", Encoding.ASCII.GetString(firstBuffer));

        var secondBuffer = new byte[2];
        var secondRead = await queue.ReadAsync(secondBuffer, CancellationToken.None);
        Assert.Equal(2, secondRead);
        Assert.Equal("ef", Encoding.ASCII.GetString(secondBuffer));

        queue.Complete();
        var eofBuffer = new byte[1];
        Assert.Equal(0, await queue.ReadAsync(eofBuffer, CancellationToken.None));
    }

    [Fact]
    public async Task PushStreamAsync_switches_to_stream_mode_and_rejects_later_packets()
    {
        await using var queue = new RuntimeSplitHttpUploadQueue(maxPackets: 4);

        await queue.PushStreamAsync(
            new MemoryStream(Encoding.ASCII.GetBytes("stream-body"), writable: false),
            CancellationToken.None);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => queue
            .PushPayloadAsync(Encoding.ASCII.GetBytes("late-packet"), sequence: 0, CancellationToken.None)
            .AsTask());
        Assert.Contains("stream-up", exception.Message, StringComparison.OrdinalIgnoreCase);

        var buffer = new byte["stream-body".Length];
        var read = await queue.ReadAsync(buffer, CancellationToken.None);
        Assert.Equal("stream-body".Length, read);
        Assert.Equal("stream-body", Encoding.ASCII.GetString(buffer));

        queue.Complete();
    }

    [Fact]
    public async Task ReadAsync_throws_when_misordered_reassembly_buffer_exceeds_limit()
    {
        await using var queue = new RuntimeSplitHttpUploadQueue(maxPackets: 1);

        await queue.PushPayloadAsync(Encoding.ASCII.GetBytes("two"), sequence: 2, CancellationToken.None);

        var buffer = new byte[3];
        var pendingRead = queue.ReadAsync(buffer, CancellationToken.None).AsTask();

        await Task.Delay(50);
        Assert.False(pendingRead.IsCompleted);

        await queue.PushPayloadAsync(Encoding.ASCII.GetBytes("three"), sequence: 3, CancellationToken.None);
        await queue.PushPayloadAsync(Encoding.ASCII.GetBytes("four"), sequence: 4, CancellationToken.None);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => pendingRead);
        Assert.Contains("too large", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Complete_discards_unread_packet_entries_like_xray_core_close()
    {
        await using var queue = new RuntimeSplitHttpUploadQueue(maxPackets: 4);

        await queue.PushPayloadAsync(Encoding.ASCII.GetBytes("payload"), sequence: 0, CancellationToken.None);
        queue.Complete();

        var buffer = new byte["payload".Length];
        Assert.Equal(0, await queue.ReadAsync(buffer, CancellationToken.None));
    }
}
