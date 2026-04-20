using System.Diagnostics;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class RuntimeFallbackRateLimiterTests
{
    [Fact]
    public async Task WaitAsync_delays_first_large_chunk_beyond_burst_window()
    {
        var limiter = new RuntimeFallbackRateLimiter(new RuntimeFallbackLimitOptions
        {
            BytesPerSecond = 3000,
            BurstBytesPerSecond = 3000
        });

        var stopwatch = Stopwatch.StartNew();
        await limiter.WaitAsync(6000, CancellationToken.None);
        stopwatch.Stop();

        Assert.InRange(stopwatch.Elapsed, TimeSpan.FromMilliseconds(700), TimeSpan.FromSeconds(4));
    }

    [Fact]
    public async Task WaitAsync_skips_entire_chunk_when_after_bytes_is_positive_at_read_start()
    {
        var limiter = new RuntimeFallbackRateLimiter(new RuntimeFallbackLimitOptions
        {
            AfterBytes = 1000,
            BytesPerSecond = 1000,
            BurstBytesPerSecond = 1000
        });

        var stopwatch = Stopwatch.StartNew();
        await limiter.WaitAsync(5000, CancellationToken.None);
        stopwatch.Stop();

        Assert.InRange(stopwatch.Elapsed, TimeSpan.Zero, TimeSpan.FromMilliseconds(500));
    }

    [Fact]
    public async Task WaitAsync_starts_throttling_on_following_read_after_after_bytes_window_is_crossed()
    {
        var limiter = new RuntimeFallbackRateLimiter(new RuntimeFallbackLimitOptions
        {
            AfterBytes = 1000,
            BytesPerSecond = 1000,
            BurstBytesPerSecond = 1000
        });

        await limiter.WaitAsync(5000, CancellationToken.None);

        var firstAfterWindowStopwatch = Stopwatch.StartNew();
        await limiter.WaitAsync(1000, CancellationToken.None);
        firstAfterWindowStopwatch.Stop();

        var secondAfterWindowStopwatch = Stopwatch.StartNew();
        await limiter.WaitAsync(1000, CancellationToken.None);
        secondAfterWindowStopwatch.Stop();

        Assert.InRange(firstAfterWindowStopwatch.Elapsed, TimeSpan.Zero, TimeSpan.FromMilliseconds(500));
        Assert.InRange(secondAfterWindowStopwatch.Elapsed, TimeSpan.FromMilliseconds(700), TimeSpan.FromSeconds(4));
    }
}
