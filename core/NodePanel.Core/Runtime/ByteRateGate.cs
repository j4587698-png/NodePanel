using System.Diagnostics;

namespace NodePanel.Core.Runtime;

public sealed class ByteRateGate
{
    private readonly object _sync = new();

    private long _bytesPerSecond;
    private long _nextAvailableTicks;

    public ByteRateGate(long bytesPerSecond)
    {
        _bytesPerSecond = Math.Max(0, bytesPerSecond);
    }

    public void UpdateRate(long bytesPerSecond)
    {
        lock (_sync)
        {
            _bytesPerSecond = Math.Max(0, bytesPerSecond);
            _nextAvailableTicks = Math.Min(_nextAvailableTicks, Stopwatch.GetTimestamp());
        }
    }

    public async ValueTask WaitAsync(int byteCount, CancellationToken cancellationToken)
    {
        if (byteCount <= 0)
        {
            return;
        }

        long delayTicks;
        lock (_sync)
        {
            if (_bytesPerSecond <= 0)
            {
                return;
            }

            var now = Stopwatch.GetTimestamp();
            var durationTicks = (long)Math.Ceiling((double)byteCount * Stopwatch.Frequency / _bytesPerSecond);
            var start = Math.Max(now, _nextAvailableTicks);
            delayTicks = Math.Max(0, start - now);
            _nextAvailableTicks = start + durationTicks;
        }

        if (delayTicks <= 0)
        {
            return;
        }

        await Task.Delay(TimeSpan.FromSeconds((double)delayTicks / Stopwatch.Frequency), cancellationToken).ConfigureAwait(false);
    }
}
