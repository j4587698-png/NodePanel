using System.Diagnostics;

namespace NodePanel.Core.Runtime;

public sealed class RuntimeFallbackRateLimiter
{
    private readonly RuntimeFallbackLimitOptions _options;
    private readonly SemaphoreSlim _gate = new(1, 1);

    private long _totalBytes;
    private double _tokens;
    private long _lastTick;

    private readonly double _capacity;
    private readonly double _fillRateBytesPerSecond;

    public RuntimeFallbackRateLimiter(RuntimeFallbackLimitOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        _options = options;
        _fillRateBytesPerSecond = Math.Max(0, options.BytesPerSecond);

        var burst = options.BurstBytesPerSecond > 0 ? options.BurstBytesPerSecond : options.BytesPerSecond;
        _capacity = Math.Max(0, burst);
        _tokens = _capacity;
        _lastTick = Stopwatch.GetTimestamp();
    }

    public async Task WaitAsync(int readBytes, CancellationToken cancellationToken)
    {
        if (readBytes <= 0)
        {
            return;
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // AfterBytes behaves like xray-core: if the window is positive at read start,
            // skip throttling for the entire read.
            var before = _totalBytes;
            _totalBytes += readBytes;
            if (_options.AfterBytes > 0 && before < _options.AfterBytes)
            {
                return;
            }

            if (_fillRateBytesPerSecond <= 0 || _capacity <= 0)
            {
                return;
            }

            var now = Stopwatch.GetTimestamp();
            var elapsedSeconds = (now - _lastTick) / (double)Stopwatch.Frequency;
            if (elapsedSeconds > 0)
            {
                _tokens = Math.Min(_capacity, _tokens + (_fillRateBytesPerSecond * elapsedSeconds));
            }

            _lastTick = now;

            if (_tokens >= readBytes)
            {
                _tokens -= readBytes;
                return;
            }

            var missing = readBytes - _tokens;
            _tokens = 0;

            var delaySeconds = missing / _fillRateBytesPerSecond;
            if (delaySeconds <= 0)
            {
                return;
            }

            await Task.Delay(TimeSpan.FromSeconds(delaySeconds), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }
}

