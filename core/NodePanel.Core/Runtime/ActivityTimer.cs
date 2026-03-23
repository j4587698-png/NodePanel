using System.Diagnostics;
using System.Threading;

namespace NodePanel.Core.Runtime;

internal sealed class ActivityTimer : IAsyncDisposable
{
    private readonly CancellationTokenSource _disposeCts = new();
    private readonly Task _loopTask;
    private readonly Action _onTimeout;
    private readonly SemaphoreSlim _signal = new(0, 1);
    private readonly object _sync = new();

    private long _lastActivityTimestamp;
    private TimeSpan _timeout;
    private int _disposed;
    private int _signaled;
    private int _timedOut;

    private ActivityTimer(Action onTimeout, TimeSpan timeout)
    {
        _onTimeout = onTimeout;
        _timeout = timeout;
        _lastActivityTimestamp = Stopwatch.GetTimestamp();
        _loopTask = RunAsync();
        Signal();
    }

    public static ActivityTimer CancelAfterInactivity(Action onTimeout, TimeSpan timeout)
    {
        ArgumentNullException.ThrowIfNull(onTimeout);
        return new ActivityTimer(onTimeout, timeout);
    }

    public void Update()
    {
        if (Volatile.Read(ref _disposed) != 0 || Volatile.Read(ref _timedOut) != 0)
        {
            return;
        }

        Volatile.Write(ref _lastActivityTimestamp, Stopwatch.GetTimestamp());
        Signal();
    }

    public void SetTimeout(TimeSpan timeout)
    {
        if (Volatile.Read(ref _disposed) != 0 || Volatile.Read(ref _timedOut) != 0)
        {
            return;
        }

        if (timeout <= TimeSpan.Zero)
        {
            TriggerTimeout();
            return;
        }

        lock (_sync)
        {
            if (_disposed != 0 || _timedOut != 0)
            {
                return;
            }

            _timeout = timeout;
            _lastActivityTimestamp = Stopwatch.GetTimestamp();
        }

        Signal();
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _disposeCts.Cancel();

        try
        {
            await _loopTask.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (_disposeCts.IsCancellationRequested)
        {
        }
        finally
        {
            _signal.Dispose();
            _disposeCts.Dispose();
        }
    }

    private async Task RunAsync()
    {
        try
        {
            while (!_disposeCts.IsCancellationRequested)
            {
                var timeout = GetTimeout();
                if (timeout <= TimeSpan.Zero)
                {
                    TriggerTimeout();
                    return;
                }

                var lastActivityTimestamp = Volatile.Read(ref _lastActivityTimestamp);
                var elapsed = Stopwatch.GetElapsedTime(lastActivityTimestamp);
                var remaining = timeout - elapsed;
                if (remaining <= TimeSpan.Zero)
                {
                    if (Stopwatch.GetElapsedTime(Volatile.Read(ref _lastActivityTimestamp)) >= GetTimeout())
                    {
                        TriggerTimeout();
                        return;
                    }

                    continue;
                }

                var delayTask = Task.Delay(remaining, _disposeCts.Token);
                var signalTask = _signal.WaitAsync(_disposeCts.Token);
                var completedTask = await Task.WhenAny(delayTask, signalTask).ConfigureAwait(false);
                if (ReferenceEquals(completedTask, signalTask))
                {
                    Interlocked.Exchange(ref _signaled, 0);
                    await signalTask.ConfigureAwait(false);
                    continue;
                }

                await delayTask.ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (_disposeCts.IsCancellationRequested)
        {
        }
    }

    private TimeSpan GetTimeout()
    {
        lock (_sync)
        {
            return _timeout;
        }
    }

    private void TriggerTimeout()
    {
        if (Interlocked.Exchange(ref _timedOut, 1) != 0)
        {
            return;
        }

        _disposeCts.Cancel();
        _onTimeout();
    }

    private void Signal()
    {
        if (Interlocked.Exchange(ref _signaled, 1) != 0)
        {
            return;
        }

        try
        {
            _signal.Release();
        }
        catch (ObjectDisposedException)
        {
        }
        catch (SemaphoreFullException)
        {
        }
    }
}
