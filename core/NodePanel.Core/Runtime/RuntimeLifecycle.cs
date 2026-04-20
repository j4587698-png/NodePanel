namespace NodePanel.Core.Runtime;

public interface IRuntimeStartable
{
    void Start();
}

internal sealed class RuntimeComponentLifecycle
{
    private readonly HashSet<object> _trackedInstances = new(System.Collections.Generic.ReferenceEqualityComparer.Instance);
    private readonly List<IRuntimeStartable> _startables = [];
    private readonly List<IAsyncDisposable> _asyncDisposables = [];
    private readonly object _sync = new();

    public void Track(object instance)
    {
        ArgumentNullException.ThrowIfNull(instance);

        lock (_sync)
        {
            if (!_trackedInstances.Add(instance))
            {
                return;
            }

            if (instance is IRuntimeStartable startable)
            {
                _startables.Add(startable);
            }

            if (instance is IAsyncDisposable asyncDisposable)
            {
                _asyncDisposables.Add(asyncDisposable);
            }
        }
    }

    public IReadOnlyList<IRuntimeStartable> GetStartables()
    {
        lock (_sync)
        {
            return _startables.ToArray();
        }
    }

    public IReadOnlyList<IAsyncDisposable> GetAsyncDisposables()
    {
        lock (_sync)
        {
            return _asyncDisposables.ToArray();
        }
    }
}
