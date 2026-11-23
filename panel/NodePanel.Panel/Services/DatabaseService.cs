using System.Text;
using FreeSql;
using Microsoft.Extensions.Options;
using NodePanel.Panel.Configuration;

namespace NodePanel.Panel.Services;

public sealed class DatabaseService : IDisposable
{
    private IFreeSql? _fsql;
    public IFreeSql FSql => _fsql ?? throw new InvalidOperationException("Database is not initialized.");

    public bool IsConfigured { get; private set; }

    internal SemaphoreSlim TrafficWriteLock { get; } = new(1, 1);

    public DatabaseService(IOptionsMonitor<PanelOptions> options)
    {
        Initialize(options.CurrentValue);
        options.OnChange(Initialize);
    }

    private void Initialize(PanelOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.DbType) || string.IsNullOrWhiteSpace(options.DbConnectionString))
        {
            IsConfigured = false;
            return;
        }

        var oldFsql = _fsql;

        var dataType = options.DbType.Equals("mysql", StringComparison.OrdinalIgnoreCase)
            ? DataType.MySql
            : DataType.Sqlite;

        var connectionString = dataType == DataType.Sqlite
            ? ApplySqliteDefaults(options.DbConnectionString)
            : options.DbConnectionString;

        _fsql = new FreeSqlBuilder()
            .UseConnectionString(dataType, connectionString)
            .UseAutoSyncStructure(true)
            .Build();

        IsConfigured = true;

        oldFsql?.Dispose();
    }

    internal static string ApplySqliteDefaults(string connectionString)
    {
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            return connectionString;
        }

        // WAL is not supported for in-memory databases, and pooling would
        // otherwise keep one in-memory database alive across requests.
        var isInMemory = connectionString.Contains(":memory:", StringComparison.OrdinalIgnoreCase)
                         || connectionString.Contains("Mode=Memory", StringComparison.OrdinalIgnoreCase);
        if (isInMemory)
        {
            return connectionString;
        }

        var builder = new StringBuilder(connectionString.Trim().TrimEnd(';'));
        var compactConnectionString = connectionString.Replace(" ", string.Empty, StringComparison.Ordinal);

        void AddIfMissing(string key, string value)
        {
            var compactKey = key.Replace(" ", string.Empty, StringComparison.Ordinal);
            if (compactConnectionString.Contains(compactKey + "=", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            builder.Append(';').Append(key).Append('=').Append(value);
        }

        AddIfMissing("Pooling", "True");
        AddIfMissing("BusyTimeout", "5000");
        AddIfMissing("Default Timeout", "30");
        AddIfMissing("Journal Mode", "WAL");
        AddIfMissing("Synchronous", "Normal");
        AddIfMissing("Cache Size", "2000");

        return builder.ToString();
    }

    public void Dispose()
    {
        _fsql?.Dispose();
    }
}
