using FreeSql;
using Microsoft.Extensions.Options;
using NodePanel.Panel.Configuration;

namespace NodePanel.Panel.Services;

public sealed class DatabaseService : IDisposable
{
    private IFreeSql? _fsql;
    public IFreeSql FSql => _fsql ?? throw new InvalidOperationException("Database is not initialized.");

    public bool IsConfigured { get; private set; }

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

        _fsql = new FreeSqlBuilder()
            .UseConnectionString(dataType, options.DbConnectionString)
            .UseAutoSyncStructure(true)
            .Build();

        IsConfigured = true;

        oldFsql?.Dispose();
    }

    public void Dispose()
    {
        _fsql?.Dispose();
    }
}
