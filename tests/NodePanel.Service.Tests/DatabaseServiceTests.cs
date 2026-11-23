using NodePanel.Panel.Services;

namespace NodePanel.Service.Tests;

public sealed class DatabaseServiceTests
{
    [Fact]
    public void ApplySqliteDefaults_enables_wal_and_busy_timeout_for_file_databases()
    {
        var connectionString = DatabaseService.ApplySqliteDefaults("Data Source=panel.db");

        Assert.Contains("Journal Mode=WAL", connectionString, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Synchronous=Normal", connectionString, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("BusyTimeout=5000", connectionString, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Cache Size=2000", connectionString, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Default Timeout=30", connectionString, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Pooling=True", connectionString, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ApplySqliteDefaults_keeps_explicit_provider_settings()
    {
        var original = "Data Source=panel.db;journal mode=delete;busy timeout=100";
        var connectionString = DatabaseService.ApplySqliteDefaults(original);

        Assert.Contains("journal mode=delete", connectionString, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Journal Mode=WAL", connectionString, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("BusyTimeout=5000", connectionString, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Pooling=True", connectionString, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ApplySqliteDefaults_is_idempotent()
    {
        var once = DatabaseService.ApplySqliteDefaults("Data Source=panel.db");
        var twice = DatabaseService.ApplySqliteDefaults(once);

        Assert.Equal(once, twice, StringComparer.Ordinal);
    }

    [Theory]
    [InlineData("Data Source=:memory:")]
    [InlineData("Data Source=file:memdb1?Mode=Memory&Cache=Shared")]
    public void ApplySqliteDefaults_leaves_in_memory_databases_untouched(string connectionString)
    {
        Assert.Equal(connectionString, DatabaseService.ApplySqliteDefaults(connectionString), StringComparer.Ordinal);
    }
}
