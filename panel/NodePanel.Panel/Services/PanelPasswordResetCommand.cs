using System.Data.SQLite;
using System.Text;
using FreeSql;
using Microsoft.AspNetCore.Identity;
using NodePanel.Panel.Configuration;
using NodePanel.Panel.Models;

namespace NodePanel.Panel.Services;

internal static class PanelPasswordResetCommand
{
    public static async Task<int> RunFromConsoleAsync(IConfiguration configuration)
    {
        if (Console.IsInputRedirected || Console.IsOutputRedirected)
        {
            Console.Error.WriteLine("重置密码需要交互式终端；Docker 请使用 docker exec -it。");
            return 1;
        }

        return await RunConfiguredAsync(configuration, Console.In, Console.Out, Console.Error, ReadPassword);
    }

    internal static async Task<int> RunConfiguredAsync(
        IConfiguration configuration,
        TextReader input,
        TextWriter output,
        TextWriter error,
        Func<string> readPassword)
    {
        var options = configuration.GetSection(PanelOptions.SectionName).Get<PanelOptions>();
        if (options is null || string.IsNullOrWhiteSpace(options.DbType) ||
            string.IsNullOrWhiteSpace(options.DbConnectionString))
        {
            await error.WriteLineAsync("面板数据库尚未配置。");
            return 1;
        }

        DataType dataType;
        string connectionString;
        if (options.DbType.Equals("sqlite", StringComparison.OrdinalIgnoreCase))
        {
            dataType = DataType.Sqlite;
            var sqlite = new SQLiteConnectionStringBuilder(options.DbConnectionString)
            {
                FailIfMissing = true
            };
            connectionString = sqlite.ConnectionString;
        }
        else if (options.DbType.Equals("mysql", StringComparison.OrdinalIgnoreCase))
        {
            dataType = DataType.MySql;
            connectionString = options.DbConnectionString;
        }
        else
        {
            await error.WriteLineAsync($"不支持的数据库类型：{options.DbType}");
            return 1;
        }

        using var database = new FreeSqlBuilder()
            .UseConnectionString(dataType, connectionString)
            .UseAutoSyncStructure(false)
            .Build();

        return await RunAsync(database, input, output, error, readPassword);
    }

    internal static async Task<int> RunAsync(
        IFreeSql database,
        TextReader input,
        TextWriter output,
        TextWriter error,
        Func<string> readPassword)
    {
        await output.WriteAsync("用户邮箱：");
        var email = (await input.ReadLineAsync())?.Trim();
        if (string.IsNullOrWhiteSpace(email))
        {
            await error.WriteLineAsync("邮箱不能为空。");
            return 1;
        }

        var users = await database.Select<UserEntity>()
            .Where(user => user.Email == email)
            .Limit(2)
            .ToListAsync();
        if (users.Count != 1)
        {
            await error.WriteLineAsync(users.Count == 0 ? "未找到该邮箱的用户。" : "该邮箱对应多个用户，无法安全重置。");
            return 1;
        }

        await output.WriteAsync("新密码：");
        var password = readPassword();
        await output.WriteLineAsync();
        await output.WriteAsync("再次输入新密码：");
        var confirmation = readPassword();
        await output.WriteLineAsync();
        if (string.IsNullOrWhiteSpace(password) || password != confirmation)
        {
            await error.WriteLineAsync("密码不能为空，且两次输入必须一致。");
            return 1;
        }

        var user = users[0];
        var hash = new PasswordHasher<UserEntity>().HashPassword(user, password);
        var changed = await database.Update<UserEntity>()
            .Set(item => item.PasswordHash, hash)
            .Where(item => item.UserId == user.UserId)
            .ExecuteAffrowsAsync();
        if (changed != 1)
        {
            await error.WriteLineAsync("密码未更新，请确认用户仍然存在。");
            return 1;
        }

        await output.WriteLineAsync("密码已重置。");
        return 0;
    }

    private static string ReadPassword()
    {
        var password = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                return password.ToString();
            }

            if (key.Key == ConsoleKey.Backspace)
            {
                if (password.Length > 0)
                {
                    password.Length--;
                }
            }
            else if (!char.IsControl(key.KeyChar))
            {
                password.Append(key.KeyChar);
            }
        }
    }
}
