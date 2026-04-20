using System.Diagnostics;

namespace NodePanel.Core.Tests;

internal static class GoInteropTestSupport
{
    public static bool TryGetGoExecutablePath(out string path)
    {
        var toolsDirectory = Path.Combine(FindWorkspaceRoot(), ".codex-build", "tools");
        if (Directory.Exists(toolsDirectory))
        {
            path = Directory
                .EnumerateFiles(toolsDirectory, "go.exe", SearchOption.AllDirectories)
                .Where(static candidate =>
                    candidate.EndsWith(
                        $"{Path.DirectorySeparatorChar}go{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}go.exe",
                        StringComparison.OrdinalIgnoreCase))
                .Where(IsCompleteGoExecutablePath)
                .OrderByDescending(static candidate => candidate.Contains("-full", StringComparison.OrdinalIgnoreCase))
                .ThenByDescending(static candidate => candidate, StringComparer.OrdinalIgnoreCase)
                .FirstOrDefault() ?? string.Empty;
            if (!string.IsNullOrWhiteSpace(path))
            {
                return true;
            }
        }

        var tool = OperatingSystem.IsWindows() ? "where.exe" : "which";
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = tool,
                Arguments = "go",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            }
        };

        if (!process.Start())
        {
            path = string.Empty;
            return false;
        }

        var output = process.StandardOutput.ReadLine();
        process.WaitForExit();
        path = string.IsNullOrWhiteSpace(output) ? string.Empty : output.Trim();
        return process.ExitCode == 0 &&
               !string.IsNullOrWhiteSpace(path) &&
               IsCompleteGoExecutablePath(path);
    }

    public static string FindWorkspaceRoot()
    {
        if (TryFindWorkspaceRoot(AppContext.BaseDirectory, out var root) ||
            TryFindWorkspaceRoot(Directory.GetCurrentDirectory(), out root))
        {
            return root;
        }

        throw new DirectoryNotFoundException("Could not locate the Xray-core workspace root.");
    }

    public static ProcessStartInfo CreateGoHelperStartInfo(
        string goExecutable,
        string workspaceRoot,
        string helperPath,
        params string[] arguments)
    {
        var codexBuildDirectory = Path.Combine(workspaceRoot, ".codex-build");
        var goCacheDirectory = Path.Combine(codexBuildDirectory, "go-cache");
        var goModuleCacheDirectory = Path.Combine(codexBuildDirectory, "go-mod");
        var goRootDirectory = GetGoRootDirectory(goExecutable);
        Directory.CreateDirectory(goCacheDirectory);
        Directory.CreateDirectory(goModuleCacheDirectory);

        var startInfo = new ProcessStartInfo
        {
            FileName = goExecutable,
            WorkingDirectory = Path.Combine(workspaceRoot, "xray-core"),
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        startInfo.ArgumentList.Add("run");
        startInfo.ArgumentList.Add(helperPath);
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        startInfo.Environment["GOROOT"] = goRootDirectory;
        startInfo.Environment["GOCACHE"] = goCacheDirectory;
        startInfo.Environment["GOMODCACHE"] = goModuleCacheDirectory;
        return startInfo;
    }

    public static async Task<(string Stdout, string Stderr)> WaitForProcessExitAsync(
        Process process,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(process);

        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();

        await process.WaitForExitAsync(cancellationToken);
        return (await stdoutTask.ConfigureAwait(false), await stderrTask.ConfigureAwait(false));
    }

    public static void TryTerminateProcess(Process process)
    {
        ArgumentNullException.ThrowIfNull(process);

        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch
        {
        }
    }

    private static bool IsCompleteGoExecutablePath(string candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate) || !File.Exists(candidate))
        {
            return false;
        }

        var goRootDirectory = GetGoRootDirectory(candidate);
        return File.Exists(Path.Combine(goRootDirectory, "src", "fmt", "print.go")) &&
               File.Exists(Path.Combine(goRootDirectory, "src", "errors", "errors.go"));
    }

    private static string GetGoRootDirectory(string goExecutable)
    {
        var binDirectory = Path.GetDirectoryName(goExecutable);
        return binDirectory is null
            ? string.Empty
            : Path.GetFullPath(Path.Combine(binDirectory, ".."));
    }

    private static bool TryFindWorkspaceRoot(string startPath, out string root)
    {
        for (var directory = new DirectoryInfo(startPath); directory is not null; directory = directory.Parent)
        {
            if (Directory.Exists(Path.Combine(directory.FullName, "Xray-dotnet")) &&
                Directory.Exists(Path.Combine(directory.FullName, "xray-core")))
            {
                root = directory.FullName;
                return true;
            }
        }

        root = string.Empty;
        return false;
    }
}
