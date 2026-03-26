using System.Diagnostics;
using System.Globalization;
using NodePanel.ControlPlane.Protocol;

namespace NodePanel.Service.Runtime;

public sealed class HostResourceTelemetryProvider
{
    private readonly object _sync = new();
    private LinuxCpuCounters? _lastCpuCounters;

    public NodeHostResourcePayload Capture()
    {
        using var process = Process.GetCurrentProcess();
        process.Refresh();

        var payload = new NodeHostResourcePayload
        {
            CpuLogicalCores = Environment.ProcessorCount,
            ProcessWorkingSetBytes = process.WorkingSet64
        };

        if (!OperatingSystem.IsLinux())
        {
            return payload;
        }

        try
        {
            if (TryReadLinuxCpuCounters(out var cpuCounters))
            {
                payload = payload with
                {
                    CpuUsagePercent = ComputeCpuUsagePercent(cpuCounters)
                };
            }

            if (TryReadLinuxMemoryInfo(out var totalMemoryBytes, out var availableMemoryBytes))
            {
                payload = payload with
                {
                    TotalMemoryBytes = totalMemoryBytes,
                    AvailableMemoryBytes = availableMemoryBytes
                };
            }

            if (TryReadLinuxLoadAverage(out var loadAverage1m, out var loadAverage5m, out var loadAverage15m))
            {
                payload = payload with
                {
                    LoadAverage1m = loadAverage1m,
                    LoadAverage5m = loadAverage5m,
                    LoadAverage15m = loadAverage15m
                };
            }

            if (TryReadLinuxUptime(out var uptimeSeconds))
            {
                payload = payload with
                {
                    UptimeSeconds = uptimeSeconds
                };
            }

            return payload;
        }
        catch (Exception ex)
        {
            return payload with
            {
                Error = ex.Message
            };
        }
    }

    private double? ComputeCpuUsagePercent(LinuxCpuCounters current)
    {
        lock (_sync)
        {
            var previous = _lastCpuCounters;
            _lastCpuCounters = current;

            if (previous is null)
            {
                return null;
            }

            var totalDiff = current.TotalTicks - previous.TotalTicks;
            var idleDiff = current.IdleTicks - previous.IdleTicks;
            if (totalDiff <= 0)
            {
                return null;
            }

            var busyRatio = 1d - Math.Clamp((double)idleDiff / totalDiff, 0d, 1d);
            return Math.Round(Math.Clamp(busyRatio * 100d, 0d, 100d), 2, MidpointRounding.AwayFromZero);
        }
    }

    private static bool TryReadLinuxCpuCounters(out LinuxCpuCounters counters)
    {
        counters = default!;

        const string path = "/proc/stat";
        if (!File.Exists(path))
        {
            return false;
        }

        using var reader = File.OpenText(path);
        var firstLine = reader.ReadLine();
        if (string.IsNullOrWhiteSpace(firstLine))
        {
            return false;
        }

        var parts = firstLine.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length < 5 || !string.Equals(parts[0], "cpu", StringComparison.Ordinal))
        {
            return false;
        }

        long totalTicks = 0;
        for (var index = 1; index < parts.Length; index++)
        {
            if (!long.TryParse(parts[index], NumberStyles.Integer, CultureInfo.InvariantCulture, out var value))
            {
                return false;
            }

            totalTicks += value;
        }

        if (!long.TryParse(parts[4], NumberStyles.Integer, CultureInfo.InvariantCulture, out var idleTicks))
        {
            return false;
        }

        long ioWaitTicks = 0;
        if (parts.Length > 5)
        {
            long.TryParse(parts[5], NumberStyles.Integer, CultureInfo.InvariantCulture, out ioWaitTicks);
        }

        counters = new LinuxCpuCounters(totalTicks, idleTicks + ioWaitTicks);
        return true;
    }

    private static bool TryReadLinuxMemoryInfo(out long? totalMemoryBytes, out long? availableMemoryBytes)
    {
        totalMemoryBytes = null;
        availableMemoryBytes = null;

        const string path = "/proc/meminfo";
        if (!File.Exists(path))
        {
            return false;
        }

        foreach (var line in File.ReadLines(path))
        {
            if (totalMemoryBytes is null && TryParseMemInfoLine(line, "MemTotal:", out var totalKilobytes))
            {
                totalMemoryBytes = totalKilobytes * 1024L;
                continue;
            }

            if (availableMemoryBytes is null && TryParseMemInfoLine(line, "MemAvailable:", out var availableKilobytes))
            {
                availableMemoryBytes = availableKilobytes * 1024L;
            }

            if (totalMemoryBytes.HasValue && availableMemoryBytes.HasValue)
            {
                return true;
            }
        }

        return totalMemoryBytes.HasValue || availableMemoryBytes.HasValue;
    }

    private static bool TryReadLinuxLoadAverage(out double? loadAverage1m, out double? loadAverage5m, out double? loadAverage15m)
    {
        loadAverage1m = null;
        loadAverage5m = null;
        loadAverage15m = null;

        const string path = "/proc/loadavg";
        if (!File.Exists(path))
        {
            return false;
        }

        var content = File.ReadAllText(path);
        var parts = content.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length < 3)
        {
            return false;
        }

        loadAverage1m = TryParseDouble(parts[0]);
        loadAverage5m = TryParseDouble(parts[1]);
        loadAverage15m = TryParseDouble(parts[2]);
        return loadAverage1m.HasValue || loadAverage5m.HasValue || loadAverage15m.HasValue;
    }

    private static bool TryReadLinuxUptime(out long? uptimeSeconds)
    {
        uptimeSeconds = null;

        const string path = "/proc/uptime";
        if (!File.Exists(path))
        {
            return false;
        }

        var content = File.ReadAllText(path);
        var firstToken = content.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .FirstOrDefault();
        var uptime = TryParseDouble(firstToken);
        if (!uptime.HasValue)
        {
            return false;
        }

        uptimeSeconds = Math.Max(0L, (long)Math.Floor(uptime.Value));
        return true;
    }

    private static bool TryParseMemInfoLine(string line, string fieldName, out long valueKilobytes)
    {
        valueKilobytes = 0;

        if (!line.StartsWith(fieldName, StringComparison.Ordinal))
        {
            return false;
        }

        var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length < 2)
        {
            return false;
        }

        return long.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out valueKilobytes);
    }

    private static double? TryParseDouble(string? value)
        => double.TryParse(value, NumberStyles.Float | NumberStyles.AllowThousands, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : null;

    private sealed record LinuxCpuCounters(long TotalTicks, long IdleTicks);
}
