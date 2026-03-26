namespace NodePanel.Panel.Models;

public sealed record PlanCycleOption(
    string Cycle,
    string DisplayName,
    decimal Price,
    string DurationText,
    string ResetText);

public static class PlanPresentation
{
    public const string TrafficUnitMb = "MB";
    public const string TrafficUnitGb = "GB";
    public const string TrafficUnitTb = "TB";
    public const string RateUnitKbPerSecond = "KB/s";
    public const string RateUnitMbPerSecond = "MB/s";
    public const string RateUnitGbPerSecond = "GB/s";

    private const long Kilobyte = 1024L;
    private const long Megabyte = 1024L * 1024L;
    private const long Gigabyte = Megabyte * 1024L;
    private const long Terabyte = Gigabyte * 1024L;

    public static bool HasAvailableCycles(PanelPlanRecord plan)
        => GetAvailableCycles(plan).Count > 0;

    public static IReadOnlyList<PlanCycleOption> GetAvailableCycles(PanelPlanRecord plan)
    {
        ArgumentNullException.ThrowIfNull(plan);

        var options = new List<PlanCycleOption>(6);
        AppendCycleOption(options, "month", plan.MonthPrice);
        AppendCycleOption(options, "quarter", plan.QuarterPrice);
        AppendCycleOption(options, "half_year", plan.HalfYearPrice);
        AppendCycleOption(options, "year", plan.YearPrice);
        AppendCycleOption(options, "one_time", plan.OneTimePrice);
        AppendCycleOption(options, "reset_price", plan.ResetPrice);
        return options;
    }

    public static decimal GetPreviewPrice(PanelPlanRecord plan)
    {
        ArgumentNullException.ThrowIfNull(plan);

        var cycles = GetAvailableCycles(plan);
        return cycles.Count == 0 ? 0m : cycles.Min(static item => item.Price);
    }

    public static decimal? GetCyclePrice(PanelPlanRecord plan, string? cycle)
    {
        ArgumentNullException.ThrowIfNull(plan);

        return NormalizeCycle(cycle) switch
        {
            "month" => NormalizePrice(plan.MonthPrice),
            "quarter" => NormalizePrice(plan.QuarterPrice),
            "half_year" => NormalizePrice(plan.HalfYearPrice),
            "year" => NormalizePrice(plan.YearPrice),
            "one_time" => NormalizePrice(plan.OneTimePrice),
            "reset_price" => NormalizePrice(plan.ResetPrice),
            _ => null
        };
    }

    public static string GetCycleDisplayName(string? cycle)
        => NormalizeCycle(cycle) switch
        {
            "month" => "月付",
            "quarter" => "季付",
            "half_year" => "半年付",
            "year" => "年付",
            "one_time" => "一次性",
            "reset_price" => "流量重置包",
            _ => "未知周期"
        };

    public static string GetCycleDurationText(string? cycle)
        => NormalizeCycle(cycle) switch
        {
            "month" => "31 天有效",
            "quarter" => "90 天有效",
            "half_year" => "180 天有效",
            "year" => "365 天有效",
            "one_time" => "长期有效",
            "reset_price" => "立即生效",
            _ => string.Empty
        };

    public static string GetCycleResetText(string? cycle)
        => NormalizeCycle(cycle) switch
        {
            "month" or "quarter" or "half_year" or "year" => "每月重置",
            "one_time" => "不重置",
            "reset_price" => "立即重置一次",
            _ => string.Empty
        };

    public static string GetCycleSummaryText(string? cycle)
    {
        var parts = new[] { GetCycleDurationText(cycle), GetCycleResetText(cycle) }
            .Where(static part => !string.IsNullOrWhiteSpace(part));

        return string.Join(" · ", parts);
    }

    public static DateTimeOffset? CalculateExpiresAt(string? cycle, DateTimeOffset? fallback = null, DateTimeOffset? now = null)
    {
        var current = now ?? DateTimeOffset.UtcNow;

        return NormalizeCycle(cycle) switch
        {
            "month" => current.AddDays(31),
            "quarter" => current.AddDays(90),
            "half_year" => current.AddDays(180),
            "year" => current.AddDays(365),
            "one_time" => null,
            _ => fallback
        };
    }

    public static string GetResetSummary(PanelPlanRecord plan)
    {
        ArgumentNullException.ThrowIfNull(plan);

        var cycles = GetAvailableCycles(plan);
        var parts = new List<string>(3);
        if (cycles.Any(static item => IsRecurringCycle(item.Cycle)))
        {
            parts.Add("周期套餐每月重置");
        }

        if (cycles.Any(static item => string.Equals(item.Cycle, "one_time", StringComparison.Ordinal)))
        {
            parts.Add("一次性套餐不重置");
        }

        if (cycles.Any(static item => string.Equals(item.Cycle, "reset_price", StringComparison.Ordinal)))
        {
            parts.Add("支持单独购买流量重置");
        }

        return string.Join("，", parts);
    }

    public static string FormatPrice(decimal amount, string currencySymbol)
        => amount == 0m
            ? "免费"
            : $"{NormalizeCurrencySymbol(currencySymbol)}{amount:0.00}";

    public static string FormatTraffic(long bytes)
    {
        var (amount, unit) = ToEditableTraffic(bytes);
        return $"{amount:0.##} {unit}";
    }

    public static string FormatRate(long bytesPerSecond)
    {
        if (bytesPerSecond <= 0)
        {
            return "不限速";
        }

        var (amount, unit) = ToEditableRate(bytesPerSecond);
        return $"{amount:0.##} {unit}";
    }

    public static (decimal Amount, string Unit) ToEditableTraffic(long bytes)
    {
        var normalizedBytes = Math.Max(0L, bytes);
        if (normalizedBytes == 0)
        {
            return (0m, TrafficUnitGb);
        }

        if (normalizedBytes % Terabyte == 0)
        {
            return (normalizedBytes / (decimal)Terabyte, TrafficUnitTb);
        }

        if (normalizedBytes % Gigabyte == 0)
        {
            return (normalizedBytes / (decimal)Gigabyte, TrafficUnitGb);
        }

        if (normalizedBytes % Megabyte == 0)
        {
            return (normalizedBytes / (decimal)Megabyte, TrafficUnitMb);
        }

        if (normalizedBytes >= Terabyte)
        {
            return (decimal.Round(normalizedBytes / (decimal)Terabyte, 2, MidpointRounding.AwayFromZero), TrafficUnitTb);
        }

        if (normalizedBytes >= Gigabyte)
        {
            return (decimal.Round(normalizedBytes / (decimal)Gigabyte, 2, MidpointRounding.AwayFromZero), TrafficUnitGb);
        }

        return (decimal.Round(normalizedBytes / (decimal)Megabyte, 2, MidpointRounding.AwayFromZero), TrafficUnitMb);
    }

    public static long ToTrafficBytes(decimal amount, string? unit)
    {
        if (amount <= 0)
        {
            return 0;
        }

        var factor = NormalizeTrafficUnit(unit) switch
        {
            TrafficUnitMb => Megabyte,
            TrafficUnitTb => Terabyte,
            _ => Gigabyte
        };

        var bytes = decimal.Round(amount * factor, 0, MidpointRounding.AwayFromZero);
        if (bytes >= long.MaxValue)
        {
            return long.MaxValue;
        }

        return decimal.ToInt64(bytes);
    }

    public static (decimal Amount, string Unit) ToEditableRate(long bytesPerSecond)
    {
        var normalizedBytesPerSecond = Math.Max(0L, bytesPerSecond);
        if (normalizedBytesPerSecond == 0)
        {
            return (0m, RateUnitMbPerSecond);
        }

        if (normalizedBytesPerSecond % Gigabyte == 0)
        {
            return (normalizedBytesPerSecond / (decimal)Gigabyte, RateUnitGbPerSecond);
        }

        if (normalizedBytesPerSecond % Megabyte == 0)
        {
            return (normalizedBytesPerSecond / (decimal)Megabyte, RateUnitMbPerSecond);
        }

        if (normalizedBytesPerSecond % Kilobyte == 0)
        {
            return (normalizedBytesPerSecond / (decimal)Kilobyte, RateUnitKbPerSecond);
        }

        if (normalizedBytesPerSecond >= Gigabyte)
        {
            return (decimal.Round(normalizedBytesPerSecond / (decimal)Gigabyte, 2, MidpointRounding.AwayFromZero), RateUnitGbPerSecond);
        }

        if (normalizedBytesPerSecond >= Megabyte)
        {
            return (decimal.Round(normalizedBytesPerSecond / (decimal)Megabyte, 2, MidpointRounding.AwayFromZero), RateUnitMbPerSecond);
        }

        return (decimal.Round(normalizedBytesPerSecond / (decimal)Kilobyte, 2, MidpointRounding.AwayFromZero), RateUnitKbPerSecond);
    }

    public static long ToRateBytesPerSecond(decimal amount, string? unit)
    {
        if (amount <= 0)
        {
            return 0;
        }

        var factor = NormalizeRateUnit(unit) switch
        {
            RateUnitGbPerSecond => Gigabyte,
            RateUnitKbPerSecond => Kilobyte,
            _ => Megabyte
        };

        var bytesPerSecond = decimal.Round(amount * factor, 0, MidpointRounding.AwayFromZero);
        if (bytesPerSecond >= long.MaxValue)
        {
            return long.MaxValue;
        }

        return decimal.ToInt64(bytesPerSecond);
    }

    public static string NormalizeTrafficUnit(string? unit)
        => unit?.Trim().ToUpperInvariant() switch
        {
            TrafficUnitMb => TrafficUnitMb,
            TrafficUnitTb => TrafficUnitTb,
            _ => TrafficUnitGb
        };

    public static string NormalizeRateUnit(string? unit)
        => unit?.Trim().ToUpperInvariant() switch
        {
            "GB/S" => RateUnitGbPerSecond,
            "KB/S" => RateUnitKbPerSecond,
            _ => RateUnitMbPerSecond
        };

    private static void AppendCycleOption(List<PlanCycleOption> options, string cycle, decimal? price)
    {
        var normalizedPrice = NormalizePrice(price);
        if (!normalizedPrice.HasValue)
        {
            return;
        }

        options.Add(
            new PlanCycleOption(
                cycle,
                GetCycleDisplayName(cycle),
                normalizedPrice.Value,
                GetCycleDurationText(cycle),
                GetCycleResetText(cycle)));
    }

    private static decimal? NormalizePrice(decimal? price)
        => price.HasValue ? Math.Max(0m, price.Value) : null;

    private static string NormalizeCurrencySymbol(string? currencySymbol)
        => string.IsNullOrWhiteSpace(currencySymbol) ? "¥" : currencySymbol.Trim();

    private static string NormalizeCycle(string? cycle)
        => string.IsNullOrWhiteSpace(cycle) ? string.Empty : cycle.Trim().ToLowerInvariant();

    private static bool IsRecurringCycle(string cycle)
        => string.Equals(cycle, "month", StringComparison.Ordinal) ||
           string.Equals(cycle, "quarter", StringComparison.Ordinal) ||
           string.Equals(cycle, "half_year", StringComparison.Ordinal) ||
           string.Equals(cycle, "year", StringComparison.Ordinal);
}
