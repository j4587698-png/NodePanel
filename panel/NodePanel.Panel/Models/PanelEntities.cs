using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json;
using FreeSql.DataAnnotations;
using NodePanel.ControlPlane.Configuration;
using ColumnAttribute = FreeSql.DataAnnotations.ColumnAttribute;
using TableAttribute = FreeSql.DataAnnotations.TableAttribute;

namespace NodePanel.Panel.Models;

[Table(Name = "np_users")]
public class UserEntity
{
    [Column(IsPrimary = true)]
    public string UserId { get; set; } = string.Empty;

    public string Email { get; set; } = string.Empty;

    public string PasswordHash { get; set; } = string.Empty;

    public bool IsAdmin { get; set; }

    public string DisplayName { get; set; } = string.Empty;

    public string SubscriptionToken { get; set; } = string.Empty;

    public string TrojanPassword { get; set; } = string.Empty;

    public string V2rayUuid { get; set; } = string.Empty;

    public int GroupId { get; set; }

    public bool Enabled { get; set; } = true;

    public long BytesPerSecond { get; set; }

    public int DeviceLimit { get; set; }

    public string PlanName { get; set; } = string.Empty;

    public string Cycle { get; set; } = string.Empty;

    public long TransferEnableBytes { get; set; }

    public DateTimeOffset? ExpiresAt { get; set; }

    [Column(DbType = "varchar(1024)")]
    public string PurchaseUrl { get; set; } = string.Empty;

    [Column(StringLength = -1)]
    public string PortalNotice { get; set; } = string.Empty;

    [Column(DbType = "varchar(1024)")]
    public string NodeIdsJson { get; set; } = "[]";

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    [Column(DbType = "varchar(64)")]
    public string InviteUserId { get; set; } = string.Empty;

    [Column(DbType = "decimal(10,2)")]
    public decimal CommissionBalance { get; set; } = 0m;

    public int CommissionRate { get; set; } = 0;

    [NotMapped]
    public IReadOnlyList<string> NodeIds
    {
        get => ReadNodeIds(NodeIdsJson);
        set => NodeIdsJson = JsonSerializer.Serialize(NormalizeNodeIds(value));
    }

    public PanelUserRecord ToRecord() => new PanelUserRecord
    {
        UserId = UserId,
        DisplayName = NodeFormValueCodec.TrimOrEmpty(DisplayName),
        SubscriptionToken = NodeFormValueCodec.TrimOrEmpty(SubscriptionToken),
        TrojanPassword = NodeFormValueCodec.TrimOrEmpty(TrojanPassword),
        V2rayUuid = NodeFormValueCodec.TrimOrEmpty(V2rayUuid),
        InviteUserId = NodeFormValueCodec.TrimOrEmpty(InviteUserId),
        CommissionBalance = CommissionBalance,
        CommissionRate = Math.Clamp(CommissionRate, 0, 100),
        GroupId = GroupId,
        Enabled = Enabled,
        BytesPerSecond = BytesPerSecond,
        DeviceLimit = DeviceLimit,
        NodeIds = NodeIds,
        Subscription = new PanelUserSubscriptionProfile
        {
            PlanName = NodeFormValueCodec.TrimOrEmpty(PlanName),
            Cycle = NodeFormValueCodec.TrimOrEmpty(Cycle),
            TransferEnableBytes = TransferEnableBytes,
            ExpiresAt = ExpiresAt,
            PurchaseUrl = NodeFormValueCodec.TrimOrEmpty(PurchaseUrl),
            PortalNotice = PortalNotice ?? string.Empty
        }
    };

    public void ApplyRecord(PanelUserRecord record)
    {
        DisplayName = record.DisplayName;
        SubscriptionToken = record.SubscriptionToken;
        TrojanPassword = record.TrojanPassword;
        V2rayUuid = record.V2rayUuid;
        InviteUserId = record.InviteUserId;
        CommissionBalance = record.CommissionBalance;
        CommissionRate = Math.Clamp(record.CommissionRate, 0, 100);
        GroupId = record.GroupId;
        Enabled = record.Enabled;
        BytesPerSecond = record.BytesPerSecond;
        DeviceLimit = record.DeviceLimit;
        NodeIds = record.NodeIds;
        PlanName = record.Subscription.PlanName;
        Cycle = record.Subscription.Cycle;
        TransferEnableBytes = record.Subscription.TransferEnableBytes;
        ExpiresAt = record.Subscription.ExpiresAt;
        PurchaseUrl = record.Subscription.PurchaseUrl;
        PortalNotice = record.Subscription.PortalNotice;
    }

    private static IReadOnlyList<string> ReadNodeIds(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return Array.Empty<string>();
        }

        var normalized = value.Trim();
        if (!normalized.StartsWith("[", StringComparison.Ordinal))
        {
            return NormalizeNodeIds(NodeFormValueCodec.ParseCsv(normalized));
        }

        try
        {
            return NormalizeNodeIds(JsonSerializer.Deserialize<string[]>(normalized));
        }
        catch (JsonException)
        {
            return Array.Empty<string>();
        }
    }

    private static IReadOnlyList<string> NormalizeNodeIds(IEnumerable<string>? values)
        => (values ?? Array.Empty<string>())
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Select(static value => value.Trim())
            .Distinct(StringComparer.Ordinal)
            .ToArray();
}

[Table(Name = "np_nodes")]
public class NodeEntity
{
    [Column(IsPrimary = true)]
    public string NodeId { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;

    [Column(DbType = "varchar(32)")]
    public string Protocol { get; set; } = "trojan";

    [Column(DbType = "varchar(1024)")]
    public string GroupIdsJson { get; set; } = "[]";

    [Column(DbType = "decimal(10,2)")]
    public decimal TrafficMultiplier { get; set; } = 1.0m;

    public bool Enabled { get; set; } = true;

    public int DesiredRevision { get; set; } = 1;

    public string SubscriptionHost { get; set; } = string.Empty;

    public string SubscriptionSni { get; set; } = string.Empty;

    public string SubscriptionRegion { get; set; } = string.Empty;

    [Column(DbType = "varchar(1024)")]
    public string SubscriptionTagsCsv { get; set; } = string.Empty;

    public bool SubscriptionAllowInsecure { get; set; }

    [Column(StringLength = -1)]
    public string ConfigJson { get; set; } = string.Empty;

    [NotMapped]
    public NodeServiceConfig Config
    {
        get => string.IsNullOrWhiteSpace(ConfigJson)
            ? new NodeServiceConfig()
            : JsonSerializer.Deserialize<NodeServiceConfig>(ConfigJson, new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? new NodeServiceConfig();
        set => ConfigJson = JsonSerializer.Serialize(value ?? new NodeServiceConfig());
    }

    [NotMapped]
    public IReadOnlyList<int> GroupIds
    {
        get => string.IsNullOrWhiteSpace(GroupIdsJson)
            ? Array.Empty<int>()
            : JsonSerializer.Deserialize<int[]>(GroupIdsJson) ?? Array.Empty<int>();
        set => GroupIdsJson = JsonSerializer.Serialize(value ?? Array.Empty<int>());
    }

    [NotMapped]
    public IReadOnlyList<string> SubscriptionTags
    {
        get => NodeFormValueCodec.ParseCsv(SubscriptionTagsCsv);
        set => SubscriptionTagsCsv = NodeFormValueCodec.JoinCsv(value);
    }

    public PanelNodeRecord ToRecord() => new PanelNodeRecord
    {
        NodeId = NodeId,
        Protocol = Protocol,
        Config = Config,
        DesiredRevision = DesiredRevision,
        TrafficMultiplier = TrafficMultiplier,
        Enabled = Enabled,
        GroupIds = GroupIds,
        DisplayName = DisplayName,
        SubscriptionHost = SubscriptionHost,
        SubscriptionSni = SubscriptionSni,
        SubscriptionRegion = SubscriptionRegion,
        SubscriptionTags = SubscriptionTags,
        SubscriptionAllowInsecure = SubscriptionAllowInsecure
    };

    public void ApplyRecord(PanelNodeRecord record)
    {
        Config = record.Config;
        Protocol = record.Protocol;
        DesiredRevision = record.DesiredRevision;
        TrafficMultiplier = record.TrafficMultiplier;
        Enabled = record.Enabled;
        GroupIds = record.GroupIds;
        DisplayName = record.DisplayName;
        SubscriptionHost = record.SubscriptionHost;
        SubscriptionSni = record.SubscriptionSni;
        SubscriptionRegion = record.SubscriptionRegion;
        SubscriptionTags = record.SubscriptionTags;
        SubscriptionAllowInsecure = record.SubscriptionAllowInsecure;
    }
}

[Table(Name = "np_plans")]
public class PlanEntity
{
    [Column(IsPrimary = true)]
    public string PlanId { get; set; } = string.Empty;

    public int GroupId { get; set; }

    public string Name { get; set; } = string.Empty;

    public long TransferEnableBytes { get; set; }

    public decimal? MonthPrice { get; set; }
    public decimal? QuarterPrice { get; set; }
    public decimal? HalfYearPrice { get; set; }
    public decimal? YearPrice { get; set; }
    public decimal? OneTimePrice { get; set; }
    public decimal? ResetPrice { get; set; }

    public PanelPlanRecord ToRecord() => new PanelPlanRecord
    {
        PlanId = PlanId,
        GroupId = GroupId,
        Name = Name,
        TransferEnableBytes = TransferEnableBytes,
        MonthPrice = MonthPrice,
        QuarterPrice = QuarterPrice,
        HalfYearPrice = HalfYearPrice,
        YearPrice = YearPrice,
        OneTimePrice = OneTimePrice,
        ResetPrice = ResetPrice
    };

    public void ApplyRecord(PanelPlanRecord record)
    {
        Name = record.Name;
        GroupId = record.GroupId;
        TransferEnableBytes = record.TransferEnableBytes;
        MonthPrice = record.MonthPrice;
        QuarterPrice = record.QuarterPrice;
        HalfYearPrice = record.HalfYearPrice;
        YearPrice = record.YearPrice;
        OneTimePrice = record.OneTimePrice;
        ResetPrice = record.ResetPrice;
    }
}

[Table(Name = "np_traffic_records")]
public class TrafficRecordEntity
{
    [Column(IsPrimary = true)]
    public string UserId { get; set; } = string.Empty;

    public long UploadBytes { get; set; }

    public long DownloadBytes { get; set; }

    public DateTimeOffset? LastResetAt { get; set; }

    public PanelUserTrafficRecord ToRecord() => new PanelUserTrafficRecord
    {
        UserId = UserId,
        UploadBytes = UploadBytes,
        DownloadBytes = DownloadBytes,
        LastResetAt = LastResetAt
    };
}

[Table(Name = "np_orders")]
public class OrderEntity
{
    [Column(IsPrimary = true)]
    public string OrderId { get; set; } = string.Empty;

    public string UserId { get; set; } = string.Empty;

    public string PlanId { get; set; } = string.Empty;

    public string Cycle { get; set; } = string.Empty;

    public string TradeNo { get; set; } = string.Empty;

    public decimal TotalAmount { get; set; }

    public int Status { get; set; } // 0: Pending, 1: Paid, 2: Cancelled

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public DateTimeOffset? PaidAt { get; set; }

    public PanelOrderRecord ToRecord() => new PanelOrderRecord
    {
        OrderId = OrderId,
        UserId = UserId,
        PlanId = PlanId,
        Cycle = Cycle,
        TradeNo = TradeNo,
        TotalAmount = TotalAmount,
        Status = Status,
        CreatedAt = CreatedAt,
        PaidAt = PaidAt
    };
}

[Table(Name = "np_settings")]
public class SettingEntity
{
    [Column(IsPrimary = true)]
    public string Key { get; set; } = string.Empty;

    [Column(StringLength = -1)]
    public string Value { get; set; } = string.Empty;
}

[Table(Name = "np_tickets")]
public class TicketEntity
{
    [Column(IsPrimary = true)]
    public string TicketId { get; set; } = string.Empty;

    public string UserId { get; set; } = string.Empty;

    public string Subject { get; set; } = string.Empty;

    public int Level { get; set; } // 0: Low, 1: Medium, 2: High

    public int Status { get; set; } // 0: Open, 1: Closed

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}

[Table(Name = "np_ticket_messages")]
public class TicketMessageEntity
{
    [Column(IsPrimary = true)]
    public string MessageId { get; set; } = string.Empty;

    public string TicketId { get; set; } = string.Empty;

    public string UserId { get; set; } = string.Empty;

    [Column(StringLength = -1)]
    public string Content { get; set; } = string.Empty;

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}

[Table(Name = "np_invite_codes")]
public class InviteCodeEntity
{
    [Column(IsPrimary = true)]
    public string Code { get; set; } = string.Empty;

    public string UserId { get; set; } = string.Empty;

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}

[Table(Name = "np_commission_logs")]
public class CommissionLogEntity
{
    [Column(IsPrimary = true)]
    public string LogId { get; set; } = string.Empty;

    public string InviteUserId { get; set; } = string.Empty;

    public string OrderId { get; set; } = string.Empty;

    public decimal TradeAmount { get; set; }

    public decimal CommissionAmount { get; set; }

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}

[Table(Name = "np_server_groups")]
public class ServerGroupEntity
{
    [Column(IsPrimary = true, IsIdentity = true)]
    public int GroupId { get; set; }

    public string Name { get; set; } = string.Empty;

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}
