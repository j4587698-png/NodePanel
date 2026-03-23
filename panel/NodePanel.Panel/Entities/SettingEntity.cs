using FreeSql.DataAnnotations;

namespace NodePanel.Panel.Entities;

[Table(Name = "np_settings")]
public class SettingEntity
{
    [Column(IsPrimary = true, StringLength = 100)]
    public string Key { get; set; } = null!;

    [Column(StringLength = -1)] // -1 means MAX length, usually mapped to text/longtext
    public string Value { get; set; } = string.Empty;

    [Column(StringLength = 100)]
    public string Type { get; set; } = "string"; // Can be string, bool, json, int

    [Column(StringLength = 255)]
    public string? Description { get; set; }
}
