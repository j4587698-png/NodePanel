using System.Buffers;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using Microsoft.Extensions.Configuration;
using NodePanel.ControlPlane.Configuration;
using NodePanel.Service.Runtime;

namespace NodePanel.Service.Configuration;

public static class NodePanelOptionsLoader
{
    private static readonly NodePanelOptions DefaultOptions = new();
    private static readonly ControlPlaneOptions DefaultControlPlaneOptions = new();

    public static NodePanelOptions Load(IConfiguration configuration, string[] args)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(args);

        var section = configuration.GetSection(NodePanelOptions.SectionName);
        var panelUrl = FirstNonEmpty(
            GetArgumentValue(args, "--panel-url"),
            GetArgumentValue(args, "--control-plane-url"),
            configuration[$"{NodePanelOptions.SectionName}:{nameof(NodePanelOptions.PanelUrl)}"],
            configuration[$"{NodePanelOptions.SectionName}:{nameof(NodePanelOptions.ControlPlane)}:{nameof(ControlPlaneOptions.Url)}"]);

        var enabled = ResolveBoolean(
            DefaultControlPlaneOptions.Enabled,
            GetArgumentValue(args, "--control-plane-enabled"),
            configuration[$"{NodePanelOptions.SectionName}:{nameof(NodePanelOptions.ControlPlane)}:{nameof(ControlPlaneOptions.Enabled)}"]);

        if (!string.IsNullOrWhiteSpace(panelUrl))
        {
            enabled = true;
        }

        return new NodePanelOptions
        {
            PanelUrl = panelUrl,
            CachedConfigPath = FirstNonEmpty(
                configuration[$"{NodePanelOptions.SectionName}:{nameof(NodePanelOptions.CachedConfigPath)}"],
                DefaultOptions.CachedConfigPath),
            Identity = new NodeIdentityOptions
            {
                NodeId = FirstNonEmpty(
                    GetArgumentValue(args, "--node-id"),
                    configuration[$"{NodePanelOptions.SectionName}:{nameof(NodePanelOptions.Identity)}:{nameof(NodeIdentityOptions.NodeId)}"])
            },
            ControlPlane = new ControlPlaneOptions
            {
                Enabled = enabled,
                Url = panelUrl,
                AccessToken = FirstNonEmpty(
                    GetArgumentValue(args, "--panel-access-token"),
                    GetArgumentValue(args, "--control-plane-access-token"),
                    configuration[$"{NodePanelOptions.SectionName}:{nameof(NodePanelOptions.ControlPlane)}:{nameof(ControlPlaneOptions.AccessToken)}"]),
                ConnectTimeoutSeconds = ReadInt32(
                    configuration[$"{NodePanelOptions.SectionName}:{nameof(NodePanelOptions.ControlPlane)}:{nameof(ControlPlaneOptions.ConnectTimeoutSeconds)}"],
                    DefaultControlPlaneOptions.ConnectTimeoutSeconds),
                HeartbeatIntervalSeconds = ReadInt32(
                    configuration[$"{NodePanelOptions.SectionName}:{nameof(NodePanelOptions.ControlPlane)}:{nameof(ControlPlaneOptions.HeartbeatIntervalSeconds)}"],
                    DefaultControlPlaneOptions.HeartbeatIntervalSeconds),
                ReconnectDelaySeconds = ReadInt32(
                    configuration[$"{NodePanelOptions.SectionName}:{nameof(NodePanelOptions.ControlPlane)}:{nameof(ControlPlaneOptions.ReconnectDelaySeconds)}"],
                    DefaultControlPlaneOptions.ReconnectDelaySeconds)
            },
            Bootstrap = LoadSection(
                section.GetSection(nameof(NodePanelOptions.Bootstrap)),
                ServiceRuntimeJsonSerializerContext.Default.NodeServiceConfig,
                new NodeServiceConfig())
        };
    }

    private static T LoadSection<T>(IConfigurationSection section, JsonTypeInfo<T> typeInfo, T fallback)
        where T : class
    {
        if (!HasConfigurationValue(section, typeInfo))
        {
            return fallback;
        }

        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            WriteSection(writer, section, typeInfo);
        }

        return JsonSerializer.Deserialize(buffer.WrittenSpan, typeInfo) ?? fallback;
    }

    private static void WriteSection(Utf8JsonWriter writer, IConfigurationSection section, JsonTypeInfo typeInfo)
    {
        if (TryWriteSimpleValue(writer, section, typeInfo.Type))
        {
            return;
        }

        switch (typeInfo.Kind)
        {
            case JsonTypeInfoKind.Object:
                writer.WriteStartObject();
                foreach (var property in typeInfo.Properties)
                {
                    if (property.IsExtensionData || (property.Set is null && property.AssociatedParameter is null))
                    {
                        continue;
                    }

                    var child = section.GetSection(property.Name);
                    var childTypeInfo = ResolveTypeInfo(property.PropertyType);
                    if (!HasConfigurationValue(child, childTypeInfo))
                    {
                        continue;
                    }

                    writer.WritePropertyName(property.Name);
                    WriteSection(writer, child, childTypeInfo);
                }

                writer.WriteEndObject();
                return;

            case JsonTypeInfoKind.Enumerable:
                writer.WriteStartArray();
                var elementType = typeInfo.ElementType
                    ?? throw new InvalidOperationException($"Missing element metadata for configuration section '{section.Path}'.");
                var elementTypeInfo = ResolveTypeInfo(elementType);
                foreach (var child in GetOrderedChildren(section))
                {
                    WriteSection(writer, child, elementTypeInfo);
                }

                writer.WriteEndArray();
                return;

            case JsonTypeInfoKind.Dictionary:
                writer.WriteStartObject();
                var valueType = typeInfo.ElementType
                    ?? throw new InvalidOperationException($"Missing dictionary value metadata for configuration section '{section.Path}'.");
                var valueTypeInfo = ResolveTypeInfo(valueType);
                foreach (var child in GetOrderedChildren(section))
                {
                    writer.WritePropertyName(child.Key);
                    WriteSection(writer, child, valueTypeInfo);
                }

                writer.WriteEndObject();
                return;

            default:
                throw new InvalidOperationException(
                    $"Configuration section '{section.Path}' cannot be converted to '{typeInfo.Type.FullName}'.");
        }
    }

    private static bool HasConfigurationValue(IConfigurationSection section, JsonTypeInfo typeInfo)
    {
        if (IsSimpleType(typeInfo.Type))
        {
            return Nullable.GetUnderlyingType(typeInfo.Type) == typeof(string) || typeInfo.Type == typeof(string)
                ? section.Value is not null
                : !string.IsNullOrWhiteSpace(section.Value);
        }

        return section.GetChildren().Any();
    }

    private static bool TryWriteSimpleValue(Utf8JsonWriter writer, IConfigurationSection section, Type type)
    {
        var underlyingType = Nullable.GetUnderlyingType(type) ?? type;
        var value = section.Value;
        if (underlyingType == typeof(string))
        {
            writer.WriteStringValue(value ?? string.Empty);
            return true;
        }

        if (!IsSimpleType(type))
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        if (underlyingType == typeof(bool))
        {
            if (!bool.TryParse(value, out var result))
            {
                throw CreateInvalidScalarException(section, value, underlyingType);
            }

            writer.WriteBooleanValue(result);
            return true;
        }

        if (underlyingType == typeof(int))
        {
            if (!int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var result))
            {
                throw CreateInvalidScalarException(section, value, underlyingType);
            }

            writer.WriteNumberValue(result);
            return true;
        }

        if (underlyingType == typeof(uint))
        {
            if (!uint.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var result))
            {
                throw CreateInvalidScalarException(section, value, underlyingType);
            }

            writer.WriteNumberValue(result);
            return true;
        }

        if (underlyingType == typeof(long))
        {
            if (!long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var result))
            {
                throw CreateInvalidScalarException(section, value, underlyingType);
            }

            writer.WriteNumberValue(result);
            return true;
        }

        if (underlyingType == typeof(double))
        {
            if (!double.TryParse(value, NumberStyles.Float | NumberStyles.AllowThousands, CultureInfo.InvariantCulture, out var result))
            {
                throw CreateInvalidScalarException(section, value, underlyingType);
            }

            writer.WriteNumberValue(result);
            return true;
        }

        if (underlyingType == typeof(decimal))
        {
            if (!decimal.TryParse(value, NumberStyles.Number, CultureInfo.InvariantCulture, out var result))
            {
                throw CreateInvalidScalarException(section, value, underlyingType);
            }

            writer.WriteNumberValue(result);
            return true;
        }

        if (underlyingType == typeof(DateTimeOffset))
        {
            if (!DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var result))
            {
                throw CreateInvalidScalarException(section, value, underlyingType);
            }

            writer.WriteStringValue(result);
            return true;
        }

        if (underlyingType == typeof(DateTime))
        {
            if (!DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var result))
            {
                throw CreateInvalidScalarException(section, value, underlyingType);
            }

            writer.WriteStringValue(result);
            return true;
        }

        if (underlyingType == typeof(Guid))
        {
            if (!Guid.TryParse(value, out var result))
            {
                throw CreateInvalidScalarException(section, value, underlyingType);
            }

            writer.WriteStringValue(result);
            return true;
        }

        if (underlyingType == typeof(TimeSpan))
        {
            if (!TimeSpan.TryParse(value, CultureInfo.InvariantCulture, out var result))
            {
                throw CreateInvalidScalarException(section, value, underlyingType);
            }

            writer.WriteStringValue(result.ToString("c", CultureInfo.InvariantCulture));
            return true;
        }

        return false;
    }

    private static JsonTypeInfo ResolveTypeInfo(Type type)
        => ServiceRuntimeJsonSerializerContext.Default.Options.GetTypeInfo(type)
           ?? throw new InvalidOperationException($"Missing JSON metadata for type '{type.FullName}'.");

    private static IReadOnlyList<IConfigurationSection> GetOrderedChildren(IConfigurationSection section)
    {
        var children = section.GetChildren().ToArray();
        if (children.Length == 0)
        {
            return children;
        }

        var indexedChildren = new List<(int Index, IConfigurationSection Section)>(children.Length);
        foreach (var child in children)
        {
            if (!int.TryParse(child.Key, NumberStyles.Integer, CultureInfo.InvariantCulture, out var index))
            {
                return children;
            }

            indexedChildren.Add((index, child));
        }

        indexedChildren.Sort(static (left, right) => left.Index.CompareTo(right.Index));
        return indexedChildren.Select(static item => item.Section).ToArray();
    }

    private static bool IsSimpleType(Type type)
    {
        var underlyingType = Nullable.GetUnderlyingType(type) ?? type;
        return underlyingType == typeof(string) ||
               underlyingType == typeof(bool) ||
               underlyingType == typeof(int) ||
               underlyingType == typeof(uint) ||
               underlyingType == typeof(long) ||
               underlyingType == typeof(double) ||
               underlyingType == typeof(decimal) ||
               underlyingType == typeof(DateTimeOffset) ||
               underlyingType == typeof(DateTime) ||
               underlyingType == typeof(Guid) ||
               underlyingType == typeof(TimeSpan);
    }

    private static int ReadInt32(string? value, int fallback)
        => int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var result)
            ? result
            : fallback;

    private static string GetArgumentValue(string[] args, string key)
    {
        foreach (var arg in args)
        {
            if (arg.StartsWith(key + "=", StringComparison.OrdinalIgnoreCase))
            {
                return arg[(key.Length + 1)..];
            }
        }

        return string.Empty;
    }

    private static string FirstNonEmpty(params string?[] values)
        => values.FirstOrDefault(static value => !string.IsNullOrWhiteSpace(value))?.Trim() ?? string.Empty;

    private static bool ResolveBoolean(bool fallback, params string?[] values)
    {
        foreach (var value in values)
        {
            if (bool.TryParse(value, out var result))
            {
                return result;
            }
        }

        return fallback;
    }

    private static InvalidOperationException CreateInvalidScalarException(
        IConfigurationSection section,
        string value,
        Type type)
        => new($"Configuration value '{section.Path}' with value '{value}' cannot be converted to '{type.FullName}'.");
}
