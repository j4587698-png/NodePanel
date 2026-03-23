using System.Text.Json;
using Microsoft.Extensions.Logging;
using NodePanel.ControlPlane.Configuration;
using NodePanel.Service.Configuration;

namespace NodePanel.Service.Runtime;

public sealed class PersistedNodeConfigStore
{
    private readonly ILogger<PersistedNodeConfigStore> _logger;
    private readonly string _controlPlaneUrl;
    private readonly string _nodeId;
    private readonly string _path;

    public PersistedNodeConfigStore(NodePanelOptions options, ILogger<PersistedNodeConfigStore> logger)
    {
        ArgumentNullException.ThrowIfNull(options);

        _logger = logger;
        _nodeId = ResolveNodeId(options);
        _controlPlaneUrl = NormalizeControlPlaneUrl(options.ControlPlane.Url);
        _path = ResolvePath(options.CachedConfigPath);
    }

    public string Path => _path;

    public PersistedNodeConfigDocument? TryLoad()
    {
        try
        {
            if (!File.Exists(_path))
            {
                return null;
            }

            var json = File.ReadAllText(_path);
            if (string.IsNullOrWhiteSpace(json))
            {
                return null;
            }

            var document = JsonSerializer.Deserialize(
                json,
                ServiceRuntimeJsonSerializerContext.Default.PersistedNodeConfigDocument);
            if (document is null)
            {
                return null;
            }

            if (!IsCompatible(document))
            {
                _logger.LogInformation(
                    "Ignoring persisted node config from {Path} because it belongs to node '{PersistedNodeId}' / control plane '{PersistedControlPlaneUrl}', current node is '{CurrentNodeId}' / '{CurrentControlPlaneUrl}'.",
                    _path,
                    document.NodeId ?? string.Empty,
                    document.ControlPlaneUrl ?? string.Empty,
                    _nodeId,
                    _controlPlaneUrl);
                return null;
            }

            return document;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to load the persisted node config from {Path}.", _path);
            return null;
        }
    }

    public void Save(int revision, NodeServiceConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);

        var document = new PersistedNodeConfigDocument
        {
            NodeId = _nodeId,
            ControlPlaneUrl = _controlPlaneUrl,
            Revision = Math.Max(0, revision),
            SavedAt = DateTimeOffset.UtcNow,
            Config = config
        };

        var directory = System.IO.Path.GetDirectoryName(_path);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var tempPath = _path + ".tmp";
        var bytes = JsonSerializer.SerializeToUtf8Bytes(
            document,
            ServiceRuntimeJsonSerializerContext.Default.PersistedNodeConfigDocument);

        File.WriteAllBytes(tempPath, bytes);
        File.Move(tempPath, _path, overwrite: true);
    }

    private static string ResolvePath(string cachedConfigPath)
    {
        if (string.IsNullOrWhiteSpace(cachedConfigPath))
        {
            return System.IO.Path.Combine(AppContext.BaseDirectory, "node-runtime-config.json");
        }

        return System.IO.Path.IsPathRooted(cachedConfigPath)
            ? System.IO.Path.GetFullPath(cachedConfigPath)
            : System.IO.Path.GetFullPath(System.IO.Path.Combine(AppContext.BaseDirectory, cachedConfigPath));
    }

    private static string ResolveNodeId(NodePanelOptions options)
        => string.IsNullOrWhiteSpace(options.Identity.NodeId)
            ? Environment.MachineName
            : options.Identity.NodeId.Trim();

    private static string NormalizeControlPlaneUrl(string? value)
        => string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim();

    private bool IsCompatible(PersistedNodeConfigDocument document)
    {
        if (string.IsNullOrWhiteSpace(document.NodeId))
        {
            return false;
        }

        if (!string.Equals(document.NodeId, _nodeId, StringComparison.Ordinal))
        {
            return false;
        }

        var persistedControlPlaneUrl = NormalizeControlPlaneUrl(document.ControlPlaneUrl);
        if (!string.Equals(persistedControlPlaneUrl, _controlPlaneUrl, StringComparison.Ordinal))
        {
            return false;
        }

        return true;
    }
}

public sealed record PersistedNodeConfigDocument
{
    public string NodeId { get; init; } = string.Empty;

    public string ControlPlaneUrl { get; init; } = string.Empty;

    public int Revision { get; init; }

    public DateTimeOffset SavedAt { get; init; }

    public required NodeServiceConfig Config { get; init; }
}
