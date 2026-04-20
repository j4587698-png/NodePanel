using NodePanel.ControlPlane.Configuration;
using NodePanel.ControlPlane.Runtime;

namespace NodePanel.ControlPlane.Tests;

public sealed class RoutingResourceLocatorTests
{
    [Fact]
    public void ApplyDefaults_prefers_asset_environment_directory_and_config_subdirectory()
    {
        var assetRoot = CreateTempDirectory();
        var baseDirectory = CreateTempDirectory();
        var currentDirectory = CreateTempDirectory();
        try
        {
            Directory.CreateDirectory(Path.Combine(assetRoot, "config"));
            File.WriteAllText(Path.Combine(assetRoot, "config", "geosite.dat"), string.Empty);
            File.WriteAllText(Path.Combine(assetRoot, "config", "geoip.dat"), string.Empty);

            var config = RoutingResourceLocator.ApplyDefaults(
                new NodeServiceConfig(),
                baseDirectory,
                currentDirectory,
                name => string.Equals(name, RoutingResourceLocator.AssetLocationEnvironmentName, StringComparison.Ordinal)
                    ? assetRoot
                    : null);

            Assert.Equal(
                Path.GetFullPath(Path.Combine(assetRoot, "config")),
                config.RoutingResources.ResourceDirectory);
            Assert.Equal(
                Path.GetFullPath(Path.Combine(assetRoot, "config", "geosite.dat")),
                config.RoutingResources.GeoSitePath);
            Assert.Equal(
                Path.GetFullPath(Path.Combine(assetRoot, "config", "geoip.dat")),
                config.RoutingResources.GeoIpPath);
        }
        finally
        {
            DeleteDirectoryIfExists(assetRoot);
            DeleteDirectoryIfExists(baseDirectory);
            DeleteDirectoryIfExists(currentDirectory);
        }
    }

    [Fact]
    public void ApplyDefaults_normalizes_explicit_resource_directory_and_relative_file_paths()
    {
        var baseDirectory = CreateTempDirectory();
        try
        {
            var config = RoutingResourceLocator.ApplyDefaults(
                new NodeServiceConfig
                {
                    RoutingResources = new RoutingResourceOptions
                    {
                        ResourceDirectory = " assets ",
                        GeoSitePath = " geosite-cn.dat ",
                        GeoIpPath = " geoip-us.dat "
                    }
                },
                baseDirectory,
                baseDirectory,
                _ => null);

            var expectedDirectory = Path.GetFullPath(Path.Combine(baseDirectory, "assets"));
            Assert.Equal(expectedDirectory, config.RoutingResources.ResourceDirectory);
            Assert.Equal(
                Path.GetFullPath(Path.Combine(expectedDirectory, "geosite-cn.dat")),
                config.RoutingResources.GeoSitePath);
            Assert.Equal(
                Path.GetFullPath(Path.Combine(expectedDirectory, "geoip-us.dat")),
                config.RoutingResources.GeoIpPath);
        }
        finally
        {
            DeleteDirectoryIfExists(baseDirectory);
        }
    }

    private static string CreateTempDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "NodePanel-RoutingLocator-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private static void DeleteDirectoryIfExists(string path)
    {
        if (Directory.Exists(path))
        {
            Directory.Delete(path, recursive: true);
        }
    }
}
