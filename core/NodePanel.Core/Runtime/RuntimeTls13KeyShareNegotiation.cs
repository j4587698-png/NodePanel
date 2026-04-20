namespace NodePanel.Core.Runtime;

internal readonly record struct RuntimeTls13ClientKeyShareRequirements(
    bool UsesX25519Kyber768Draft00,
    bool UsesX25519MlKem768,
    bool UsesSecp256r1MlKem768,
    bool UsesSecp384r1MlKem1024,
    bool UsesSecp521r1);

internal static class RuntimeTls13KeyShareNegotiation
{
    private static readonly ushort[] PreferredServerGroupsInternal =
    [
        RuntimeTlsNamedGroups.X25519MLKem768,
        RuntimeTlsNamedGroups.X25519Kyber768Draft00,
        RuntimeTlsNamedGroups.X25519,
        RuntimeTlsNamedGroups.Secp256r1MLKem768,
        RuntimeTlsNamedGroups.Secp256r1,
        RuntimeTlsNamedGroups.Secp384r1MLKem1024,
        RuntimeTlsNamedGroups.Secp384r1,
        RuntimeTlsNamedGroups.Secp521r1
    ];

    public static IReadOnlyList<ushort> PreferredServerGroups => PreferredServerGroupsInternal;

    public static RuntimeTls13ClientKeyShareRequirements ResolveClientKeyShareRequirements(
        RuntimeRealityTls13ClientHelloProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);

        HashSet<ushort> groups = new(profile.SupportedGroups);
        foreach (var keyShareGroup in profile.KeyShareGroups)
        {
            groups.Add(keyShareGroup);
        }

        return new RuntimeTls13ClientKeyShareRequirements(
            groups.Contains(RuntimeTlsNamedGroups.X25519Kyber768Draft00) &&
            RuntimeX25519Kyber768Draft00.IsSupported,
            groups.Contains(RuntimeTlsNamedGroups.X25519MLKem768) &&
            RuntimeX25519MlKem768.IsSupported,
            groups.Contains(RuntimeTlsNamedGroups.Secp256r1MLKem768) &&
            RuntimeSecp256r1MlKem768.IsSupported,
            groups.Contains(RuntimeTlsNamedGroups.Secp384r1MLKem1024) &&
            RuntimeSecp384r1MlKem1024.IsSupported,
            groups.Contains(RuntimeTlsNamedGroups.Secp521r1));
    }

    public static bool IsRuntimeSupported(ushort group)
        => group switch
        {
            RuntimeTlsNamedGroups.X25519 => true,
            RuntimeTlsNamedGroups.X25519Kyber768Draft00 => RuntimeX25519Kyber768Draft00.IsSupported,
            RuntimeTlsNamedGroups.X25519MLKem768 => RuntimeX25519MlKem768.IsSupported,
            RuntimeTlsNamedGroups.Secp256r1MLKem768 => RuntimeSecp256r1MlKem768.IsSupported,
            RuntimeTlsNamedGroups.Secp256r1 => true,
            RuntimeTlsNamedGroups.Secp384r1MLKem1024 => RuntimeSecp384r1MlKem1024.IsSupported,
            RuntimeTlsNamedGroups.Secp384r1 => true,
            RuntimeTlsNamedGroups.Secp521r1 => true,
            _ => false
        };
}
