namespace NodePanel.Core.Runtime;

internal static class RuntimeRealityFingerprintCatalog
{
    private static readonly HashSet<string> KnownFingerprints = new(StringComparer.Ordinal)
    {
        string.Empty,

        "chrome",
        "firefox",
        "safari",
        "ios",
        "android",
        "edge",
        "360",
        "qq",
        "random",
        "randomized",
        "randomizednoalpn",
        "unsafe",

        "hellofirefox_99",
        "hellofirefox_102",
        "hellofirefox_105",
        "hellofirefox_120",
        "hellochrome_83",
        "hellochrome_87",
        "hellochrome_96",
        "hellochrome_100",
        "hellochrome_102",
        "hellochrome_106_shuffle",
        "hellochrome_120",
        "hellochrome_131",
        "helloios_13",
        "helloios_14",
        "helloedge_85",
        "helloedge_106",
        "hellosafari_16_0",
        "hello360_11_0",
        "helloqq_11_1",

        "hellogolang",
        "hellorandomized",
        "hellorandomizedalpn",
        "hellorandomizednoalpn",
        "hellofirefox_auto",
        "hellofirefox_55",
        "hellofirefox_56",
        "hellofirefox_63",
        "hellofirefox_65",
        "hellochrome_auto",
        "hellochrome_58",
        "hellochrome_62",
        "hellochrome_70",
        "hellochrome_72",
        "helloios_auto",
        "helloios_11_1",
        "helloios_12_1",
        "helloandroid_11_okhttp",
        "helloedge_auto",
        "hellosafari_auto",
        "hello360_auto",
        "hello360_7_5",
        "helloqq_auto",
        "hellochrome_100_psk",
        "hellochrome_112_psk_shuf",
        "hellochrome_114_padding_psk_shuf",
        "hellochrome_115_pq",
        "hellochrome_115_pq_psk",
        "hellochrome_120_pq"
    };

    public static bool IsKnown(string fingerprint)
        => KnownFingerprints.Contains(string.IsNullOrWhiteSpace(fingerprint)
            ? string.Empty
            : fingerprint.Trim().ToLowerInvariant());
}
