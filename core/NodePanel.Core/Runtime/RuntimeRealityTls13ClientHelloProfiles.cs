using System.Security.Cryptography;

namespace NodePanel.Core.Runtime;

internal enum RuntimeRealityTls13ExtensionKind
{
    Grease,
    ServerName,
    ExtendedMasterSecret,
    RenegotiationInfo,
    SupportedGroups,
    EcPointFormats,
    SessionTicket,
    ApplicationProtocols,
    StatusRequest,
    SignatureAlgorithms,
    SignedCertificateTimestamp,
    SupportedVersions,
    PskKeyExchangeModes,
    SignatureAlgorithmsCert,
    CompressCertificate,
    ApplicationSettings,
    ApplicationSettingsNew,
    DelegatedCredentials,
    RecordSizeLimit,
    EchGrease,
    NextProtocolNegotiation,
    FakeChannelId,
    FakeOldChannelId,
    KeyShare,
    Padding
}

internal sealed record RuntimeRealityTls13ClientHelloProfile(
    bool UseGrease,
    IReadOnlyList<ushort> CipherSuites,
    IReadOnlyList<ushort> SupportedGroups,
    IReadOnlyList<ushort> KeyShareGroups,
    IReadOnlyList<ushort> SupportedVersions,
    IReadOnlyList<ushort> SignatureAlgorithms,
    IReadOnlyList<ushort> SignatureAlgorithmsCert,
    IReadOnlyList<RuntimeRealityTls13ExtensionKind> Extensions,
    int PaddingLength = 0,
    bool IncludeGreaseKeyShare = false,
    bool ShuffleCipherSuites = false,
    bool ShuffleSupportedGroups = false,
    bool ShuffleKeyShares = false,
    bool ReuseHybridClassicalX25519KeyShare = false,
    int? RecordSizeLimit = null,
    IReadOnlyList<ushort>? DelegatedCredentialSignatureAlgorithms = null,
    IReadOnlyList<ushort>? CompressCertificateAlgorithms = null,
    IReadOnlyList<ushort>? EchGreaseCandidateAeads = null,
    IReadOnlyList<ushort>? EchGreaseCandidatePayloadLengths = null,
    bool UseRandomSessionId = true,
    bool AllowAutomaticApplicationProtocolInjection = true,
    bool UseBoringPadding = false,
    bool ShuffleExtensions = false,
    ushort ClientHelloLegacyVersion = 0x0303,
    IReadOnlyList<string>? ClientHelloApplicationProtocols = null);

internal static class RuntimeRealityTls13ClientHelloProfileCatalog
{
    private static readonly string[] RandomModernFingerprints =
    [
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
        "helloqq_11_1"
    ];

    private static readonly Lazy<string> RandomModernFingerprint = new(CreateRandomModernFingerprint);
    private static readonly Lazy<RuntimeRealityTls13ClientHelloProfile> RandomizedProfile
        = new(() => CreateRandomizedProfile(
            RuntimeTlsRandomizedAlpnMode.Always,
            RandomNumberGenerator.GetBytes(32),
            forceTls13: true));
    private static readonly Lazy<RuntimeRealityTls13ClientHelloProfile> RandomizedNoAlpnProfile
        = new(() => CreateRandomizedProfile(
            RuntimeTlsRandomizedAlpnMode.Never,
            RandomNumberGenerator.GetBytes(32),
            forceTls13: true));

    private static readonly ushort[] ChromeCipherSuites =
    [
        0x1301, 0x1302, 0x1303,
        0xC02B, 0xC02F, 0xC02C, 0xC030,
        0xCCA9, 0xCCA8,
        0xC013, 0xC014,
        0x009C, 0x009D, 0x002F, 0x0035
    ];

    private static readonly ushort[] ChromeLegacyCipherSuitesWith3Des =
    [
        0x1301, 0x1302, 0x1303,
        0xC02B, 0xC02F, 0xC02C, 0xC030,
        0xCCA9, 0xCCA8,
        0xC013, 0xC014,
        0x009C, 0x009D, 0x002F, 0x0035,
        0x000A
    ];

    private static readonly ushort[] Chrome58CipherSuites =
    [
        0xC02B, 0xC02F, 0xC02C, 0xC030,
        0xCCA9, 0xCCA8,
        0xC013, 0xC014,
        0x009C, 0x009D, 0x002F, 0x0035,
        0x000A
    ];

    private static readonly ushort[] FirefoxCipherSuites =
    [
        0x1301, 0x1303, 0x1302,
        0xC02B, 0xC02F, 0xCCA9, 0xCCA8, 0xC02C, 0xC030,
        0xC00A, 0xC009, 0xC013, 0xC014,
        0x009C, 0x009D, 0x002F, 0x0035
    ];

    private static readonly ushort[] SafariCipherSuites =
    [
        0x1301, 0x1302, 0x1303,
        0xC02C, 0xC02B, 0xCCA9,
        0xC030, 0xC02F, 0xCCA8,
        0xC00A, 0xC009, 0xC014, 0xC013,
        0x009D, 0x009C, 0x0035, 0x002F,
        0xC008, 0xC012, 0x000A
    ];

    private static readonly ushort[] Ios14CipherSuites =
    [
        0x1301, 0x1302, 0x1303,
        0xC02C, 0xC02B, 0xCCA9,
        0xC030, 0xC02F, 0xCCA8,
        0xC024, 0xC023, 0xC00A, 0xC009,
        0xC028, 0xC027, 0xC014, 0xC013,
        0x009D, 0x009C, 0x003D, 0x003C,
        0x0035, 0x002F, 0xC008, 0xC012, 0x000A
    ];

    private static readonly ushort[] AndroidCipherSuites =
    [
        0xC02B, 0xC02C, 0xCCA9,
        0xC02F, 0xC030, 0xCCA8,
        0xC013, 0xC014,
        0x009C, 0x009D,
        0x002F, 0x0035
    ];

    private static readonly ushort[] ThreeSixty11CipherSuites =
    [
        0x1301, 0x1302, 0x1303,
        0xC02B, 0xC02F, 0xC02C, 0xC030,
        0xCCA9, 0xCCA8,
        0xC013, 0xC014,
        0x009C, 0x009D, 0x002F, 0x0035,
        0x000A
    ];

    private static readonly ushort[] ThreeSixty75CipherSuites =
    [
        0xC00A, 0xC014, 0x0039, 0x006B,
        0x0035, 0x003D, 0xC007, 0xC009,
        0xC023, 0xC011, 0xC013, 0xC027,
        0x0033, 0x0067, 0x0032, 0x0005,
        0x0004, 0x002F, 0x003C, 0x000A
    ];

    private static readonly ushort[] CommonSupportedGroups =
    [
        RuntimeTlsNamedGroups.X25519,
        RuntimeTlsNamedGroups.Secp256r1,
        RuntimeTlsNamedGroups.Secp384r1
    ];

    private static readonly ushort[] ThreeSixty75SupportedGroups =
    [
        RuntimeTlsNamedGroups.Secp256r1,
        RuntimeTlsNamedGroups.Secp384r1,
        RuntimeTlsNamedGroups.Secp521r1
    ];

    private static readonly ushort[] ChromeKeyShareGroups =
    [
        RuntimeTlsNamedGroups.X25519
    ];

    private static readonly ushort[] FirefoxKeyShareGroups =
    [
        RuntimeTlsNamedGroups.X25519,
        RuntimeTlsNamedGroups.Secp256r1
    ];

    private static readonly ushort[] FirefoxSupportedGroups =
    [
        RuntimeTlsNamedGroups.X25519,
        RuntimeTlsNamedGroups.Secp256r1,
        RuntimeTlsNamedGroups.Secp384r1,
        RuntimeTlsNamedGroups.Secp521r1,
        0x0100,
        0x0101
    ];

    private static readonly ushort[] SafariSupportedGroups =
    [
        RuntimeTlsNamedGroups.X25519,
        RuntimeTlsNamedGroups.Secp256r1,
        RuntimeTlsNamedGroups.Secp384r1,
        RuntimeTlsNamedGroups.Secp521r1
    ];

    private static readonly ushort[] SafariKeyShareGroups =
    [
        RuntimeTlsNamedGroups.X25519
    ];

    private static readonly ushort[] ChromePqSupportedGroups =
    [
        RuntimeTlsNamedGroups.X25519MLKem768,
        RuntimeTlsNamedGroups.X25519,
        RuntimeTlsNamedGroups.Secp256r1,
        RuntimeTlsNamedGroups.Secp384r1
    ];

    private static readonly ushort[] ChromeKyberSupportedGroups =
    [
        RuntimeTlsNamedGroups.X25519Kyber768Draft00,
        RuntimeTlsNamedGroups.X25519,
        RuntimeTlsNamedGroups.Secp256r1,
        RuntimeTlsNamedGroups.Secp384r1
    ];

    private static readonly ushort[] ChromePqKeyShareGroups =
    [
        RuntimeTlsNamedGroups.X25519MLKem768,
        RuntimeTlsNamedGroups.X25519
    ];

    private static readonly ushort[] ChromeKyberKeyShareGroups =
    [
        RuntimeTlsNamedGroups.X25519Kyber768Draft00,
        RuntimeTlsNamedGroups.X25519
    ];

    private static readonly ushort[] Chrome120KeyShareGroups =
    [
        RuntimeTlsNamedGroups.X25519
    ];

    private static readonly ushort[] Firefox148CipherSuites =
    [
        0x1301, 0x1303, 0x1302,
        0xC02B, 0xC02F, 0xCCA9, 0xCCA8, 0xC02C, 0xC030,
        0xC00A, 0xC009, 0xC013, 0xC014,
        0x009C, 0x009D, 0x002F, 0x0035
    ];

    private static readonly ushort[] Safari26_3CipherSuites =
    [
        0x1302, 0x1303, 0x1301,
        0xC02C, 0xC02B, 0xCCA9,
        0xC030, 0xC02F, 0xCCA8,
        0xC00A, 0xC009, 0xC014, 0xC013,
        0x009D, 0x009C, 0x0035, 0x002F,
        0xC008, 0xC012, 0x000A
    ];

    private static readonly ushort[] Firefox148SupportedGroups =
    [
        RuntimeTlsNamedGroups.X25519MLKem768,
        RuntimeTlsNamedGroups.X25519,
        RuntimeTlsNamedGroups.Secp256r1,
        RuntimeTlsNamedGroups.Secp384r1,
        0x0019,
        0x0100,
        0x0101
    ];

    private static readonly ushort[] Safari26_3SupportedGroups =
    [
        RuntimeTlsNamedGroups.X25519MLKem768,
        RuntimeTlsNamedGroups.X25519,
        RuntimeTlsNamedGroups.Secp256r1,
        RuntimeTlsNamedGroups.Secp384r1,
        0x0019
    ];

    private static readonly ushort[] Firefox148KeyShareGroups =
    [
        RuntimeTlsNamedGroups.X25519MLKem768,
        RuntimeTlsNamedGroups.X25519,
        RuntimeTlsNamedGroups.Secp256r1
    ];

    private static readonly ushort[] Safari26_3KeyShareGroups =
    [
        RuntimeTlsNamedGroups.X25519MLKem768,
        RuntimeTlsNamedGroups.X25519
    ];

    private static readonly ushort[] Tls13SupportedVersions =
    [
        0x0304,
        0x0303
    ];

    private static readonly ushort[] Tls13OnlySupportedVersions =
    [
        0x0304
    ];

    private static readonly ushort[] Tls13And12And11And10SupportedVersions =
    [
        0x0304,
        0x0303,
        0x0302,
        0x0301
    ];

    private static readonly ushort[] ChromeSignatureAlgorithms =
    [
        0x0403, 0x0804, 0x0401,
        0x0503, 0x0805, 0x0501,
        0x0806, 0x0601
    ];

    private static readonly ushort[] ChromeLegacySignatureAlgorithmsWithSha1 =
    [
        0x0403, 0x0804, 0x0401,
        0x0503, 0x0805, 0x0501,
        0x0806, 0x0601,
        0x0201
    ];

    private static readonly ushort[] AndroidSignatureAlgorithms =
    [
        0x0403, 0x0804, 0x0401,
        0x0503, 0x0805, 0x0501,
        0x0806, 0x0601,
        0x0201
    ];

    private static readonly ushort[] ThreeSixty75SignatureAlgorithms =
    [
        0x0401, 0x0501, 0x0201,
        0x0403, 0x0503, 0x0203,
        0x0402, 0x0202
    ];

    private static readonly ushort[] FirefoxSignatureAlgorithms =
    [
        0x0403, 0x0503, 0x0603,
        0x0804, 0x0805, 0x0806,
        0x0401, 0x0501, 0x0601,
        0x0203, 0x0201
    ];

    private static readonly ushort[] SafariSignatureAlgorithms =
    [
        0x0403, 0x0804, 0x0401,
        0x0503, 0x0203, 0x0805, 0x0805, 0x0501,
        0x0806, 0x0601, 0x0201
    ];

    private static readonly ushort[] Firefox148SignatureAlgorithms =
    [
        0x0403, 0x0503, 0x0603,
        0x0804, 0x0805, 0x0806,
        0x0401, 0x0501, 0x0601,
        0x0203, 0x0201
    ];

    private static readonly ushort[] Firefox148DelegatedCredentialSignatureAlgorithms =
    [
        0x0403, 0x0503, 0x0603, 0x0203
    ];

    private static readonly ushort[] Safari26_3SignatureAlgorithms =
    [
        0x0403, 0x0804, 0x0401,
        0x0503, 0x0805, 0x0805,
        0x0501, 0x0806, 0x0601,
        0x0201
    ];

    private static readonly ushort[] GolangSignatureAlgorithms =
    [
        0x0804,
        0x0403,
        0x0807,
        0x0805,
        0x0806,
        0x0401,
        0x0501,
        0x0601,
        0x0503,
        0x0603,
        0x0201,
        0x0203
    ];

    private static readonly ushort[] RandomizedBaseCipherSuites =
    [
        0xC02B, 0xC02F,
        0xC02C, 0xC030,
        0xCCA9, 0xCCA8,
        0xC009, 0xC013,
        0xC00A, 0xC014
    ];

    private static readonly ushort[] RandomizedTls13CipherSuites =
    [
        0x1301,
        0x1302,
        0x1303
    ];

    private static readonly ushort[] BrotliCompressionAlgorithms =
    [
        0x0002
    ];

    private static readonly ushort[] ZlibCompressionAlgorithms =
    [
        0x0001
    ];

    private static readonly ushort[] ZlibBrotliZstdCompressionAlgorithms =
    [
        0x0001,
        0x0002,
        0x0003
    ];

    private static readonly ushort[] ChromeEchGreaseCandidateAeads =
    [
        0x0001
    ];

    private static readonly ushort[] ChromeEchGreaseCandidatePayloadLengths =
    [
        128, 160, 192, 224
    ];

    private static readonly ushort[] FirefoxEchGreaseCandidateAeads =
    [
        0x0001,
        0x0003
    ];

    private static readonly ushort[] FirefoxEchGreaseCandidatePayloadLengths =
    [
        223
    ];

    private static readonly string[] ThreeSixty75ApplicationProtocols =
    [
        "spdy/2",
        "spdy/3",
        "spdy/3.1",
        "http/1.1"
    ];

    private static readonly RuntimeRealityTls13ExtensionKind[] ChromeExtensions =
    [
        RuntimeRealityTls13ExtensionKind.Grease,
        RuntimeRealityTls13ExtensionKind.ServerName,
        RuntimeRealityTls13ExtensionKind.RenegotiationInfo,
        RuntimeRealityTls13ExtensionKind.SupportedGroups,
        RuntimeRealityTls13ExtensionKind.EcPointFormats,
        RuntimeRealityTls13ExtensionKind.SessionTicket,
        RuntimeRealityTls13ExtensionKind.ApplicationProtocols,
        RuntimeRealityTls13ExtensionKind.StatusRequest,
        RuntimeRealityTls13ExtensionKind.SignatureAlgorithms,
        RuntimeRealityTls13ExtensionKind.SignedCertificateTimestamp,
        RuntimeRealityTls13ExtensionKind.SupportedVersions,
        RuntimeRealityTls13ExtensionKind.PskKeyExchangeModes,
        RuntimeRealityTls13ExtensionKind.SignatureAlgorithmsCert,
        RuntimeRealityTls13ExtensionKind.KeyShare
    ];

    private static readonly RuntimeRealityTls13ExtensionKind[] Chrome58Extensions =
    [
        RuntimeRealityTls13ExtensionKind.Grease,
        RuntimeRealityTls13ExtensionKind.RenegotiationInfo,
        RuntimeRealityTls13ExtensionKind.ServerName,
        RuntimeRealityTls13ExtensionKind.ExtendedMasterSecret,
        RuntimeRealityTls13ExtensionKind.SessionTicket,
        RuntimeRealityTls13ExtensionKind.SignatureAlgorithms,
        RuntimeRealityTls13ExtensionKind.StatusRequest,
        RuntimeRealityTls13ExtensionKind.SignedCertificateTimestamp,
        RuntimeRealityTls13ExtensionKind.ApplicationProtocols,
        RuntimeRealityTls13ExtensionKind.FakeChannelId,
        RuntimeRealityTls13ExtensionKind.EcPointFormats,
        RuntimeRealityTls13ExtensionKind.SupportedGroups,
        RuntimeRealityTls13ExtensionKind.Grease,
        RuntimeRealityTls13ExtensionKind.Padding
    ];

    private static readonly RuntimeRealityTls13ExtensionKind[] Chrome70Extensions =
    [
        RuntimeRealityTls13ExtensionKind.Grease,
        RuntimeRealityTls13ExtensionKind.RenegotiationInfo,
        RuntimeRealityTls13ExtensionKind.ServerName,
        RuntimeRealityTls13ExtensionKind.ExtendedMasterSecret,
        RuntimeRealityTls13ExtensionKind.SessionTicket,
        RuntimeRealityTls13ExtensionKind.SignatureAlgorithms,
        RuntimeRealityTls13ExtensionKind.StatusRequest,
        RuntimeRealityTls13ExtensionKind.SignedCertificateTimestamp,
        RuntimeRealityTls13ExtensionKind.ApplicationProtocols,
        RuntimeRealityTls13ExtensionKind.FakeChannelId,
        RuntimeRealityTls13ExtensionKind.EcPointFormats,
        RuntimeRealityTls13ExtensionKind.KeyShare,
        RuntimeRealityTls13ExtensionKind.PskKeyExchangeModes,
        RuntimeRealityTls13ExtensionKind.SupportedVersions,
        RuntimeRealityTls13ExtensionKind.SupportedGroups,
        RuntimeRealityTls13ExtensionKind.CompressCertificate,
        RuntimeRealityTls13ExtensionKind.Grease,
        RuntimeRealityTls13ExtensionKind.Padding
    ];

    private static readonly RuntimeRealityTls13ExtensionKind[] Chrome72Extensions =
    [
        RuntimeRealityTls13ExtensionKind.Grease,
        RuntimeRealityTls13ExtensionKind.ServerName,
        RuntimeRealityTls13ExtensionKind.ExtendedMasterSecret,
        RuntimeRealityTls13ExtensionKind.RenegotiationInfo,
        RuntimeRealityTls13ExtensionKind.SupportedGroups,
        RuntimeRealityTls13ExtensionKind.EcPointFormats,
        RuntimeRealityTls13ExtensionKind.SessionTicket,
        RuntimeRealityTls13ExtensionKind.ApplicationProtocols,
        RuntimeRealityTls13ExtensionKind.StatusRequest,
        RuntimeRealityTls13ExtensionKind.SignatureAlgorithms,
        RuntimeRealityTls13ExtensionKind.SignedCertificateTimestamp,
        RuntimeRealityTls13ExtensionKind.KeyShare,
        RuntimeRealityTls13ExtensionKind.PskKeyExchangeModes,
        RuntimeRealityTls13ExtensionKind.SupportedVersions,
        RuntimeRealityTls13ExtensionKind.CompressCertificate,
        RuntimeRealityTls13ExtensionKind.Grease,
        RuntimeRealityTls13ExtensionKind.Padding
    ];

    private static readonly RuntimeRealityTls13ExtensionKind[] Chrome96Extensions =
    [
        RuntimeRealityTls13ExtensionKind.Grease,
        RuntimeRealityTls13ExtensionKind.ServerName,
        RuntimeRealityTls13ExtensionKind.ExtendedMasterSecret,
        RuntimeRealityTls13ExtensionKind.RenegotiationInfo,
        RuntimeRealityTls13ExtensionKind.SupportedGroups,
        RuntimeRealityTls13ExtensionKind.EcPointFormats,
        RuntimeRealityTls13ExtensionKind.SessionTicket,
        RuntimeRealityTls13ExtensionKind.ApplicationProtocols,
        RuntimeRealityTls13ExtensionKind.StatusRequest,
        RuntimeRealityTls13ExtensionKind.SignatureAlgorithms,
        RuntimeRealityTls13ExtensionKind.SignedCertificateTimestamp,
        RuntimeRealityTls13ExtensionKind.KeyShare,
        RuntimeRealityTls13ExtensionKind.PskKeyExchangeModes,
        RuntimeRealityTls13ExtensionKind.SupportedVersions,
        RuntimeRealityTls13ExtensionKind.CompressCertificate,
        RuntimeRealityTls13ExtensionKind.ApplicationSettings,
        RuntimeRealityTls13ExtensionKind.Grease,
        RuntimeRealityTls13ExtensionKind.Padding
    ];

    private static readonly RuntimeRealityTls13ExtensionKind[] Chrome100PskExtensions =
    [
        RuntimeRealityTls13ExtensionKind.Grease,
        RuntimeRealityTls13ExtensionKind.ServerName,
        RuntimeRealityTls13ExtensionKind.ExtendedMasterSecret,
        RuntimeRealityTls13ExtensionKind.RenegotiationInfo,
        RuntimeRealityTls13ExtensionKind.SupportedGroups,
        RuntimeRealityTls13ExtensionKind.EcPointFormats,
        RuntimeRealityTls13ExtensionKind.SessionTicket,
        RuntimeRealityTls13ExtensionKind.ApplicationProtocols,
        RuntimeRealityTls13ExtensionKind.StatusRequest,
        RuntimeRealityTls13ExtensionKind.SignatureAlgorithms,
        RuntimeRealityTls13ExtensionKind.SignedCertificateTimestamp,
        RuntimeRealityTls13ExtensionKind.KeyShare,
        RuntimeRealityTls13ExtensionKind.PskKeyExchangeModes,
        RuntimeRealityTls13ExtensionKind.SupportedVersions,
        RuntimeRealityTls13ExtensionKind.CompressCertificate,
        RuntimeRealityTls13ExtensionKind.ApplicationSettings,
        RuntimeRealityTls13ExtensionKind.Grease
    ];

    private static readonly RuntimeRealityTls13ExtensionKind[] FirefoxExtensions =
    [
        RuntimeRealityTls13ExtensionKind.ServerName,
        RuntimeRealityTls13ExtensionKind.ExtendedMasterSecret,
        RuntimeRealityTls13ExtensionKind.RenegotiationInfo,
        RuntimeRealityTls13ExtensionKind.SupportedGroups,
        RuntimeRealityTls13ExtensionKind.EcPointFormats,
        RuntimeRealityTls13ExtensionKind.SessionTicket,
        RuntimeRealityTls13ExtensionKind.ApplicationProtocols,
        RuntimeRealityTls13ExtensionKind.StatusRequest,
        RuntimeRealityTls13ExtensionKind.DelegatedCredentials,
        RuntimeRealityTls13ExtensionKind.KeyShare,
        RuntimeRealityTls13ExtensionKind.SupportedVersions,
        RuntimeRealityTls13ExtensionKind.SignatureAlgorithms,
        RuntimeRealityTls13ExtensionKind.PskKeyExchangeModes,
        RuntimeRealityTls13ExtensionKind.RecordSizeLimit,
        RuntimeRealityTls13ExtensionKind.EchGrease
    ];

    private static readonly RuntimeRealityTls13ExtensionKind[] SafariExtensions =
    [
        RuntimeRealityTls13ExtensionKind.Grease,
        RuntimeRealityTls13ExtensionKind.ServerName,
        RuntimeRealityTls13ExtensionKind.ExtendedMasterSecret,
        RuntimeRealityTls13ExtensionKind.RenegotiationInfo,
        RuntimeRealityTls13ExtensionKind.SupportedGroups,
        RuntimeRealityTls13ExtensionKind.EcPointFormats,
        RuntimeRealityTls13ExtensionKind.ApplicationProtocols,
        RuntimeRealityTls13ExtensionKind.StatusRequest,
        RuntimeRealityTls13ExtensionKind.SignatureAlgorithms,
        RuntimeRealityTls13ExtensionKind.SignedCertificateTimestamp,
        RuntimeRealityTls13ExtensionKind.KeyShare,
        RuntimeRealityTls13ExtensionKind.PskKeyExchangeModes,
        RuntimeRealityTls13ExtensionKind.SupportedVersions,
        RuntimeRealityTls13ExtensionKind.CompressCertificate,
        RuntimeRealityTls13ExtensionKind.Grease,
        RuntimeRealityTls13ExtensionKind.Padding
    ];

    private static readonly RuntimeRealityTls13ExtensionKind[] IosExtensions =
    [
        RuntimeRealityTls13ExtensionKind.Grease,
        RuntimeRealityTls13ExtensionKind.ServerName,
        RuntimeRealityTls13ExtensionKind.ExtendedMasterSecret,
        RuntimeRealityTls13ExtensionKind.RenegotiationInfo,
        RuntimeRealityTls13ExtensionKind.SupportedGroups,
        RuntimeRealityTls13ExtensionKind.EcPointFormats,
        RuntimeRealityTls13ExtensionKind.ApplicationProtocols,
        RuntimeRealityTls13ExtensionKind.StatusRequest,
        RuntimeRealityTls13ExtensionKind.SignatureAlgorithms,
        RuntimeRealityTls13ExtensionKind.SignedCertificateTimestamp,
        RuntimeRealityTls13ExtensionKind.KeyShare,
        RuntimeRealityTls13ExtensionKind.PskKeyExchangeModes,
        RuntimeRealityTls13ExtensionKind.SupportedVersions,
        RuntimeRealityTls13ExtensionKind.Grease,
        RuntimeRealityTls13ExtensionKind.Padding
    ];

    private static readonly RuntimeRealityTls13ExtensionKind[] AndroidExtensions =
    [
        RuntimeRealityTls13ExtensionKind.ServerName,
        RuntimeRealityTls13ExtensionKind.ExtendedMasterSecret,
        RuntimeRealityTls13ExtensionKind.RenegotiationInfo,
        RuntimeRealityTls13ExtensionKind.SupportedGroups,
        RuntimeRealityTls13ExtensionKind.EcPointFormats,
        RuntimeRealityTls13ExtensionKind.StatusRequest,
        RuntimeRealityTls13ExtensionKind.SignatureAlgorithms,
    ];

    private static readonly RuntimeRealityTls13ExtensionKind[] Edge85Extensions =
    [
        RuntimeRealityTls13ExtensionKind.Grease,
        RuntimeRealityTls13ExtensionKind.ServerName,
        RuntimeRealityTls13ExtensionKind.ExtendedMasterSecret,
        RuntimeRealityTls13ExtensionKind.RenegotiationInfo,
        RuntimeRealityTls13ExtensionKind.SupportedGroups,
        RuntimeRealityTls13ExtensionKind.EcPointFormats,
        RuntimeRealityTls13ExtensionKind.SessionTicket,
        RuntimeRealityTls13ExtensionKind.ApplicationProtocols,
        RuntimeRealityTls13ExtensionKind.StatusRequest,
        RuntimeRealityTls13ExtensionKind.SignatureAlgorithms,
        RuntimeRealityTls13ExtensionKind.SignedCertificateTimestamp,
        RuntimeRealityTls13ExtensionKind.KeyShare,
        RuntimeRealityTls13ExtensionKind.PskKeyExchangeModes,
        RuntimeRealityTls13ExtensionKind.SupportedVersions,
        RuntimeRealityTls13ExtensionKind.CompressCertificate,
        RuntimeRealityTls13ExtensionKind.Grease,
        RuntimeRealityTls13ExtensionKind.Padding
    ];

    private static readonly RuntimeRealityTls13ExtensionKind[] Edge106Extensions =
    [
        RuntimeRealityTls13ExtensionKind.Grease,
        RuntimeRealityTls13ExtensionKind.ServerName,
        RuntimeRealityTls13ExtensionKind.ExtendedMasterSecret,
        RuntimeRealityTls13ExtensionKind.RenegotiationInfo,
        RuntimeRealityTls13ExtensionKind.SupportedGroups,
        RuntimeRealityTls13ExtensionKind.EcPointFormats,
        RuntimeRealityTls13ExtensionKind.SessionTicket,
        RuntimeRealityTls13ExtensionKind.ApplicationProtocols,
        RuntimeRealityTls13ExtensionKind.StatusRequest,
        RuntimeRealityTls13ExtensionKind.SignatureAlgorithms,
        RuntimeRealityTls13ExtensionKind.SignedCertificateTimestamp,
        RuntimeRealityTls13ExtensionKind.KeyShare,
        RuntimeRealityTls13ExtensionKind.PskKeyExchangeModes,
        RuntimeRealityTls13ExtensionKind.SupportedVersions,
        RuntimeRealityTls13ExtensionKind.CompressCertificate,
        RuntimeRealityTls13ExtensionKind.ApplicationSettings,
        RuntimeRealityTls13ExtensionKind.Grease,
        RuntimeRealityTls13ExtensionKind.Padding
    ];

    private static readonly RuntimeRealityTls13ExtensionKind[] ThreeSixty11Extensions =
    [
        RuntimeRealityTls13ExtensionKind.Grease,
        RuntimeRealityTls13ExtensionKind.ServerName,
        RuntimeRealityTls13ExtensionKind.ExtendedMasterSecret,
        RuntimeRealityTls13ExtensionKind.RenegotiationInfo,
        RuntimeRealityTls13ExtensionKind.SupportedGroups,
        RuntimeRealityTls13ExtensionKind.EcPointFormats,
        RuntimeRealityTls13ExtensionKind.SessionTicket,
        RuntimeRealityTls13ExtensionKind.ApplicationProtocols,
        RuntimeRealityTls13ExtensionKind.StatusRequest,
        RuntimeRealityTls13ExtensionKind.SignatureAlgorithms,
        RuntimeRealityTls13ExtensionKind.SignedCertificateTimestamp,
        RuntimeRealityTls13ExtensionKind.FakeChannelId,
        RuntimeRealityTls13ExtensionKind.KeyShare,
        RuntimeRealityTls13ExtensionKind.PskKeyExchangeModes,
        RuntimeRealityTls13ExtensionKind.SupportedVersions,
        RuntimeRealityTls13ExtensionKind.CompressCertificate,
        RuntimeRealityTls13ExtensionKind.Grease,
        RuntimeRealityTls13ExtensionKind.Padding
    ];

    private static readonly RuntimeRealityTls13ExtensionKind[] ThreeSixty75Extensions =
    [
        RuntimeRealityTls13ExtensionKind.ServerName,
        RuntimeRealityTls13ExtensionKind.RenegotiationInfo,
        RuntimeRealityTls13ExtensionKind.SupportedGroups,
        RuntimeRealityTls13ExtensionKind.EcPointFormats,
        RuntimeRealityTls13ExtensionKind.SessionTicket,
        RuntimeRealityTls13ExtensionKind.NextProtocolNegotiation,
        RuntimeRealityTls13ExtensionKind.ApplicationProtocols,
        RuntimeRealityTls13ExtensionKind.FakeOldChannelId,
        RuntimeRealityTls13ExtensionKind.StatusRequest,
        RuntimeRealityTls13ExtensionKind.SignatureAlgorithms
    ];

    private static readonly RuntimeRealityTls13ExtensionKind[] ChromePqExtensions =
    [
        RuntimeRealityTls13ExtensionKind.Grease,
        RuntimeRealityTls13ExtensionKind.ServerName,
        RuntimeRealityTls13ExtensionKind.ExtendedMasterSecret,
        RuntimeRealityTls13ExtensionKind.RenegotiationInfo,
        RuntimeRealityTls13ExtensionKind.SupportedGroups,
        RuntimeRealityTls13ExtensionKind.EcPointFormats,
        RuntimeRealityTls13ExtensionKind.SessionTicket,
        RuntimeRealityTls13ExtensionKind.ApplicationProtocols,
        RuntimeRealityTls13ExtensionKind.StatusRequest,
        RuntimeRealityTls13ExtensionKind.SignatureAlgorithms,
        RuntimeRealityTls13ExtensionKind.SignedCertificateTimestamp,
        RuntimeRealityTls13ExtensionKind.KeyShare,
        RuntimeRealityTls13ExtensionKind.PskKeyExchangeModes,
        RuntimeRealityTls13ExtensionKind.SupportedVersions,
        RuntimeRealityTls13ExtensionKind.CompressCertificate,
        RuntimeRealityTls13ExtensionKind.ApplicationSettings,
        RuntimeRealityTls13ExtensionKind.Grease,
        RuntimeRealityTls13ExtensionKind.Padding
    ];

    private static readonly RuntimeRealityTls13ExtensionKind[] ChromePqNoPaddingExtensions =
    [
        RuntimeRealityTls13ExtensionKind.Grease,
        RuntimeRealityTls13ExtensionKind.ServerName,
        RuntimeRealityTls13ExtensionKind.ExtendedMasterSecret,
        RuntimeRealityTls13ExtensionKind.RenegotiationInfo,
        RuntimeRealityTls13ExtensionKind.SupportedGroups,
        RuntimeRealityTls13ExtensionKind.EcPointFormats,
        RuntimeRealityTls13ExtensionKind.SessionTicket,
        RuntimeRealityTls13ExtensionKind.ApplicationProtocols,
        RuntimeRealityTls13ExtensionKind.StatusRequest,
        RuntimeRealityTls13ExtensionKind.SignatureAlgorithms,
        RuntimeRealityTls13ExtensionKind.SignedCertificateTimestamp,
        RuntimeRealityTls13ExtensionKind.KeyShare,
        RuntimeRealityTls13ExtensionKind.PskKeyExchangeModes,
        RuntimeRealityTls13ExtensionKind.SupportedVersions,
        RuntimeRealityTls13ExtensionKind.CompressCertificate,
        RuntimeRealityTls13ExtensionKind.ApplicationSettings,
        RuntimeRealityTls13ExtensionKind.Grease
    ];

    private static readonly RuntimeRealityTls13ExtensionKind[] Chrome120Extensions =
    [
        RuntimeRealityTls13ExtensionKind.Grease,
        RuntimeRealityTls13ExtensionKind.ServerName,
        RuntimeRealityTls13ExtensionKind.ExtendedMasterSecret,
        RuntimeRealityTls13ExtensionKind.RenegotiationInfo,
        RuntimeRealityTls13ExtensionKind.SupportedGroups,
        RuntimeRealityTls13ExtensionKind.EcPointFormats,
        RuntimeRealityTls13ExtensionKind.SessionTicket,
        RuntimeRealityTls13ExtensionKind.ApplicationProtocols,
        RuntimeRealityTls13ExtensionKind.StatusRequest,
        RuntimeRealityTls13ExtensionKind.SignatureAlgorithms,
        RuntimeRealityTls13ExtensionKind.SignedCertificateTimestamp,
        RuntimeRealityTls13ExtensionKind.KeyShare,
        RuntimeRealityTls13ExtensionKind.PskKeyExchangeModes,
        RuntimeRealityTls13ExtensionKind.SupportedVersions,
        RuntimeRealityTls13ExtensionKind.CompressCertificate,
        RuntimeRealityTls13ExtensionKind.ApplicationSettings,
        RuntimeRealityTls13ExtensionKind.EchGrease,
        RuntimeRealityTls13ExtensionKind.Grease,
        RuntimeRealityTls13ExtensionKind.Padding
    ];

    private static readonly RuntimeRealityTls13ExtensionKind[] Chrome120PqExtensions =
    [
        RuntimeRealityTls13ExtensionKind.Grease,
        RuntimeRealityTls13ExtensionKind.ServerName,
        RuntimeRealityTls13ExtensionKind.ExtendedMasterSecret,
        RuntimeRealityTls13ExtensionKind.RenegotiationInfo,
        RuntimeRealityTls13ExtensionKind.SupportedGroups,
        RuntimeRealityTls13ExtensionKind.EcPointFormats,
        RuntimeRealityTls13ExtensionKind.SessionTicket,
        RuntimeRealityTls13ExtensionKind.ApplicationProtocols,
        RuntimeRealityTls13ExtensionKind.StatusRequest,
        RuntimeRealityTls13ExtensionKind.SignatureAlgorithms,
        RuntimeRealityTls13ExtensionKind.SignedCertificateTimestamp,
        RuntimeRealityTls13ExtensionKind.KeyShare,
        RuntimeRealityTls13ExtensionKind.PskKeyExchangeModes,
        RuntimeRealityTls13ExtensionKind.SupportedVersions,
        RuntimeRealityTls13ExtensionKind.CompressCertificate,
        RuntimeRealityTls13ExtensionKind.ApplicationSettings,
        RuntimeRealityTls13ExtensionKind.EchGrease,
        RuntimeRealityTls13ExtensionKind.Grease
    ];

    private static readonly RuntimeRealityTls13ExtensionKind[] Chrome131Extensions =
    [
        RuntimeRealityTls13ExtensionKind.Grease,
        RuntimeRealityTls13ExtensionKind.ServerName,
        RuntimeRealityTls13ExtensionKind.ExtendedMasterSecret,
        RuntimeRealityTls13ExtensionKind.RenegotiationInfo,
        RuntimeRealityTls13ExtensionKind.SupportedGroups,
        RuntimeRealityTls13ExtensionKind.EcPointFormats,
        RuntimeRealityTls13ExtensionKind.SessionTicket,
        RuntimeRealityTls13ExtensionKind.ApplicationProtocols,
        RuntimeRealityTls13ExtensionKind.StatusRequest,
        RuntimeRealityTls13ExtensionKind.SignatureAlgorithms,
        RuntimeRealityTls13ExtensionKind.SignedCertificateTimestamp,
        RuntimeRealityTls13ExtensionKind.KeyShare,
        RuntimeRealityTls13ExtensionKind.PskKeyExchangeModes,
        RuntimeRealityTls13ExtensionKind.SupportedVersions,
        RuntimeRealityTls13ExtensionKind.CompressCertificate,
        RuntimeRealityTls13ExtensionKind.ApplicationSettings,
        RuntimeRealityTls13ExtensionKind.EchGrease,
        RuntimeRealityTls13ExtensionKind.Grease
    ];

    private static readonly RuntimeRealityTls13ExtensionKind[] Chrome133Extensions =
    [
        RuntimeRealityTls13ExtensionKind.Grease,
        RuntimeRealityTls13ExtensionKind.ServerName,
        RuntimeRealityTls13ExtensionKind.ExtendedMasterSecret,
        RuntimeRealityTls13ExtensionKind.RenegotiationInfo,
        RuntimeRealityTls13ExtensionKind.SupportedGroups,
        RuntimeRealityTls13ExtensionKind.EcPointFormats,
        RuntimeRealityTls13ExtensionKind.SessionTicket,
        RuntimeRealityTls13ExtensionKind.ApplicationProtocols,
        RuntimeRealityTls13ExtensionKind.StatusRequest,
        RuntimeRealityTls13ExtensionKind.SignatureAlgorithms,
        RuntimeRealityTls13ExtensionKind.SignedCertificateTimestamp,
        RuntimeRealityTls13ExtensionKind.KeyShare,
        RuntimeRealityTls13ExtensionKind.PskKeyExchangeModes,
        RuntimeRealityTls13ExtensionKind.SupportedVersions,
        RuntimeRealityTls13ExtensionKind.CompressCertificate,
        RuntimeRealityTls13ExtensionKind.ApplicationSettingsNew,
        RuntimeRealityTls13ExtensionKind.EchGrease,
        RuntimeRealityTls13ExtensionKind.Grease
    ];

    private static readonly RuntimeRealityTls13ExtensionKind[] Firefox148Extensions =
    [
        RuntimeRealityTls13ExtensionKind.ServerName,
        RuntimeRealityTls13ExtensionKind.ExtendedMasterSecret,
        RuntimeRealityTls13ExtensionKind.RenegotiationInfo,
        RuntimeRealityTls13ExtensionKind.SupportedGroups,
        RuntimeRealityTls13ExtensionKind.EcPointFormats,
        RuntimeRealityTls13ExtensionKind.ApplicationProtocols,
        RuntimeRealityTls13ExtensionKind.StatusRequest,
        RuntimeRealityTls13ExtensionKind.DelegatedCredentials,
        RuntimeRealityTls13ExtensionKind.SignedCertificateTimestamp,
        RuntimeRealityTls13ExtensionKind.KeyShare,
        RuntimeRealityTls13ExtensionKind.SupportedVersions,
        RuntimeRealityTls13ExtensionKind.SignatureAlgorithms,
        RuntimeRealityTls13ExtensionKind.RecordSizeLimit,
        RuntimeRealityTls13ExtensionKind.CompressCertificate,
        RuntimeRealityTls13ExtensionKind.EchGrease
    ];

    private static readonly RuntimeRealityTls13ExtensionKind[] Safari26_3Extensions =
    [
        RuntimeRealityTls13ExtensionKind.Grease,
        RuntimeRealityTls13ExtensionKind.ServerName,
        RuntimeRealityTls13ExtensionKind.ExtendedMasterSecret,
        RuntimeRealityTls13ExtensionKind.RenegotiationInfo,
        RuntimeRealityTls13ExtensionKind.SupportedGroups,
        RuntimeRealityTls13ExtensionKind.EcPointFormats,
        RuntimeRealityTls13ExtensionKind.ApplicationProtocols,
        RuntimeRealityTls13ExtensionKind.StatusRequest,
        RuntimeRealityTls13ExtensionKind.SignatureAlgorithms,
        RuntimeRealityTls13ExtensionKind.SignedCertificateTimestamp,
        RuntimeRealityTls13ExtensionKind.KeyShare,
        RuntimeRealityTls13ExtensionKind.PskKeyExchangeModes,
        RuntimeRealityTls13ExtensionKind.SupportedVersions,
        RuntimeRealityTls13ExtensionKind.CompressCertificate,
        RuntimeRealityTls13ExtensionKind.Grease
    ];

    private static readonly RuntimeRealityTls13ExtensionKind[] GolangExtensions =
    [
        RuntimeRealityTls13ExtensionKind.ServerName,
        RuntimeRealityTls13ExtensionKind.EcPointFormats,
        RuntimeRealityTls13ExtensionKind.RenegotiationInfo,
        RuntimeRealityTls13ExtensionKind.ExtendedMasterSecret,
        RuntimeRealityTls13ExtensionKind.SignedCertificateTimestamp,
        RuntimeRealityTls13ExtensionKind.StatusRequest,
        RuntimeRealityTls13ExtensionKind.SupportedGroups,
        RuntimeRealityTls13ExtensionKind.SignatureAlgorithms,
        RuntimeRealityTls13ExtensionKind.SupportedVersions,
        RuntimeRealityTls13ExtensionKind.KeyShare
    ];

    public static RuntimeRealityTls13ClientHelloProfile Resolve(string? fingerprint)
    {
        var normalized = NormalizeFingerprint(fingerprint);
        return normalized switch
        {
            "" or "chrome" or "hellochrome_auto"
                => CreateChrome133Profile(),

            "helloedge_auto" or "edge" or "helloedge_85"
                => CreateEdge85Profile(),

            "helloedge_106"
                => CreateEdge106Profile(),

            "hello360_auto" or "360" or "hello360_7_5"
                => CreateThreeSixty75Profile(),

            "hello360_11_0"
                => CreateThreeSixty11Profile(),

            "helloqq_auto" or "helloqq_11_1" or "qq"
                => CreateQq11Profile(),

            "hellochrome_120"
                => CreateChrome120Profile(),

            "hellochrome_131"
                => CreateChrome131Profile(),

            "hellochrome_58" or "hellochrome_62"
                => CreateChrome58Profile(),

            "hellochrome_70"
                => CreateChrome70Profile(),

            "hellochrome_72"
                => CreateChrome72Profile(),

            "hellochrome_83" or "hellochrome_87"
                => CreateChrome83Profile(),

            "hellochrome_96"
                => CreateChrome96Profile(),

            "hellochrome_100" or "hellochrome_102"
                => CreateChrome100Profile(),

            "hellochrome_106_shuffle"
                => CreateChrome106ShuffledProfile(),

            "hellochrome_100_psk"
                => CreateChrome100PskProfile(),

            "hellochrome_112_psk_shuf"
                => CreateChrome112PskShuffledProfile(),

            "hellochrome_114_padding_psk_shuf"
                => CreateChrome114PaddingPskShuffledProfile(),

            "hellochrome_115_pq"
                => CreateChrome115PqProfile(includePadding: true),

            "hellochrome_115_pq_psk"
                => CreateChrome115PqProfile(includePadding: false),

            "hellochrome_120_pq"
                => CreateChrome120PqProfile(),

            "firefox" or "hellofirefox_auto"
                => CreateFirefox148Profile(),

            "hellofirefox_55" or "hellofirefox_56" or "hellofirefox_63" or "hellofirefox_65" or "hellofirefox_99" or "hellofirefox_102" or "hellofirefox_105" or "hellofirefox_120"
                => CreateFirefoxProfile(),

            "safari" or "hellosafari_auto"
                => CreateSafari26_3Profile(),

            "hellosafari_16_0"
                => CreateSafariProfile(),

            "ios" or "helloios_auto" or "helloios_11_1" or "helloios_12_1" or "helloios_13" or "helloios_14"
                => CreateIosProfile(),

            "android" or "helloandroid_11_okhttp"
                => CreateAndroidProfile(),

            "randomized"
                => RandomizedProfile.Value,

            "randomizednoalpn"
                => RandomizedNoAlpnProfile.Value,

            "hellorandomized"
                => CreateRandomizedProfile(RuntimeTlsRandomizedAlpnMode.Random, RandomNumberGenerator.GetBytes(32)),

            "hellorandomizedalpn"
                => CreateRandomizedProfile(RuntimeTlsRandomizedAlpnMode.Always, RandomNumberGenerator.GetBytes(32)),

            "hellorandomizednoalpn"
                => CreateRandomizedProfile(RuntimeTlsRandomizedAlpnMode.Never, RandomNumberGenerator.GetBytes(32)),

            "random"
                => Resolve(RandomModernFingerprint.Value),

            "hellogolang"
                => CreateGolangProfile(),

            _ => CreateChromeProfile()
        };
    }

    private static RuntimeRealityTls13ClientHelloProfile CreateChromeProfile()
        => CreateChrome133Profile();

    private static RuntimeRealityTls13ClientHelloProfile CreateChrome133Profile()
        => new(
            UseGrease: true,
            CipherSuites: ChromeCipherSuites,
            SupportedGroups: ChromePqSupportedGroups,
            KeyShareGroups: ChromePqKeyShareGroups,
            SupportedVersions: Tls13SupportedVersions,
            SignatureAlgorithms: ChromeSignatureAlgorithms,
            SignatureAlgorithmsCert: ChromeSignatureAlgorithms,
            Extensions: Chrome133Extensions,
            IncludeGreaseKeyShare: true,
            CompressCertificateAlgorithms: BrotliCompressionAlgorithms,
            EchGreaseCandidateAeads: ChromeEchGreaseCandidateAeads,
            EchGreaseCandidatePayloadLengths: ChromeEchGreaseCandidatePayloadLengths,
            ShuffleExtensions: true);

    private static RuntimeRealityTls13ClientHelloProfile CreateChrome120Profile()
        => new(
            UseGrease: true,
            CipherSuites: ChromeCipherSuites,
            SupportedGroups: CommonSupportedGroups,
            KeyShareGroups: Chrome120KeyShareGroups,
            SupportedVersions: Tls13SupportedVersions,
            SignatureAlgorithms: ChromeSignatureAlgorithms,
            SignatureAlgorithmsCert: ChromeSignatureAlgorithms,
            Extensions: Chrome120Extensions,
            IncludeGreaseKeyShare: true,
            UseBoringPadding: true,
            CompressCertificateAlgorithms: BrotliCompressionAlgorithms,
            EchGreaseCandidateAeads: ChromeEchGreaseCandidateAeads,
            EchGreaseCandidatePayloadLengths: ChromeEchGreaseCandidatePayloadLengths,
            ShuffleExtensions: true);

    private static RuntimeRealityTls13ClientHelloProfile CreateEdge85Profile()
        => new(
            UseGrease: true,
            CipherSuites: ChromeCipherSuites,
            SupportedGroups: CommonSupportedGroups,
            KeyShareGroups: ChromeKeyShareGroups,
            SupportedVersions: Tls13And12And11And10SupportedVersions,
            SignatureAlgorithms: ChromeSignatureAlgorithms,
            SignatureAlgorithmsCert: Array.Empty<ushort>(),
            Extensions: Edge85Extensions,
            IncludeGreaseKeyShare: true,
            UseBoringPadding: true,
            CompressCertificateAlgorithms: BrotliCompressionAlgorithms);

    private static RuntimeRealityTls13ClientHelloProfile CreateEdge106Profile()
        => new(
            UseGrease: true,
            CipherSuites: ChromeCipherSuites,
            SupportedGroups: CommonSupportedGroups,
            KeyShareGroups: ChromeKeyShareGroups,
            SupportedVersions: Tls13SupportedVersions,
            SignatureAlgorithms: ChromeSignatureAlgorithms,
            SignatureAlgorithmsCert: Array.Empty<ushort>(),
            Extensions: Edge106Extensions,
            IncludeGreaseKeyShare: true,
            UseBoringPadding: true,
            CompressCertificateAlgorithms: BrotliCompressionAlgorithms);

    private static RuntimeRealityTls13ClientHelloProfile CreateChrome58Profile()
        => new(
            UseGrease: true,
            CipherSuites: Chrome58CipherSuites,
            SupportedGroups: CommonSupportedGroups,
            KeyShareGroups: Array.Empty<ushort>(),
            SupportedVersions: Array.Empty<ushort>(),
            SignatureAlgorithms: ChromeLegacySignatureAlgorithmsWithSha1,
            SignatureAlgorithmsCert: Array.Empty<ushort>(),
            Extensions: Chrome58Extensions,
            UseBoringPadding: true);

    private static RuntimeRealityTls13ClientHelloProfile CreateChrome70Profile()
        => CreateChromeLegacyTls13Profile(
            ChromeLegacyCipherSuitesWith3Des,
            Tls13And12And11And10SupportedVersions,
            ChromeLegacySignatureAlgorithmsWithSha1,
            Chrome70Extensions);

    private static RuntimeRealityTls13ClientHelloProfile CreateChrome72Profile()
        => CreateChromeLegacyTls13Profile(
            ChromeLegacyCipherSuitesWith3Des,
            Tls13And12And11And10SupportedVersions,
            ChromeLegacySignatureAlgorithmsWithSha1,
            Chrome72Extensions);

    private static RuntimeRealityTls13ClientHelloProfile CreateChrome83Profile()
        => CreateChromeLegacyTls13Profile(
            ChromeCipherSuites,
            Tls13And12And11And10SupportedVersions,
            ChromeSignatureAlgorithms,
            Chrome72Extensions);

    private static RuntimeRealityTls13ClientHelloProfile CreateChrome96Profile()
        => CreateChromeLegacyTls13Profile(
            ChromeCipherSuites,
            Tls13And12And11And10SupportedVersions,
            ChromeSignatureAlgorithms,
            Chrome96Extensions);

    private static RuntimeRealityTls13ClientHelloProfile CreateChrome100Profile()
        => CreateChromeLegacyTls13Profile(
            ChromeCipherSuites,
            Tls13SupportedVersions,
            ChromeSignatureAlgorithms,
            Chrome96Extensions);

    private static RuntimeRealityTls13ClientHelloProfile CreateChrome106ShuffledProfile()
        => new(
            UseGrease: true,
            CipherSuites: ChromeCipherSuites,
            SupportedGroups: CommonSupportedGroups,
            KeyShareGroups: ChromeKeyShareGroups,
            SupportedVersions: Tls13SupportedVersions,
            SignatureAlgorithms: ChromeSignatureAlgorithms,
            SignatureAlgorithmsCert: Array.Empty<ushort>(),
            Extensions: Chrome96Extensions,
            IncludeGreaseKeyShare: true,
            CompressCertificateAlgorithms: BrotliCompressionAlgorithms,
            UseBoringPadding: true,
            ShuffleExtensions: true);

    private static RuntimeRealityTls13ClientHelloProfile CreateChrome100PskProfile()
        => new(
            UseGrease: true,
            CipherSuites: ChromeCipherSuites,
            SupportedGroups: CommonSupportedGroups,
            KeyShareGroups: ChromeKeyShareGroups,
            SupportedVersions: Tls13SupportedVersions,
            SignatureAlgorithms: ChromeSignatureAlgorithms,
            SignatureAlgorithmsCert: Array.Empty<ushort>(),
            Extensions: Chrome100PskExtensions,
            IncludeGreaseKeyShare: true,
            CompressCertificateAlgorithms: BrotliCompressionAlgorithms);

    private static RuntimeRealityTls13ClientHelloProfile CreateChrome112PskShuffledProfile()
        => new(
            UseGrease: true,
            CipherSuites: ChromeCipherSuites,
            SupportedGroups: CommonSupportedGroups,
            KeyShareGroups: ChromeKeyShareGroups,
            SupportedVersions: Tls13SupportedVersions,
            SignatureAlgorithms: ChromeSignatureAlgorithms,
            SignatureAlgorithmsCert: Array.Empty<ushort>(),
            Extensions: Chrome100PskExtensions,
            IncludeGreaseKeyShare: true,
            CompressCertificateAlgorithms: BrotliCompressionAlgorithms,
            ShuffleExtensions: true);

    private static RuntimeRealityTls13ClientHelloProfile CreateChrome114PaddingPskShuffledProfile()
        => new(
            UseGrease: true,
            CipherSuites: ChromeCipherSuites,
            SupportedGroups: CommonSupportedGroups,
            KeyShareGroups: ChromeKeyShareGroups,
            SupportedVersions: Tls13SupportedVersions,
            SignatureAlgorithms: ChromeSignatureAlgorithms,
            SignatureAlgorithmsCert: Array.Empty<ushort>(),
            Extensions: Chrome96Extensions,
            IncludeGreaseKeyShare: true,
            CompressCertificateAlgorithms: BrotliCompressionAlgorithms,
            UseBoringPadding: true,
            ShuffleExtensions: true);

    private static RuntimeRealityTls13ClientHelloProfile CreateChromeLegacyTls13Profile(
        IReadOnlyList<ushort> cipherSuites,
        IReadOnlyList<ushort> supportedVersions,
        IReadOnlyList<ushort> signatureAlgorithms,
        IReadOnlyList<RuntimeRealityTls13ExtensionKind> extensions)
        => new(
            UseGrease: true,
            CipherSuites: cipherSuites,
            SupportedGroups: CommonSupportedGroups,
            KeyShareGroups: ChromeKeyShareGroups,
            SupportedVersions: supportedVersions,
            SignatureAlgorithms: signatureAlgorithms,
            SignatureAlgorithmsCert: Array.Empty<ushort>(),
            Extensions: extensions,
            IncludeGreaseKeyShare: true,
            CompressCertificateAlgorithms: BrotliCompressionAlgorithms,
            UseBoringPadding: true);

    private static RuntimeRealityTls13ClientHelloProfile CreateChrome115PqProfile(bool includePadding)
        => new(
            UseGrease: true,
            CipherSuites: ChromeCipherSuites,
            SupportedGroups: ChromeKyberSupportedGroups,
            KeyShareGroups: ChromeKyberKeyShareGroups,
            SupportedVersions: Tls13SupportedVersions,
            SignatureAlgorithms: ChromeSignatureAlgorithms,
            SignatureAlgorithmsCert: Array.Empty<ushort>(),
            Extensions: includePadding ? ChromePqExtensions : ChromePqNoPaddingExtensions,
            IncludeGreaseKeyShare: true,
            CompressCertificateAlgorithms: BrotliCompressionAlgorithms,
            UseBoringPadding: includePadding,
            ShuffleExtensions: true);

    private static RuntimeRealityTls13ClientHelloProfile CreateChrome120PqProfile()
        => new(
            UseGrease: true,
            CipherSuites: ChromeCipherSuites,
            SupportedGroups: ChromeKyberSupportedGroups,
            KeyShareGroups: ChromeKyberKeyShareGroups,
            SupportedVersions: Tls13SupportedVersions,
            SignatureAlgorithms: ChromeSignatureAlgorithms,
            SignatureAlgorithmsCert: ChromeSignatureAlgorithms,
            Extensions: Chrome120PqExtensions,
            IncludeGreaseKeyShare: true,
            CompressCertificateAlgorithms: BrotliCompressionAlgorithms,
            EchGreaseCandidateAeads: ChromeEchGreaseCandidateAeads,
            EchGreaseCandidatePayloadLengths: ChromeEchGreaseCandidatePayloadLengths,
            ShuffleExtensions: true);

    private static RuntimeRealityTls13ClientHelloProfile CreateChrome131Profile()
        => new(
            UseGrease: true,
            CipherSuites: ChromeCipherSuites,
            SupportedGroups: ChromePqSupportedGroups,
            KeyShareGroups: ChromePqKeyShareGroups,
            SupportedVersions: Tls13SupportedVersions,
            SignatureAlgorithms: ChromeSignatureAlgorithms,
            SignatureAlgorithmsCert: ChromeSignatureAlgorithms,
            Extensions: Chrome131Extensions,
            IncludeGreaseKeyShare: true,
            CompressCertificateAlgorithms: BrotliCompressionAlgorithms,
            EchGreaseCandidateAeads: ChromeEchGreaseCandidateAeads,
            EchGreaseCandidatePayloadLengths: ChromeEchGreaseCandidatePayloadLengths,
            ShuffleExtensions: true);

    private static RuntimeRealityTls13ClientHelloProfile CreateFirefoxProfile()
        => new(
            UseGrease: false,
            CipherSuites: FirefoxCipherSuites,
            SupportedGroups: FirefoxSupportedGroups,
            KeyShareGroups: FirefoxKeyShareGroups,
            SupportedVersions: Tls13SupportedVersions,
            SignatureAlgorithms: FirefoxSignatureAlgorithms,
            SignatureAlgorithmsCert: Array.Empty<ushort>(),
            Extensions: FirefoxExtensions,
            RecordSizeLimit: 0x4001,
            DelegatedCredentialSignatureAlgorithms: Firefox148DelegatedCredentialSignatureAlgorithms,
            EchGreaseCandidateAeads: FirefoxEchGreaseCandidateAeads,
            EchGreaseCandidatePayloadLengths: FirefoxEchGreaseCandidatePayloadLengths);

    private static RuntimeRealityTls13ClientHelloProfile CreateFirefox148Profile()
        => new(
            UseGrease: false,
            CipherSuites: Firefox148CipherSuites,
            SupportedGroups: Firefox148SupportedGroups,
            KeyShareGroups: Firefox148KeyShareGroups,
            SupportedVersions: Tls13SupportedVersions,
            SignatureAlgorithms: Firefox148SignatureAlgorithms,
            SignatureAlgorithmsCert: Firefox148SignatureAlgorithms,
            Extensions: Firefox148Extensions,
            ReuseHybridClassicalX25519KeyShare: true,
            RecordSizeLimit: 0x4001,
            DelegatedCredentialSignatureAlgorithms: Firefox148DelegatedCredentialSignatureAlgorithms,
            CompressCertificateAlgorithms: ZlibBrotliZstdCompressionAlgorithms,
            EchGreaseCandidateAeads: FirefoxEchGreaseCandidateAeads,
            EchGreaseCandidatePayloadLengths: FirefoxEchGreaseCandidatePayloadLengths);

    private static RuntimeRealityTls13ClientHelloProfile CreateSafariProfile()
        => new(
            UseGrease: true,
            CipherSuites: SafariCipherSuites,
            SupportedGroups: SafariSupportedGroups,
            KeyShareGroups: SafariKeyShareGroups,
            SupportedVersions: Tls13And12And11And10SupportedVersions,
            SignatureAlgorithms: SafariSignatureAlgorithms,
            SignatureAlgorithmsCert: SafariSignatureAlgorithms,
            Extensions: SafariExtensions,
            CompressCertificateAlgorithms: ZlibCompressionAlgorithms,
            UseBoringPadding: true);

    private static RuntimeRealityTls13ClientHelloProfile CreateSafari26_3Profile()
        => new(
            UseGrease: true,
            CipherSuites: Safari26_3CipherSuites,
            SupportedGroups: Safari26_3SupportedGroups,
            KeyShareGroups: Safari26_3KeyShareGroups,
            SupportedVersions: Tls13SupportedVersions,
            SignatureAlgorithms: Safari26_3SignatureAlgorithms,
            SignatureAlgorithmsCert: Safari26_3SignatureAlgorithms,
            Extensions: Safari26_3Extensions,
            IncludeGreaseKeyShare: true,
            CompressCertificateAlgorithms: ZlibCompressionAlgorithms);

    private static RuntimeRealityTls13ClientHelloProfile CreateIosProfile()
        => new(
            UseGrease: true,
            CipherSuites: Ios14CipherSuites,
            SupportedGroups: SafariSupportedGroups,
            KeyShareGroups: SafariKeyShareGroups,
            SupportedVersions: Tls13And12And11And10SupportedVersions,
            SignatureAlgorithms: SafariSignatureAlgorithms,
            SignatureAlgorithmsCert: Array.Empty<ushort>(),
            Extensions: IosExtensions,
            IncludeGreaseKeyShare: true,
            UseBoringPadding: true);

    private static RuntimeRealityTls13ClientHelloProfile CreateAndroidProfile()
        => new(
            UseGrease: false,
            CipherSuites: AndroidCipherSuites,
            SupportedGroups: CommonSupportedGroups,
            KeyShareGroups: Array.Empty<ushort>(),
            SupportedVersions: Array.Empty<ushort>(),
            SignatureAlgorithms: AndroidSignatureAlgorithms,
            SignatureAlgorithmsCert: Array.Empty<ushort>(),
            Extensions: AndroidExtensions,
            AllowAutomaticApplicationProtocolInjection: false);

    private static RuntimeRealityTls13ClientHelloProfile CreateThreeSixty75Profile()
        => new(
            UseGrease: false,
            CipherSuites: ThreeSixty75CipherSuites,
            SupportedGroups: ThreeSixty75SupportedGroups,
            KeyShareGroups: Array.Empty<ushort>(),
            SupportedVersions: Array.Empty<ushort>(),
            SignatureAlgorithms: ThreeSixty75SignatureAlgorithms,
            SignatureAlgorithmsCert: Array.Empty<ushort>(),
            Extensions: ThreeSixty75Extensions,
            AllowAutomaticApplicationProtocolInjection: false,
            ClientHelloApplicationProtocols: ThreeSixty75ApplicationProtocols);

    private static RuntimeRealityTls13ClientHelloProfile CreateThreeSixty11Profile()
        => new(
            UseGrease: true,
            CipherSuites: ThreeSixty11CipherSuites,
            SupportedGroups: CommonSupportedGroups,
            KeyShareGroups: ChromeKeyShareGroups,
            SupportedVersions: Tls13And12And11And10SupportedVersions,
            SignatureAlgorithms: AndroidSignatureAlgorithms,
            SignatureAlgorithmsCert: Array.Empty<ushort>(),
            Extensions: ThreeSixty11Extensions,
            IncludeGreaseKeyShare: true,
            CompressCertificateAlgorithms: BrotliCompressionAlgorithms,
            UseBoringPadding: true);

    private static RuntimeRealityTls13ClientHelloProfile CreateQq11Profile()
        => new(
            UseGrease: true,
            CipherSuites: ChromeCipherSuites,
            SupportedGroups: CommonSupportedGroups,
            KeyShareGroups: ChromeKeyShareGroups,
            SupportedVersions: Tls13And12And11And10SupportedVersions,
            SignatureAlgorithms: AndroidSignatureAlgorithms,
            SignatureAlgorithmsCert: Array.Empty<ushort>(),
            Extensions: Edge106Extensions,
            IncludeGreaseKeyShare: true,
            CompressCertificateAlgorithms: BrotliCompressionAlgorithms,
            UseBoringPadding: true);

    private static RuntimeRealityTls13ClientHelloProfile CreateGolangProfile()
        => new(
            UseGrease: false,
            CipherSuites: BuildGolangCipherSuites(includeTls13CipherSuites: true),
            SupportedGroups: RuntimeX25519MlKem768.IsSupported
                ? [RuntimeTlsNamedGroups.X25519MLKem768, RuntimeTlsNamedGroups.X25519, RuntimeTlsNamedGroups.Secp256r1, RuntimeTlsNamedGroups.Secp384r1, RuntimeTlsNamedGroups.Secp521r1]
                : [RuntimeTlsNamedGroups.X25519, RuntimeTlsNamedGroups.Secp256r1, RuntimeTlsNamedGroups.Secp384r1, RuntimeTlsNamedGroups.Secp521r1],
            KeyShareGroups: RuntimeX25519MlKem768.IsSupported
                ? [RuntimeTlsNamedGroups.X25519MLKem768, RuntimeTlsNamedGroups.X25519]
                : [RuntimeTlsNamedGroups.X25519],
            SupportedVersions: Tls13SupportedVersions,
            SignatureAlgorithms: GolangSignatureAlgorithms,
            SignatureAlgorithmsCert: Array.Empty<ushort>(),
            Extensions: GolangExtensions,
            ReuseHybridClassicalX25519KeyShare: RuntimeX25519MlKem768.IsSupported,
            UseRandomSessionId: true,
            AllowAutomaticApplicationProtocolInjection: false);

    private static RuntimeRealityTls13ClientHelloProfile CreateRandomizedProfile(
        RuntimeTlsRandomizedAlpnMode alpnMode,
        ReadOnlySpan<byte> seed,
        bool forceTls13 = false)
    {
        var prng = new RuntimeTlsRandomizedProfilePrng(seed);
        var includeAlpn = alpnMode switch
        {
            RuntimeTlsRandomizedAlpnMode.Always => true,
            RuntimeTlsRandomizedAlpnMode.Never => false,
            _ => prng.FlipWeightedCoin(0.7)
        };
        var supportsTls13 = forceTls13 || prng.FlipWeightedCoin(0.4);
        var cipherSuites = BuildRandomizedCipherSuites(prng, supportsTls13);
        var supportedVersions = supportsTls13
            ? (prng.NextBoolean()
                ? Tls13SupportedVersions
                : Tls13And12And11And10SupportedVersions)
            : Array.Empty<ushort>();
        var signatureAlgorithms = BuildRandomizedSignatureAlgorithms(prng, supportsTls13);
        var supportedGroups = BuildRandomizedSupportedGroups(prng, supportsTls13);
        var keyShareGroups = supportsTls13
            ? BuildRandomizedKeyShareGroups(prng)
            : Array.Empty<ushort>();
        var extensions = BuildRandomizedExtensions(prng, includeAlpn, supportsTls13);
        return new(
            UseGrease: false,
            CipherSuites: cipherSuites,
            SupportedGroups: supportedGroups,
            KeyShareGroups: keyShareGroups,
            SupportedVersions: supportedVersions,
            SignatureAlgorithms: signatureAlgorithms,
            SignatureAlgorithmsCert: Array.Empty<ushort>(),
            Extensions: extensions,
            UseRandomSessionId: true,
            AllowAutomaticApplicationProtocolInjection: includeAlpn,
            UseBoringPadding: Array.IndexOf(extensions, RuntimeRealityTls13ExtensionKind.Padding) >= 0);
    }

    private static IReadOnlyList<ushort> BuildRandomizedCipherSuites(
        RuntimeTlsRandomizedProfilePrng prng,
        bool includeTls13CipherSuites)
    {
        ArgumentNullException.ThrowIfNull(prng);

        var cipherSuites = RandomizedBaseCipherSuites.ToArray();
        prng.Shuffle(cipherSuites);

        var combined = new List<ushort>(RandomizedTls13CipherSuites.Length + cipherSuites.Length);
        if (includeTls13CipherSuites)
        {
            var tls13CipherSuites = RandomizedTls13CipherSuites.ToArray();
            prng.Shuffle(tls13CipherSuites);
            combined.AddRange(tls13CipherSuites);
        }

        combined.AddRange(cipherSuites);

        for (var index = 1; index < combined.Count; index++)
        {
            var removalWeight = 0.4 * index / combined.Count;
            if (!prng.FlipWeightedCoin(removalWeight))
            {
                continue;
            }

            combined.RemoveAt(index);
            index--;
        }

        return combined.ToArray();
    }

    private static IReadOnlyList<ushort> BuildRandomizedSupportedGroups(
        RuntimeTlsRandomizedProfilePrng prng,
        bool supportsTls13)
    {
        ArgumentNullException.ThrowIfNull(prng);

        var supportedGroups = new List<ushort>(5);
        if (RuntimeX25519MlKem768.IsSupported &&
            supportsTls13 &&
            prng.FlipWeightedCoin(0.71))
        {
            supportedGroups.Add(RuntimeTlsNamedGroups.X25519MLKem768);
        }

        if (prng.FlipWeightedCoin(0.71) || supportsTls13)
        {
            supportedGroups.Add(RuntimeTlsNamedGroups.X25519);
        }

        supportedGroups.Add(RuntimeTlsNamedGroups.Secp256r1);
        supportedGroups.Add(RuntimeTlsNamedGroups.Secp384r1);
        if (prng.FlipWeightedCoin(0.46))
        {
            supportedGroups.Add(RuntimeTlsNamedGroups.Secp521r1);
        }

        return supportedGroups.ToArray();
    }

    private static IReadOnlyList<ushort> BuildRandomizedKeyShareGroups(RuntimeTlsRandomizedProfilePrng prng)
    {
        ArgumentNullException.ThrowIfNull(prng);

        var keyShareGroups = new List<ushort>(3)
        {
            RuntimeTlsNamedGroups.X25519
        };
        if (prng.FlipWeightedCoin(0.5))
        {
            keyShareGroups.Add(RuntimeTlsNamedGroups.Secp256r1);
        }

        if (RuntimeX25519MlKem768.IsSupported &&
            prng.FlipWeightedCoin(0.5))
        {
            keyShareGroups.Insert(0, RuntimeTlsNamedGroups.X25519MLKem768);
        }

        return keyShareGroups.ToArray();
    }

    private static IReadOnlyList<ushort> BuildRandomizedSignatureAlgorithms(
        RuntimeTlsRandomizedProfilePrng prng,
        bool supportsTls13)
    {
        ArgumentNullException.ThrowIfNull(prng);

        var signatureAlgorithms = new List<ushort>
        {
            0x0403,
            0x0401,
            0x0503,
            0x0501,
            0x0201,
            0x0601
        };
        if (prng.FlipWeightedCoin(0.63))
        {
            signatureAlgorithms.Add(0x0203);
        }

        if (prng.FlipWeightedCoin(0.59))
        {
            signatureAlgorithms.Add(0x0603);
        }

        if (prng.FlipWeightedCoin(0.51) || supportsTls13)
        {
            signatureAlgorithms.Add(0x0804);
        }

        if (signatureAlgorithms.Contains(0x0804) &&
            prng.FlipWeightedCoin(0.9))
        {
            signatureAlgorithms.Add(0x0805);
            signatureAlgorithms.Add(0x0806);
        }

        prng.Shuffle(signatureAlgorithms);
        return signatureAlgorithms.ToArray();
    }

    private static RuntimeRealityTls13ExtensionKind[] BuildRandomizedExtensions(
        RuntimeTlsRandomizedProfilePrng prng,
        bool includeAlpn,
        bool supportsTls13)
    {
        ArgumentNullException.ThrowIfNull(prng);

        var extensions = new List<RuntimeRealityTls13ExtensionKind>
        {
            RuntimeRealityTls13ExtensionKind.ServerName,
            RuntimeRealityTls13ExtensionKind.SessionTicket,
            RuntimeRealityTls13ExtensionKind.SignatureAlgorithms,
            RuntimeRealityTls13ExtensionKind.EcPointFormats,
            RuntimeRealityTls13ExtensionKind.SupportedGroups
        };
        if (includeAlpn)
        {
            extensions.Add(RuntimeRealityTls13ExtensionKind.ApplicationProtocols);
        }

        if (prng.FlipWeightedCoin(0.62) || supportsTls13)
        {
            extensions.Add(RuntimeRealityTls13ExtensionKind.Padding);
        }

        if (prng.FlipWeightedCoin(0.74))
        {
            extensions.Add(RuntimeRealityTls13ExtensionKind.StatusRequest);
        }

        if (prng.FlipWeightedCoin(0.46))
        {
            extensions.Add(RuntimeRealityTls13ExtensionKind.SignedCertificateTimestamp);
        }

        if (prng.FlipWeightedCoin(0.75))
        {
            extensions.Add(RuntimeRealityTls13ExtensionKind.RenegotiationInfo);
        }

        if (prng.FlipWeightedCoin(0.77))
        {
            extensions.Add(RuntimeRealityTls13ExtensionKind.ExtendedMasterSecret);
        }

        if (supportsTls13)
        {
            extensions.Add(RuntimeRealityTls13ExtensionKind.KeyShare);
            extensions.Add(RuntimeRealityTls13ExtensionKind.PskKeyExchangeModes);
            extensions.Add(RuntimeRealityTls13ExtensionKind.SupportedVersions);
        }

        if (supportsTls13 &&
            includeAlpn &&
            prng.FlipWeightedCoin(0.33))
        {
            extensions.Add(RuntimeRealityTls13ExtensionKind.ApplicationSettings);
        }

        prng.Shuffle(extensions);
        return extensions.ToArray();
    }

    private static string CreateRandomModernFingerprint()
        => RandomModernFingerprints[RandomNumberGenerator.GetInt32(RandomModernFingerprints.Length)];

    private static string NormalizeFingerprint(string? value)
        => string.IsNullOrWhiteSpace(value)
            ? string.Empty
            : value.Trim().ToLowerInvariant();

    private static bool PreferAesGcmCipherSuites()
        => AesGcm.IsSupported &&
           ((System.Runtime.Intrinsics.X86.Aes.IsSupported &&
             System.Runtime.Intrinsics.X86.Pclmulqdq.IsSupported &&
             System.Runtime.Intrinsics.X86.Sse41.IsSupported &&
             System.Runtime.Intrinsics.X86.Ssse3.IsSupported) ||
            System.Runtime.Intrinsics.Arm.Aes.IsSupported);

    private static ushort[] BuildGolangCipherSuites(bool includeTls13CipherSuites)
    {
        ushort[] tls12CipherSuites = PreferAesGcmCipherSuites()
            ? [0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC009, 0xC013, 0xC00A, 0xC014]
            : [0xCCA9, 0xCCA8, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xC009, 0xC013, 0xC00A, 0xC014];
        if (!includeTls13CipherSuites)
        {
            return tls12CipherSuites;
        }

        ushort[] tls13CipherSuites = PreferAesGcmCipherSuites()
            ? [0x1301, 0x1302, 0x1303]
            : [0x1303, 0x1301, 0x1302];
        return [.. tls12CipherSuites, .. tls13CipherSuites];
    }

    private enum RuntimeTlsRandomizedAlpnMode
    {
        Always,
        Never,
        Random
    }

    private sealed class RuntimeTlsRandomizedProfilePrng
    {
        private readonly byte[] _seed;
        private readonly byte[] _blockBuffer = new byte[64];

        private ulong _counter;
        private int _offset = 64;

        public RuntimeTlsRandomizedProfilePrng(ReadOnlySpan<byte> seed)
        {
            _seed = seed.ToArray();
        }

        public bool NextBoolean()
            => (NextUInt32() & 1) == 0;

        public bool FlipWeightedCoin(double weight)
        {
            if (weight <= 0)
            {
                return false;
            }

            if (weight >= 1)
            {
                return true;
            }

            return NextDouble() < weight;
        }

        public int NextInt32(int maxExclusive)
        {
            if (maxExclusive <= 1)
            {
                return 0;
            }

            var bound = (uint)maxExclusive;
            var threshold = uint.MaxValue - (uint.MaxValue % bound);
            while (true)
            {
                var value = NextUInt32();
                if (value < threshold)
                {
                    return (int)(value % bound);
                }
            }
        }

        public void Shuffle<T>(IList<T> values)
        {
            ArgumentNullException.ThrowIfNull(values);

            for (var index = values.Count - 1; index > 0; index--)
            {
                var swapIndex = NextInt32(index + 1);
                (values[index], values[swapIndex]) = (values[swapIndex], values[index]);
            }
        }

        private double NextDouble()
            => NextUInt32() / ((double)uint.MaxValue + 1d);

        private uint NextUInt32()
        {
            Span<byte> buffer = stackalloc byte[4];
            Read(buffer);
            return ((uint)buffer[0] << 24) |
                   ((uint)buffer[1] << 16) |
                   ((uint)buffer[2] << 8) |
                   buffer[3];
        }

        private void Read(Span<byte> destination)
        {
            var written = 0;
            while (written < destination.Length)
            {
                if (_offset >= _blockBuffer.Length)
                {
                    FillBlock();
                }

                var count = Math.Min(destination.Length - written, _blockBuffer.Length - _offset);
                _blockBuffer.AsSpan(_offset, count).CopyTo(destination.Slice(written, count));
                _offset += count;
                written += count;
            }
        }

        private void FillBlock()
        {
            var input = new byte[_seed.Length + sizeof(ulong)];
            _seed.CopyTo(input, 0);
            var counterOffset = _seed.Length;
            var counter = _counter;
            for (var index = sizeof(ulong) - 1; index >= 0; index--)
            {
                input[counterOffset + index] = (byte)(counter & 0xFF);
                counter >>= 8;
            }

            if (Shake256.IsSupported)
            {
                var block = Shake256.HashData(input, _blockBuffer.Length);
                block.CopyTo(_blockBuffer, 0);
            }
            else
            {
                var first = SHA256.HashData(input);
                first.CopyTo(_blockBuffer, 0);
                input[counterOffset + sizeof(ulong) - 1] ^= 0xA5;
                var second = SHA256.HashData(input);
                second.CopyTo(_blockBuffer, first.Length);
            }

            _counter++;
            _offset = 0;
        }
    }
}
