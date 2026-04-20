using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class RuntimeHybridMlKemTests
{
    [Fact]
    public void X25519Kyber768Draft00_uses_x25519_prefix_layout_matching_utls()
    {
        if (!RuntimeX25519Kyber768Draft00.IsSupported)
        {
            return;
        }

        using var clientX25519KeyPair = RuntimeX25519.CreateKeyPair();
        using var clientMlKemKeyPair = RuntimeX25519Kyber768Draft00.CreateMlKemKeyPair();
        var clientKeyShare = RuntimeX25519Kyber768Draft00.BuildClientKeyShare(
            clientX25519KeyPair.PublicKey,
            clientMlKemKeyPair.PublicKey);

        Assert.Equal(RuntimeX25519Kyber768Draft00.ClientKeyShareLength, clientKeyShare.Length);
        Assert.Equal(
            clientX25519KeyPair.PublicKey,
            clientKeyShare[..RuntimeX25519.KeyLength]);
        Assert.Equal(
            clientMlKemKeyPair.PublicKey,
            clientKeyShare[RuntimeX25519.KeyLength..]);

        var serverExchange = RuntimeX25519Kyber768Draft00.Encapsulate(clientKeyShare);
        var clientSharedSecret = RuntimeX25519Kyber768Draft00.DeriveSharedSecret(
            clientX25519KeyPair.PrivateKey,
            clientMlKemKeyPair.Key,
            serverExchange.ServerKeyShare);

        Assert.Equal(serverExchange.SharedSecret, clientSharedSecret);
    }

    [Fact]
    public void X25519MlKem768_uses_mlkem_prefix_layout_matching_go_tls()
    {
        if (!RuntimeX25519MlKem768.IsSupported)
        {
            return;
        }

        using var clientX25519KeyPair = RuntimeX25519.CreateKeyPair();
        using var clientMlKemKeyPair = RuntimeX25519MlKem768.CreateMlKemKeyPair();
        var clientKeyShare = RuntimeX25519MlKem768.BuildClientKeyShare(
            clientX25519KeyPair.PublicKey,
            clientMlKemKeyPair.PublicKey);

        Assert.Equal(RuntimeX25519MlKem768.ClientKeyShareLength, clientKeyShare.Length);
        Assert.Equal(
            clientMlKemKeyPair.PublicKey,
            clientKeyShare[..RuntimeX25519MlKem768.MlKemPublicKeyLength]);
        Assert.Equal(
            clientX25519KeyPair.PublicKey,
            clientKeyShare[^RuntimeX25519.KeyLength..]);

        var serverExchange = RuntimeX25519MlKem768.Encapsulate(clientKeyShare);
        var clientSharedSecret = RuntimeX25519MlKem768.DeriveSharedSecret(
            clientX25519KeyPair.PrivateKey,
            clientMlKemKeyPair.Key,
            serverExchange.ServerKeyShare);

        Assert.Equal(serverExchange.SharedSecret, clientSharedSecret);
    }

    [Fact]
    public void Secp256r1MlKem768_roundtrips_shared_secret()
    {
        if (!RuntimeSecp256r1MlKem768.IsSupported)
        {
            return;
        }

        using var clientSecp256r1KeyPair = RuntimeSecp256r1.CreateKeyPair();
        using var clientMlKemKeyPair = RuntimeSecp256r1MlKem768.CreateMlKemKeyPair();
        var clientKeyShare = RuntimeSecp256r1MlKem768.BuildClientKeyShare(
            clientSecp256r1KeyPair.PublicKey,
            clientMlKemKeyPair.PublicKey);

        var serverExchange = RuntimeSecp256r1MlKem768.Encapsulate(clientKeyShare);
        var clientSharedSecret = RuntimeSecp256r1MlKem768.DeriveSharedSecret(
            clientSecp256r1KeyPair.PrivateKey,
            clientMlKemKeyPair.Key,
            serverExchange.ServerKeyShare);

        Assert.Equal(RuntimeSecp256r1MlKem768.ClientKeyShareLength, clientKeyShare.Length);
        Assert.Equal(RuntimeSecp256r1MlKem768.ServerKeyShareLength, serverExchange.ServerKeyShare.Length);
        Assert.Equal(serverExchange.SharedSecret, clientSharedSecret);
    }

    [Fact]
    public void Secp384r1MlKem1024_roundtrips_shared_secret()
    {
        if (!RuntimeSecp384r1MlKem1024.IsSupported)
        {
            return;
        }

        using var clientSecp384r1KeyPair = RuntimeSecp384r1.CreateKeyPair();
        using var clientMlKemKeyPair = RuntimeSecp384r1MlKem1024.CreateMlKemKeyPair();
        var clientKeyShare = RuntimeSecp384r1MlKem1024.BuildClientKeyShare(
            clientSecp384r1KeyPair.PublicKey,
            clientMlKemKeyPair.PublicKey);

        var serverExchange = RuntimeSecp384r1MlKem1024.Encapsulate(clientKeyShare);
        var clientSharedSecret = RuntimeSecp384r1MlKem1024.DeriveSharedSecret(
            clientSecp384r1KeyPair.PrivateKey,
            clientMlKemKeyPair.Key,
            serverExchange.ServerKeyShare);

        Assert.Equal(RuntimeSecp384r1MlKem1024.ClientKeyShareLength, clientKeyShare.Length);
        Assert.Equal(RuntimeSecp384r1MlKem1024.ServerKeyShareLength, serverExchange.ServerKeyShare.Length);
        Assert.Equal(serverExchange.SharedSecret, clientSharedSecret);
    }
}
