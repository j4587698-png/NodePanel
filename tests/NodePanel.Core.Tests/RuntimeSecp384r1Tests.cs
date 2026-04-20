using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class RuntimeSecp384r1Tests
{
    [Fact]
    public void DeriveSharedSecret_is_symmetric_between_two_keypairs()
    {
        using var client = RuntimeSecp384r1.CreateKeyPair();
        using var server = RuntimeSecp384r1.CreateKeyPair();

        var clientSharedSecret = RuntimeSecp384r1.DeriveSharedSecret(client.PrivateKey, server.PublicKey);
        var serverSharedSecret = RuntimeSecp384r1.DeriveSharedSecret(server.PrivateKey, client.PublicKey);

        Assert.Equal(RuntimeSecp384r1.PrivateKeyLength, clientSharedSecret.Length);
        Assert.Equal(clientSharedSecret, serverSharedSecret);
    }

    [Fact]
    public void CreateKeyPair_emits_uncompressed_tls_ec_point()
    {
        using var keyPair = RuntimeSecp384r1.CreateKeyPair();

        Assert.Equal(RuntimeSecp384r1.PrivateKeyLength, keyPair.PrivateKey.Length);
        Assert.Equal(RuntimeSecp384r1.PublicKeyLength, keyPair.PublicKey.Length);
        Assert.Equal(0x04, keyPair.PublicKey[0]);
    }
}
