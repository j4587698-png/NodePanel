using NodePanel.Core.Protocol;

namespace NodePanel.Core.Tests;

public sealed class VmessHandshakeDrainerTests
{
    private const int DrainFoundationBytes = 16 + 38;

    [Fact]
    public void GoMathRandom_matches_go_math_rand_sequence_for_seed_1()
    {
        var random = new GoMathRandom(1);

        Assert.Equal(1801, random.NextInt(3266));
        Assert.Equal(15, random.NextInt(64));
        Assert.Equal(7, random.NextInt(10));
        Assert.Equal(4037200794235010051L, random.NextInt63());
    }

    [Fact]
    public void GoMathRandom_matches_go_math_rand_sequence_for_negative_seed()
    {
        var random = new GoMathRandom(unchecked((long)0xFEDCBA9876543210UL));

        Assert.Equal(1629, random.NextInt(3266));
        Assert.Equal(10, random.NextInt(64));
        Assert.Equal(6, random.NextInt(10));
        Assert.Equal(1178902812443979950L, random.NextInt63());
    }

    [Fact]
    public void DeriveDeterministicDrainParameters_uses_go_compatible_signed_behavior_seed()
    {
        var result = VmessHandshakeDrainer.DeriveDeterministicDrainParameters(0xFEDCBA9876543210UL);

        Assert.Equal(1629, result.BaseDrainBytes);
        Assert.Equal(11, result.RandomDrainMax);
    }

    [Fact]
    public void Roll_matches_xray_dice_and_does_not_advance_rng_when_max_is_one()
    {
        var random = new GoMathRandom(1);

        Assert.Equal(0, GoMathRandom.Roll(random, 1));
        Assert.Equal(1801, random.NextInt(3266));
        Assert.Equal(15, random.NextInt(64));
    }

    [Fact]
    public async Task Create_uses_package_level_roll_for_random_drain_bytes()
    {
        var recordedRandomDrainMax = -1;
        var drainer = VmessHandshakeDrainer.Create(
            0xFEDCBA9876543210UL,
            randomDrainMax =>
            {
                recordedRandomDrainMax = randomDrainMax;
                return 7;
            });

        await using var stream = new MemoryStream(new byte[DrainFoundationBytes + 1629 + 7], writable: false);

        Assert.True(await drainer.DrainAsync(stream, CancellationToken.None));
        Assert.Equal(11, recordedRandomDrainMax);
        Assert.Equal(DrainFoundationBytes + 1629 + 7, stream.Position);
    }
}
