using System.Reflection;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class RuntimeRealitySpiderTests
{
    [Fact]
    public void PickSpiderRange_matches_xray_core_exclusive_upper_bound()
    {
        var pickSpiderRange = CreatePickSpiderRangeDelegate();
        var exactUpperBoundRange = new long[] { 5, 6 };
        var swappedRange = new long[] { 6, 5 };

        for (var attempt = 0; attempt < 32; attempt++)
        {
            Assert.Equal(5, pickSpiderRange(exactUpperBoundRange, 0, 1));
            Assert.Equal(5, pickSpiderRange(swappedRange, 0, 1));
        }
    }

    private static Func<IReadOnlyList<long>, int, int, long> CreatePickSpiderRangeDelegate()
    {
        var method = typeof(RuntimeRealitySpider).GetMethod(
            "PickSpiderRange",
            BindingFlags.Static | BindingFlags.NonPublic);
        Assert.NotNull(method);
        return method!.CreateDelegate<Func<IReadOnlyList<long>, int, int, long>>();
    }
}
