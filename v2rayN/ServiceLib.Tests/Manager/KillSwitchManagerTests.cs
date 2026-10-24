using System.Net;

namespace ServiceLib.Tests.Manager;

public class KillSwitchManagerTests
{
    [Test]
    public async Task BuildRuleSet_AllowsOnlyTunLanAndEntries()
    {
        var ruleSet = KillSwitchManager.BuildRuleSet(
            [IPAddress.Parse("203.0.113.7"), IPAddress.Parse("2001:db8::1")],
            [IPAddress.Parse("223.5.5.5")]);

        // replaced atomically, default deny
        await ruleSet.Should().Contain("delete table inet v2rayn_killswitch");
        await ruleSet.Should().Contain("type filter hook output priority filter; policy drop;");
        await ruleSet.Should().Contain("type filter hook forward priority filter; policy drop;");

        await ruleSet.Should().Contain("oifname \"singbox_tun\" accept");
        await ruleSet.Should().Contain("elements = { 203.0.113.7, 223.5.5.5 }");
        await ruleSet.Should().Contain("elements = { 2001:db8::1 }");
        await ruleSet.Should().Contain("192.168.0.0/16");
    }

    [Test]
    public async Task BuildRuleSet_EmptyFamily_RendersSetWithoutElements()
    {
        var ruleSet = KillSwitchManager.BuildRuleSet([IPAddress.Parse("203.0.113.7")], []);

        await ruleSet.Should().Contain("set entry6 { type ipv6_addr; }");
    }
}
