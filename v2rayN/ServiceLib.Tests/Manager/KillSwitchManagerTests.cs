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
    public async Task BuildApplyScript_KeepsWatchdogTimerEnabled()
    {
        var script = KillSwitchManager.BuildApplyScript();

        await script.Should().Contain("nft -f \"$1\"");
        // the watchdog reloads the live table whenever it is missing
        await script.Should().Contain("nft list table inet v2rayn_killswitch >/dev/null 2>&1 || {");
        await script.Should().Contain("OnUnitActiveSec=15s");
        await script.Should().Contain("systemctl enable --now v2rayn-killswitch-check.timer");
    }

    [Test]
    public async Task GetCarrier_ManualWinsOnlyWhileAutoEntryIsOff()
    {
        var item = new KillSwitchItem
        {
            Enabled = true,
            ManualCarriers = new() { ["chain"] = "manual" },
            FrozenCarriers = new() { ["chain"] = "frozen" },
        };

        await KillSwitchManager.GetCarrier(item, "chain").Should().BeEqualTo(("frozen", KillSwitchManager.ECarrierMode.Frozen));

        item.AutoEntry = false;
        await KillSwitchManager.GetCarrier(item, "chain").Should().BeEqualTo(("manual", KillSwitchManager.ECarrierMode.Manual));
    }

    [Test]
    public async Task GetCarrier_FrozenOnlyWhileSwitchIsOn_ManualAlways()
    {
        var item = new KillSwitchItem
        {
            Enabled = false,
            AutoEntry = false,
            ManualCarriers = new() { ["a"] = "manual" },
            FrozenCarriers = new() { ["b"] = "frozen" },
        };

        await KillSwitchManager.GetCarrier(item, "a").Should().BeEqualTo(("manual", KillSwitchManager.ECarrierMode.Manual));
        await KillSwitchManager.GetCarrier(item, "b").Should().BeEqualTo(((string?)null, KillSwitchManager.ECarrierMode.None));
    }

    [Test]
    public async Task MigrateLegacyPin_MovesSinglePinIntoFrozenMap()
    {
        var item = new KillSwitchItem { Enabled = true, PinnedIndexId = "carrier", PinnedForIndexId = "chain" };

        KillSwitchManager.MigrateLegacyPin(item);

        await item.FrozenCarriers!["chain"].Should().BeEqualTo("carrier");
        await item.PinnedIndexId.Should().BeNull();
        await item.PinnedForIndexId.Should().BeNull();
    }

    [Test]
    public async Task BuildRuleSet_EmptyFamily_RendersSetWithoutElements()
    {
        var ruleSet = KillSwitchManager.BuildRuleSet([IPAddress.Parse("203.0.113.7")], []);

        await ruleSet.Should().Contain("set entry6 { type ipv6_addr; }");
    }
}
