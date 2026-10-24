using CliWrap;
using CliWrap.Buffered;

namespace ServiceLib.Manager;

/// <summary>
/// Linux kill switch: an nftables table that only lets traffic leave through the TUN device,
/// to the LAN, or to the active profile's entry server(s). Everything else is rejected, so a
/// stopped core, a TUN restart or a disabled TUN can never expose the real address.
/// The rule set is also installed under /etc and reloaded at boot until the switch is turned off.
/// </summary>
public class KillSwitchManager
{
    private static readonly Lazy<KillSwitchManager> _instance = new(() => new());
    public static KillSwitchManager Instance => _instance.Value;
    private const string _tag = "KillSwitchManager";

    private const string TableName = "v2rayn_killswitch";
    private const string InstalledRuleSetPath = "/etc/v2rayn/killswitch.nft";
    private const string UnitName = "v2rayn-killswitch.service";
    private const string CheckUnitName = "v2rayn-killswitch-check";

    private static readonly string[] _privateV4 =
        ["10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255"];

    private static readonly string[] _privateV6 = ["fc00::/7", "fe80::/10", "ff00::/8"];

    public static bool IsSupported => Utils.IsLinux();

    #region Carrier pinning

    /// <summary>
    /// With the switch on, freezes the entry group of the pinned profile to the pinned member:
    /// a policy group becomes that member, a chain gets it as its first hop.
    /// </summary>
    public static async Task<ProfileItem> ApplyPinAsync(Config config, ProfileItem node)
    {
        var item = config.KillSwitchItem;
        if (item is not { Enabled: true }
            || item.PinnedIndexId.IsNullOrEmpty()
            || item.PinnedForIndexId != node.IndexId)
        {
            return node;
        }

        var pinned = await AppManager.Instance.GetProfileItem(item.PinnedIndexId!);
        if (pinned is null)
        {
            Logging.SaveLog($"{_tag}: pinned carrier {item.PinnedIndexId} no longer exists, entry group stays unpinned");
            return node;
        }

        if (node.ConfigType == EConfigType.PolicyGroup)
        {
            return pinned;
        }
        if (node.ConfigType != EConfigType.ProxyChain)
        {
            return node;
        }

        var children = Utils.String2List(node.GetProtocolExtra().ChildItems) ?? [];
        var first = children.Count > 0 ? await AppManager.Instance.GetProfileItem(children[0]) : null;
        if (first is null || !first.ConfigType.IsGroupType())
        {
            return node;
        }

        children[0] = pinned.IndexId;
        var pinnedChain = JsonUtils.DeepCopy(node)!;
        pinnedChain.SetProtocolExtra(pinnedChain.GetProtocolExtra() with { ChildItems = Utils.List2String(children) });
        return pinnedChain;
    }

    /// <summary>
    /// Picks the carrier to freeze: the alive group member with the lowest observatory delay,
    /// read from the running xray's metrics endpoint. Null when nothing has been probed alive yet.
    /// </summary>
    public static async Task<string?> PickBestCarrierAsync(CoreConfigContext? runningContext)
    {
        if (runningContext is null || runningContext.OutboundTagIndexIds.Count == 0)
        {
            return null;
        }

        var url = $"{Global.HttpProtocol}{Global.Loopback}:{AppManager.Instance.StatePort}/debug/vars";
        var result = await HttpClientHelper.Instance.TryGetAsync(url);
        if (result.IsNullOrEmpty() || JsonUtils.ParseJson(result) is not JsonObject vars
            || vars["observatory"] is not JsonObject observatory)
        {
            return null;
        }

        string? bestTag = null;
        var bestDelay = long.MaxValue;
        foreach (var (tag, status) in observatory)
        {
            if (status?["alive"]?.GetValue<bool>() != true)
            {
                continue;
            }
            var delay = status["delay"]?.GetValue<long>() ?? long.MaxValue;
            if (delay < bestDelay && runningContext.OutboundTagIndexIds.ContainsKey(tag))
            {
                bestDelay = delay;
                bestTag = tag;
            }
        }
        return bestTag is null ? null : runningContext.OutboundTagIndexIds[bestTag];
    }

    #endregion Carrier pinning

    #region Firewall

    /// <summary>
    /// Loads the rule set for the context about to run. Must be called before the cores start.
    /// Returns an error message, or null on success. Without a sudo password nothing is loaded and
    /// the caller must not start the cores (fail closed).
    /// </summary>
    public async Task<string?> ApplyAsync(CoreConfigContext context)
    {
        var entryIps = await ResolveEntryAddressesAsync(context);
        if (entryIps.Count == 0)
        {
            return "Kill switch: no entry server address could be resolved, firewall left unchanged";
        }

        // Always (re)load: the installed file only proves what was written, not that the live
        // table still exists (a `nft flush ruleset` or a firewall reload removes it silently).
        // The load is atomic and idempotent thanks to the delete-table line.
        var ruleSet = BuildRuleSet(entryIps, ResolveDirectDnsAddresses(context.AppConfig));
        var ruleSetPath = Utils.GetBinConfigPath("killswitch.nft");
        await File.WriteAllTextAsync(ruleSetPath, ruleSet);
        return await RunAsRootAsync("killswitch_apply.sh", BuildApplyScript(), ruleSetPath);
    }

    /// <summary>Root script: loads the rule set ($1), installs it for boot and keeps the watchdog timer enabled.</summary>
    public static string BuildApplyScript()
    {
        // Besides the boot-time load, a root timer re-checks the live table every 15 s and reloads
        // it if something (a ruleset flush, another firewall tool) removed it, even while v2rayN
        // is closed. Units are rewritten only when they differ, so updates reach old installs.
        return $$"""
            #!/bin/bash
            set -e
            nft -f "$1"
            install -D -m 644 "$1" {{InstalledRuleSetPath}}

            changed=0
            write_unit() {
              tmp=$(mktemp)
              cat > "$tmp"
              if ! cmp -s "$tmp" "$1"; then install -m 644 "$tmp" "$1"; changed=1; fi
              rm -f "$tmp"
            }
            write_unit /etc/systemd/system/{{UnitName}} <<'EOF'
            [Unit]
            Description=v2rayN kill switch (nftables)
            DefaultDependencies=no
            Before=network-pre.target
            Wants=network-pre.target
            ConditionPathExists={{InstalledRuleSetPath}}

            [Service]
            Type=oneshot
            RemainAfterExit=yes
            ExecStart=/usr/sbin/nft -f {{InstalledRuleSetPath}}

            [Install]
            WantedBy=sysinit.target
            EOF
            write_unit /etc/systemd/system/{{CheckUnitName}}.service <<'EOF'
            [Unit]
            Description=v2rayN kill switch watchdog
            ConditionPathExists={{InstalledRuleSetPath}}

            [Service]
            Type=oneshot
            SyslogLevel=warning
            LogLevelMax=warning
            ExecStart=/bin/sh -c 'nft list table inet {{TableName}} >/dev/null 2>&1 || { echo "kill switch table missing, reloading"; nft -f {{InstalledRuleSetPath}}; }'
            EOF
            write_unit /etc/systemd/system/{{CheckUnitName}}.timer <<'EOF'
            [Unit]
            Description=Re-check the v2rayN kill switch every 15 s

            [Timer]
            OnBootSec=10s
            OnUnitActiveSec=15s
            AccuracySec=1s

            [Install]
            WantedBy=timers.target
            EOF
            if [ "$changed" = 1 ]; then systemctl daemon-reload; fi
            systemctl enable {{UnitName}} >/dev/null 2>&1
            systemctl enable --now {{CheckUnitName}}.timer >/dev/null 2>&1
            """;
    }

    /// <summary>Removes the rule set, its boot-time copy and the watchdog timer. Returns an error message, or null.</summary>
    public async Task<string?> DisableAsync()
    {
        var script = $"""
            #!/bin/bash
            systemctl disable --now {CheckUnitName}.timer >/dev/null 2>&1 || true
            nft delete table inet {TableName} 2>/dev/null || true
            rm -f {InstalledRuleSetPath}
            """;
        return await RunAsRootAsync("killswitch_disable.sh", script, string.Empty);
    }

    private static async Task<string?> RunAsRootAsync(string fileName, string script, string argument)
    {
        if (AppManager.Instance.LinuxSudoPwd.IsNullOrEmpty())
        {
            return "Kill switch: sudo password needed to load the firewall, nothing was started (toggle TUN or the kill switch to enter it)";
        }
        try
        {
            var shFilePath = await FileUtils.CreateLinuxShellFile(fileName, script, true);
            var result = await Cli.Wrap(Global.LinuxBash)
                .WithArguments(["-c", $"sudo -S -p '' bash {shFilePath.AppendQuotes()} {argument.AppendQuotes()}"])
                .WithStandardInputPipe(PipeSource.FromString(AppManager.Instance.LinuxSudoPwd))
                .WithValidation(CommandResultValidation.None)
                .ExecuteBufferedAsync();
            if (result.ExitCode != 0)
            {
                Logging.SaveLog($"{_tag}: {fileName} failed: {result.StandardError}");
                return $"Kill switch: firewall update failed ({result.StandardError.Trim()})";
            }
            return null;
        }
        catch (Exception ex)
        {
            Logging.SaveLog(_tag, ex);
            return $"Kill switch: {ex.Message}";
        }
    }

    /// <summary>The first hop of every path out: the node itself, a chain's first hop, or every member of a group.</summary>
    private static List<ProfileItem> GetEntryNodes(CoreConfigContext context, ProfileItem node, int depth = 0)
    {
        if (depth > 10)
        {
            return [];
        }
        if (!node.ConfigType.IsGroupType())
        {
            return [node];
        }

        var children = (Utils.String2List(node.GetProtocolExtra().ChildItems) ?? [])
            .Select(id => context.AllProxiesMap.GetValueOrDefault(id))
            .OfType<ProfileItem>()
            .ToList();
        if (node.ConfigType == EConfigType.ProxyChain)
        {
            return children.Count > 0 ? GetEntryNodes(context, children[0], depth + 1) : [];
        }
        return children.SelectMany(child => GetEntryNodes(context, child, depth + 1)).ToList();
    }

    private static async Task<HashSet<IPAddress>> ResolveEntryAddressesAsync(CoreConfigContext context)
    {
        var addresses = new HashSet<IPAddress>();
        foreach (var host in GetEntryNodes(context, context.Node).Select(n => n.Address).Where(a => a.IsNotEmpty()).Distinct())
        {
            if (IPAddress.TryParse(host, out var ip))
            {
                addresses.Add(ip);
                continue;
            }
            try
            {
                addresses.UnionWith(await Dns.GetHostAddressesAsync(host));
            }
            catch (Exception ex)
            {
                Logging.SaveLog($"{_tag}: cannot resolve entry {host}: {ex.Message}");
            }
        }
        return addresses;
    }

    /// <summary>
    /// The direct DNS servers (used under TUN to resolve the entry server's name) must stay reachable.
    /// </summary>
    private static List<IPAddress> ResolveDirectDnsAddresses(Config config)
    {
        var result = new List<IPAddress>();
        foreach (var server in (config.SimpleDNSItem?.DirectDNS ?? string.Empty).Split(',', StringSplitOptions.RemoveEmptyEntries))
        {
            var host = Uri.TryCreate(server.Trim(), UriKind.Absolute, out var uri) ? uri.Host : server.Trim();
            if (IPAddress.TryParse(host, out var ip))
            {
                result.Add(ip);
            }
            else if (Global.PredefinedHosts.TryGetValue(host, out var ips))
            {
                result.AddRange(ips.Select(IPAddress.Parse));
            }
        }
        return result;
    }

    public static string BuildRuleSet(IEnumerable<IPAddress> entryIps, IEnumerable<IPAddress> dnsIps)
    {
        var allowed = entryIps.Concat(dnsIps).Distinct().ToList();
        var v4 = allowed.Where(ip => ip.AddressFamily == AddressFamily.InterNetwork).Select(ip => ip.ToString()).Order().ToList();
        var v6 = allowed.Where(ip => ip.AddressFamily == AddressFamily.InterNetworkV6).Select(ip => ip.ToString()).Order().ToList();

        static string Set(string name, string type, List<string> elements) => elements.Count == 0
            ? $"\tset {name} {{ type {type}; }}"
            : $"\tset {name} {{ type {type}; elements = {{ {string.Join(", ", elements)} }} }}";

        var privateV4 = string.Join(", ", _privateV4);
        var privateV6 = string.Join(", ", _privateV6);
        return $$"""
            # Generated by v2rayN. Remove with the kill switch toggle, or: nft delete table inet {{TableName}}
            table inet {{TableName}}
            delete table inet {{TableName}}
            table inet {{TableName}} {
            {{Set("entry4", "ipv4_addr", v4)}}
            {{Set("entry6", "ipv6_addr", v6)}}

            	chain output {
            		type filter hook output priority filter; policy drop;
            		oifname "lo" accept
            		oifname "singbox_tun" accept
            		ip daddr @entry4 accept
            		ip6 daddr @entry6 accept
            		ip daddr { {{privateV4}} } accept
            		ip6 daddr { {{privateV6}} } accept
            		reject with icmpx admin-prohibited
            	}

            	chain forward {
            		type filter hook forward priority filter; policy drop;
            		oifname "singbox_tun" accept
            		ip daddr { {{privateV4}} } accept
            		ip6 daddr { {{privateV6}} } accept
            	}
            }

            """;
    }

    #endregion Firewall
}
