# v2rayN fork: WireGuard chains, kill switch and entry control

This fork of [2dust/v2rayN](https://github.com/2dust/v2rayN) lives on the
`wg-chain-loopback` branch. It is built for one setup: **a WireGuard exit reached
through a v2ray/xray carrier**, on networks where WireGuard itself is blocked by DPI.
Observers only ever see the carrier; websites only ever see the WireGuard exit.

```
apps ─▶ TUN (sing-box) ─▶ xray ─▶ WireGuard ─▶ loopback ─▶ carrier group (best entry) ─▶ internet
                                      ▲                                                   │
                                      └──────────── exit IP seen by websites ◀────────────┘
```

Everything new is Linux-first. The kill switch is Linux only (nftables); the rest is
platform independent. The fork tracks upstream `master` and merges it regularly.

## Contents

- [What the fork adds](#what-the-fork-adds)
- [Status bar](#status-bar)
- [Entry control](#entry-control)
- [Kill switch](#kill-switch)
- [Server list](#server-list)
- [Setting up a WireGuard chain](#setting-up-a-wireguard-chain)
- [Build and install (Linux)](#build-and-install-linux)
- [Troubleshooting](#troubleshooting)
- [Change log](#change-log)

## What the fork adds

| Area | Change |
|---|---|
| WireGuard chains | A chain `group → WireGuard` builds **one** WireGuard outbound that dials through an xray `loopback` into the group's balancer. Stock v2rayN cloned the WireGuard peer once per group member, so one identity roamed between many sockets and broke. |
| Balancer fallback | The loopback balancer gets `fallbackTag` = first group member. Before the first observatory round the balancer has no pick, and xray silently routed WireGuard into itself. |
| TUN | xray is restarted once the TUN device is up, so carrier sockets are not created before TUN routing exists. |
| Group members | Members that xray refuses (VLESS/Trojan without TLS to a public address) are skipped instead of stopping the core. |
| Kill switch | nftables firewall with a status-bar toggle, survives reboots, re-checked every 15 s by a root watchdog timer. |
| Entry control | Per-chain entry (carrier) server: manual, auto (frozen) or auto + failover. |
| Status bar | Entry and exit lines showing which server you enter through and which exit (and IP) websites see. |
| Server list | Pin servers to the top; "Use as entry server for the active chain". |
| Stability | Core load/stop are serialized, so a reload racing app exit can no longer orphan an xray process. |

## Status bar

```
Local:[mixed:10808]  Enable Tun [●]  Kill switch [●]  Entry [●] [Auto + failover ▾]  …
                                              Entry: ❄ failover 203.0.113.7 · NL server
                                              Exit: 🇺🇸(US) 198.51.100.20 · ⛓ Best → us-exit
```

- **Entry line**: the server traffic enters through, prefixed with how it was chosen:
  `📌 manual`, `❄ frozen`, `❄ failover` or `auto` (the one the balancer currently rates
  best; refreshed every 30 s). The address comes first and the remark last, so
  right-to-left remarks cannot reorder the line.
- **Exit line**: the exit IP and the profile it leaves through. The IP comes from the
  connection check after each reload, which uses **Settings → Option Setting → v2rayN
  settings → Current connection info test URL**. Leave that empty and no lookup is made
  (the line then says `IP lookup off`). For WireGuard exits pick
  `https://api-ipv4.ip.sb/geoip`; the lookup goes through the tunnel. Click either line to
  re-run the check.

## Entry control

The **Entry** toggle and its dropdown decide how a chain or policy group picks its
entry (carrier) server. They are independent of the kill switch, which only owns the
firewall.

| Entry toggle | Mode | Entry server |
|---|---|---|
| Off | – | the balancer tests carriers and switches live (stock behaviour) |
| On | **Manual** | the server picked for that chain; a chain without a pick uses its frozen best |
| On | **Auto (frozen)** | the best carrier is frozen per chain and stays until you change it |
| On | **Auto + failover** | as frozen, but if the chain fails every check for 1 minute, a fresh best is frozen automatically |

Details:

- Freezing replaces the chain's carrier group with the one chosen server *before* the
  xray config is written. xray never sees the other carriers and the kill switch only
  allows that one address.
- Each chain keeps its own entry. A chain started without one reuses an entry already
  frozen for another chain on the **same carrier group** (no retest). Otherwise it runs
  the balancer until the first observatory round, freezes the best alive carrier and
  reloads.
- Turning Entry off clears all frozen entries, so turning it back on picks fresh ones.
  Manual picks are kept.
- **Failover** checks the chain every 15 s through the local SOCKS port. After a minute
  of failures the dead carrier is forgotten for every chain using it and a new best is
  frozen. With the kill switch on, the firewall stays up throughout; during the few
  seconds of re-picking it allows the whole carrier group.
- Right-click a server → **Use as entry server for the active chain** sets a manual
  entry for the active chain and switches the mode to Manual.

Settings live in `guiNConfig.json` → `KillSwitchItem`:
`EntryControl`, `EntryMode` (0 manual, 1 frozen, 2 failover), `ManualCarriers` and
`FrozenCarriers` (chain IndexId → carrier IndexId). Settings of older fork builds
(`AutoEntry`, `PinnedIndexId`/`PinnedForIndexId`) are migrated on load.

## Kill switch

Linux only. Toggle **Kill switch** in the status bar (needs the sudo password, like TUN).

- An nftables table `inet v2rayn_killswitch` drops all output and forwarded traffic
  except: loopback, the `singbox_tun` device, private/LAN ranges, the active profile's
  entry server address(es) and the Direct DNS server addresses.
- It is reloaded **before** the cores start on every (re)load. If it cannot be loaded,
  no core is started (fail closed). After a restart of v2rayN the cores only start once
  the sudo password has been entered (toggle TUN or the kill switch).
- The rule set is installed to `/etc/v2rayn/killswitch.nft` and loaded at boot by
  `v2rayn-killswitch.service`, so the machine stays protected while v2rayN is closed.
- `v2rayn-killswitch-check.timer` (root, every 15 s) reloads the table if anything
  (a ruleset flush, another firewall tool) removed it.
- Turning the switch off removes the table, the boot copy and the timer.

Emergency manual off (e.g. when the GUI will not start):

```bash
sudo systemctl disable --now v2rayn-killswitch-check.timer
sudo nft delete table inet v2rayn_killswitch
sudo rm -f /etc/v2rayn/killswitch.nft
```

Then set `"Enabled": false` under `KillSwitchItem` in
`~/.local/share/v2rayN/guiConfigs/guiNConfig.json` while v2rayN is closed, or switch the
toggle off in the GUI, otherwise the next start loads the firewall again.

## Server list

- **Pin / unpin at top** (right-click): pinned servers are listed first in every view
  and marked 📌 (`UiItem.PinnedIndexIds`).
- **Use as entry server for the active chain**: see [Entry control](#entry-control).

## Setting up a WireGuard chain

1. Add the WireGuard server as a normal profile (address, keys, PSK, MTU).
   Through a carrier, use a low MTU: **1100** is safe over hysteria2 carriers, which drop
   UDP datagrams above ~1200 bytes (small requests work, TLS handshakes silently fail).
2. Create a **policy group** (LeastPing) with the carriers, or one per subscription with
   dynamic members and a parent group over them.
3. Create a **proxy chain**: first the group, then the WireGuard profile. Set its core
   type to **Xray**.
4. Activate the chain, enable TUN, then optionally the kill switch and Entry control.

Never run a second client with the same WireGuard key at the same time: the server
roams the peer between both and both break.

## Build and install (Linux)

Requires the .NET SDK from `global.json`.

```bash
cd v2rayN
dotnet test ServiceLib.Tests
dotnet publish ./v2rayN.Desktop/v2rayN.Desktop.csproj -c Release -r linux-x64 \
  -p:SelfContained=true -o ../build/linux-64
```

Install over an existing `/opt/v2rayN` (from the official package) while v2rayN is
closed, replacing the binary atomically:

```bash
sudo cp ../build/linux-64/v2rayN /opt/v2rayN/v2rayN.new
sudo mv /opt/v2rayN/v2rayN.new /opt/v2rayN/v2rayN
```

If v2rayN was installed from a distro package, hold it (`sudo apt-mark hold v2rayn`) and
remove "v2rayN" from the in-app update targets, so neither overwrites the fork.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| TUN on, nothing loads, log shows `balancing strategy returns empty tag` → `default route` | Old build without the balancer fallback; WireGuard looped into itself. |
| Chain works without TUN, fails with it | Old build without the post-TUN restart; or an orphaned xray using the same WireGuard key (`pgrep -af 'xray run -c config.json'`). |
| `Kill switch: sudo password needed…, nothing was started` | Expected after a restart: toggle TUN or the kill switch to enter the password. |
| `cannot resolve entry <host>` in the log | The carrier's hostname does not resolve. If it is NXDOMAIN everywhere the server is gone; it is simply left out of the firewall. |
| sing-box log full of `process DNS packet: tls: first record does not look like a TLS handshake` | DNS-over-HTTPS to the Direct DNS server is being tampered with. Set **Direct DNS** to a plain address such as `223.5.5.5`. |
| Connection drops every minute | A subscription with a 1-minute auto-update interval triggers a reload each time. Set the interval to 0 (manual) or 60. |
| In-app core update of xray fails with "text file busy" | Another process runs the same xray binary. Replace it with copy + rename instead. |
| Exit line says `IP lookup off` | The connection info test URL is empty; see [Status bar](#status-bar). |

## Change log

Commits on `wg-chain-loopback` on top of upstream 7.25.6:

| Commit | Change |
|---|---|
| `b41462f` | Chain WireGuard through a policy group via loopback instead of clones |
| `b522419` | Restart xray after TUN comes up when a WireGuard chain rides a loopback |
| `1109fde` | Give the loopback balancer a fallback so WireGuard never routes into itself |
| `ccd5e74` | Linux kill switch with a frozen entry carrier |
| `e9f8a51` | Kill switch: always reload the live firewall before starting cores |
| `3bdaad2` | Kill switch: root watchdog timer reloads the firewall if it disappears |
| `43c06f3` | Pin servers to the top; pick the entry carrier by hand |
| `ad40473` | Serialize core load/stop; ignore reloads once the app is exiting |
| `7a4c495` | Per-chain entry carriers; entry/exit lines in the status bar |
| `79d05b3`, `108dc8f` | Status bar: right-to-left safe lines; respect an empty IP lookup URL |
| `b6d080f` | Entry toggle with mode dropdown: manual, auto (frozen), auto + failover |
| `36daf67` | Merge upstream `master` |
