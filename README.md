# beaconwatch

Passive C2 beaconing detector for Linux. Monitors outbound network connections per-process and uses statistical analysis to detect command-and-control beaconing patterns — processes that connect to the same destination at suspiciously regular intervals.

**Author:** https://github.com/dilates

---

## How it works

Real C2 malware "checks in" with its command server at regular intervals — every 60 seconds, every 5 minutes, every hour — sometimes with small jitter added to avoid naive detection. This regularity is a statistical fingerprint that's very different from normal application traffic (which is bursty, user-driven, and irregular).

beaconwatch:

1. **Passively observes** outbound connection events from the kernel's conntrack subsystem (no packet inspection, no traffic interception beyond metadata)
2. **Groups connections** by `(process, destination)` into flows
3. **Applies statistical tests** to the inter-connection-time distribution per flow:
   - **Coefficient of Variation (CV)** = stdev / mean — the primary signal; C2 beacons typically have CV < 0.15 even with jitter, while human/application traffic has CV > 0.5
   - **Autocorrelation** at lags 1–5 — detects periodicity even in noisier signals
   - **FFT-based period estimation** — for longer-running flows with enough samples
   - **Median Absolute Deviation (MAD)** — robust against one-off outliers like laptop suspension
4. **Scores each flow** 0–100, classifying as `benign / suspicious / likely_beacon / high_confidence_beacon`
5. **Alerts** via desktop notifications or webhook when a flow escalates

This tool does **not** decrypt or inspect packet contents — it only uses connection metadata (timestamps, source process, destination IP:port, protocol, byte counts from conntrack). This makes it:
- Lightweight (no BPF/eBPF, no raw sockets beyond conntrack)
- Legal to run anywhere (no interception)
- **Effective even against fully encrypted C2** — encryption hides payload but not timing

---

## Requirements

- Linux (conntrack netlink support)
- Python 3.11+
- Root or `CAP_NET_ADMIN` (for conntrack events)
- Either:
  - `pyroute2` (preferred, direct netlink) — `pip install pyroute2`
  - `conntrack-tools` (fallback subprocess) — `apt install conntrack-tools`

### Install

```bash
pip install beaconwatch
# or from source:
git clone https://github.com/dilates/beaconwatch
cd beaconwatch
pip install -e .
```

---

## Quick start

```bash
# Start the daemon (requires root)
sudo beaconwatch daemon --foreground

# In another terminal: open the TUI
beaconwatch tui

# Or just list suspicious flows
beaconwatch list

# Show details for a specific flow
beaconwatch show <flow-id>

# Check overall status
beaconwatch status
```

---

## Running as a systemd service

Copy the unit file from `install/beaconwatch.service` to `/etc/systemd/system/`:

```bash
sudo cp install/beaconwatch.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now beaconwatch
sudo journalctl -u beaconwatch -f
```

To run without root using `CAP_NET_ADMIN`:

```bash
sudo useradd -r -s /bin/false beaconwatch
sudo mkdir -p /var/lib/beaconwatch
sudo chown beaconwatch: /var/lib/beaconwatch
sudo setcap cap_net_admin+ep $(which beaconwatch)
# Edit /etc/systemd/system/beaconwatch.service: set User=beaconwatch, AmbientCapabilities=CAP_NET_ADMIN
```

---

## CLI reference

```
beaconwatch [OPTIONS] COMMAND

Commands:
  daemon [--foreground]              Run the capture daemon
  tui                                Launch interactive TUI
  list [--min-classification LEVEL] [--limit N]
  show FLOW_ID                       Detailed flow view with interval histogram
  allowlist list / add / remove / suggest
  alerts [--unacknowledged]
  ack ALERT_ID
  status
  --version
```

### Allowlist management

Common false positives (NTP, package managers, browser telemetry) can be allowlisted. Use `suggest` to find candidates:

```bash
beaconwatch allowlist suggest
beaconwatch allowlist add --process /usr/lib/systemd/systemd-timesyncd --dst-port 123 --reason "NTP time sync"
beaconwatch allowlist list
beaconwatch allowlist remove <id>
```

---

## TUI

The TUI reads from the SQLite database every 3 seconds (daemon writes in WAL mode — concurrent access is safe):

```
┌─ beaconwatch ─────────────────────────────────────────────────────────┐
│ ● running   Flows: 47   Connections (24h): 12,403                      │
├───────────────────────────────────────────────────────────────────────┤
│ Score  Classification      Process          Destination       Interval │
│ ─────────────────────────────────────────────────────────────────── │
│  87    HIGH CONFIDENCE     agent.sh         203.0.113.42:443  60.0s±0s│
│  52    LIKELY BEACON       suspicious.bin   198.51.100.7:8080 300s±8s │
│  18    SUSPICIOUS          curl             142.250.x.x:443   irregular│
│   5    benign              systemd-timesync pool.ntp.org:123  3600s   │
├───────────────────────────────────────────────────────────────────────┤
│ [Enter] details  [A]llowlist  [R]efresh  [Q]uit                       │
└───────────────────────────────────────────────────────────────────────┘
```

Keybindings: `Enter` = detail modal, `A` = quick allowlist, `R` = refresh, `Q` = quit.

---

## Architecture

```
Kernel conntrack → ConntrackMonitor → BeaconwatchDaemon → FlowTracker
                                                        → IntervalStats (CV, autocorr, FFT)
                                                        → score_flow (0–100)
                                                        → SQLite (WAL)
                                                        → Alerts (desktop / webhook)

TUI / CLI ──────────────────────────────────────────→ SQLite (read-only)
```

The daemon and TUI communicate exclusively through the SQLite database file. WAL (Write-Ahead Logging) mode allows the daemon to write while the TUI reads concurrently — no IPC, no sockets, no shared memory needed.

**Conntrack backends** (auto-selected):
1. **pyroute2/netlink** (preferred): direct kernel netlink socket, lowest latency
2. **conntrack subprocess** (fallback): spawns `conntrack -E`, parses text output

---

## Scoring algorithm

| Factor | Points | Condition |
|--------|--------|-----------|
| CV < 0.05 | +50 | Near-perfect periodicity |
| CV < 0.15 | +35 | High regularity (with jitter) |
| CV < 0.30 | +15 | Moderate regularity |
| Autocorrelation > 0.7 | +15 | Strong periodic signal |
| Interval 30s–1h | +10 | Classic C2 sleep range |
| Interval < 5s | +10 | Aggressive keepalive/beacon |
| Common C2 port (443/80/8080) | +5 | Blending with normal traffic |
| Unusual port | +10 | Non-standard port on public IP |
| Suspicious path (/tmp, /dev/shm, dotfiles) | +20 | Malware often runs from here |
| Unknown process | +10 | Can't identify the executable |
| Allowlisted | -30 | User-approved known-good |
| Sample count < 5 | ×0.3 | Insufficient data |
| Sample count 5–15 | ×0.7 | Moderate confidence |
| Sample count ≥ 16 | ×1.0 | Full confidence |

**Classifications:**
- `benign` (< 20): Normal traffic
- `suspicious` (20–44): Worth watching
- `likely_beacon` (45–69): Probable C2 beaconing
- `high_confidence_beacon` (≥ 70): Strong statistical evidence of C2

---

## False positives

Common benign processes that beacon regularly:

| Process | Behavior | Why it's benign |
|---------|----------|-----------------|
| `systemd-timesyncd`, `chronyd` | NTP sync every ~1024s | Time synchronization |
| `packagekitd`, `snapd`, `flatpak` | Periodic update checks | Package management |
| `NetworkManager` | Connectivity checks | Network probing |
| Browser sync | Background telemetry | Vendor telemetry |
| VPN clients | Keepalive packets | Connection maintenance |

Use `beaconwatch allowlist suggest` to find these in your environment and add them to the allowlist.

---

## Limitations

- **Cannot see packet content**: This tool only uses timing metadata. It cannot inspect payload.
- **Evasion by randomization**: Malware that uses truly random (high-CV) sleep intervals avoids timing-based detection — but this also makes the malware less reliable for the attacker (randomization defeats command delivery guarantees). In practice, most C2 frameworks use bounded jitter (±10–20%) for reliability, which beaconwatch detects.
- **Requires conntrack**: The tool relies on kernel connection tracking. If conntrack is disabled or the destination is a raw socket, events may be missed.
- **Process resolution is best-effort**: The `/proc` walk for PID→process mapping is inherently racy (process may exit between connection event and resolution). Failed resolutions are still tracked under "unknown".
- **IPv6**: Supported via /proc/net/tcp6 and /proc/net/udp6.
- **UDP**: Tracked but conntrack's UDP tracking is stateless — "closed" events may not fire. Connection counts still accumulate.

---

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

Tests cover: perfect beacon, jittered beacon, Poisson (random) traffic, edge cases (0/1/2 samples, outliers), scoring thresholds, and a full pipeline test against `tests/fixtures/sample_connections.json`.
