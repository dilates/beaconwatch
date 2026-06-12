"""Command-line interface — all beaconwatch subcommands."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from . import __url__, __version__


# ── Formatting helpers ────────────────────────────────────────────────────────

_CLASSIFICATION_COLORS = {
    "high_confidence_beacon": "bold red",
    "likely_beacon": "red",
    "suspicious": "yellow",
    "benign": "dim",
}

_CLASSIFICATION_LABELS = {
    "high_confidence_beacon": "HIGH CONFIDENCE",
    "likely_beacon": "LIKELY BEACON",
    "suspicious": "SUSPICIOUS",
    "benign": "benign",
}


def _rich_console():
    from rich.console import Console
    return Console()


def _format_interval(seconds: float | None) -> str:
    if seconds is None or seconds <= 0:
        return "—"
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{seconds / 60:.1f}m"
    else:
        return f"{seconds / 3600:.1f}h"


def _format_interval_with_jitter(mean: float | None, cv: float | None) -> str:
    if mean is None or mean <= 0:
        return "irregular"
    base = _format_interval(mean)
    if cv is not None and mean > 0:
        jitter_s = cv * mean
        return f"{base}±{_format_interval(jitter_s)}"
    return base


# ── Subcommand implementations ────────────────────────────────────────────────

def _cmd_daemon(args: argparse.Namespace, config) -> None:
    import logging as _logging
    _logging.basicConfig(
        level=_logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    from .daemon import BeaconwatchDaemon
    daemon = BeaconwatchDaemon(config)

    if args.foreground:
        asyncio.run(daemon.run())
    else:
        # Daemonize: double-fork
        import os
        pid = os.fork()
        if pid > 0:
            print(f"beaconwatch daemon started (PID {pid})")
            sys.exit(0)
        os.setsid()
        pid2 = os.fork()
        if pid2 > 0:
            sys.exit(0)

        # Redirect stdio
        with open("/dev/null", "r") as devnull:
            os.dup2(devnull.fileno(), sys.stdin.fileno())
        log_file = config.data_dir / "beaconwatch.log"
        config.ensure_data_dir()
        with open(log_file, "a") as lf:
            os.dup2(lf.fileno(), sys.stdout.fileno())
            os.dup2(lf.fileno(), sys.stderr.fileno())

        asyncio.run(daemon.run())


def _cmd_tui(args: argparse.Namespace, config) -> None:
    from .tui.app import BeaconwatchApp
    app = BeaconwatchApp(config=config)
    app.run()


def _cmd_list(args: argparse.Namespace, config) -> None:
    from rich.table import Table
    from rich import box

    console = _rich_console()

    from .store.db import Database
    with Database(config.db_path) as db:
        records = db.get_top_scoring_flows(
            limit=args.limit,
            min_classification=args.min_classification,
        )

    if not records:
        console.print("[dim]No flows matching criteria found.[/dim]")
        return

    table = Table(
        title=f"beaconwatch — top flows (min: {args.min_classification})",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold",
    )
    table.add_column("Score", justify="right", width=6)
    table.add_column("Classification", width=20)
    table.add_column("Process", width=22)
    table.add_column("Destination", width=22)
    table.add_column("Interval", width=12)
    table.add_column("Samples", justify="right", width=7)
    table.add_column("Flow ID", width=18)

    for r in records:
        color = _CLASSIFICATION_COLORS.get(r.classification, "")
        label = _CLASSIFICATION_LABELS.get(r.classification, r.classification)
        proc = r.process_name or r.process_path or "[dim]unknown[/dim]"
        dest = f"{r.dst_ip}:{r.dst_port}"
        iv = _format_interval_with_jitter(r.mean_interval, r.cv)
        samples = str(r.sample_count or "—")

        def _c(text: str) -> str:
            return f"[{color}]{text}[/{color}]" if color else text

        table.add_row(
            _c(f"{r.score:.0f}"),
            _c(label),
            _c(proc),
            _c(dest),
            _c(iv),
            _c(samples),
            _c(r.flow_id),
        )

    console.print(table)


def _cmd_show(args: argparse.Namespace, config) -> None:
    from rich.panel import Panel
    from rich.table import Table
    from rich import box

    console = _rich_console()

    from .store.db import Database
    with Database(config.db_path) as db:
        record = db.get_flow_score(args.flow_id)
        if record is None:
            console.print(f"[red]Flow ID '{args.flow_id}' not found.[/red]")
            return

        history = db.get_flow_history(args.flow_id, hours=24)

    # Score breakdown table
    color = _CLASSIFICATION_COLORS.get(record.classification, "")
    label = _CLASSIFICATION_LABELS.get(record.classification, record.classification)

    console.print(Panel(
        f"[bold]Flow:[/bold] {record.flow_id}\n"
        f"[bold]Process:[/bold] {record.process_name or record.process_path or 'unknown'}\n"
        f"[bold]Path:[/bold] {record.process_path or '—'}\n"
        f"[bold]Destination:[/bold] {record.dst_ip}:{record.dst_port} ({record.proto.upper()})\n"
        f"[bold]Score:[/bold] [{color}]{record.score:.1f}/100 — {label}[/{color}]\n"
        f"[bold]Samples:[/bold] {record.sample_count or '—'}\n"
        f"[bold]Mean interval:[/bold] {_format_interval(record.mean_interval)}\n"
        f"[bold]CV:[/bold] {record.cv:.4f}" if record.cv is not None else "",
        title="Flow Details",
        border_style="blue",
    ))

    # Reasons table
    if record.reasons:
        console.print("\n[bold]Score breakdown:[/bold]")
        for i, reason in enumerate(record.reasons):
            console.print(f"  {'→' if i == 0 else ' '} {reason}")

    # Interval histogram (ASCII) from history timestamps
    if history and len(history) >= 2:
        timestamps = [c.timestamp for c in history]
        timestamps.sort()
        intervals = [
            (timestamps[i + 1] - timestamps[i]).total_seconds()
            for i in range(len(timestamps) - 1)
        ]
        console.print()
        console.print("[bold]Interval distribution (last 24h):[/bold]")
        _print_interval_histogram(console, intervals)

    # Recent connections
    if history:
        console.print()
        console.print(f"[bold]Recent connections (last {min(10, len(history))}):[/bold]")
        for conn in history[-10:]:
            console.print(
                f"  {conn.timestamp.strftime('%H:%M:%S')}  "
                f"{conn.state:<12}  "
                f"{'↑' if conn.bytes_sent else ' '}{conn.bytes_sent or '?'}B "
                f"{'↓' if conn.bytes_recv else ' '}{conn.bytes_recv or '?'}B"
            )


def _print_interval_histogram(console, intervals: list[float], width: int = 50) -> None:
    if not intervals:
        return
    import math

    min_iv = min(intervals)
    max_iv = max(intervals)
    bins = min(20, len(intervals))

    if max_iv == min_iv:
        # All identical
        console.print(f"  All intervals = {_format_interval(min_iv)} (perfect beacon!)")
        return

    bin_size = (max_iv - min_iv) / bins
    counts = [0] * bins
    for iv in intervals:
        idx = min(int((iv - min_iv) / bin_size), bins - 1)
        counts[idx] += 1

    max_count = max(counts) or 1
    bar_chars = "▁▂▃▄▅▆▇█"

    bars = ""
    for c in counts:
        ratio = c / max_count
        char_idx = int(ratio * (len(bar_chars) - 1))
        bars += bar_chars[char_idx]

    console.print(f"  [{_format_interval(min_iv)} ─{'─' * len(bars)}─ {_format_interval(max_iv)}]")
    console.print(f"  [{bars}]")
    console.print(f"  n={len(intervals)} intervals, mean={_format_interval(sum(intervals)/len(intervals))}")


def _cmd_allowlist_list(args: argparse.Namespace, config) -> None:
    from rich.table import Table
    from rich import box

    console = _rich_console()

    from .store.db import Database
    with Database(config.db_path) as db:
        from .analysis.baseline import BaselineStore
        baseline = BaselineStore(db)
        entries = baseline.list_allowlist()

    if not entries:
        console.print("[dim]No allowlist entries.[/dim]")
        return

    table = Table(title="Allowlist", box=box.ROUNDED, show_header=True)
    table.add_column("ID", width=10)
    table.add_column("Process", width=25)
    table.add_column("Dst IP", width=16)
    table.add_column("Port", width=6)
    table.add_column("Reason", width=40)
    table.add_column("Added", width=12)

    for e in entries:
        table.add_row(
            e.id,
            e.process_path or e.process_name or "*",
            e.dst_ip or "*",
            str(e.dst_port) if e.dst_port else "*",
            e.reason,
            e.added_at.strftime("%Y-%m-%d"),
        )

    console.print(table)


def _cmd_allowlist_add(args: argparse.Namespace, config) -> None:
    console = _rich_console()

    from .store.db import Database
    with Database(config.db_path) as db:
        from .analysis.baseline import BaselineStore
        baseline = BaselineStore(db)
        entry = baseline.add_to_allowlist(
            process_path=args.process,
            process_name=None,
            dst_ip=args.dst_ip,
            dst_port=args.dst_port,
            reason=args.reason,
        )
    console.print(f"[green]Added allowlist entry {entry.id}[/green]")


def _cmd_allowlist_remove(args: argparse.Namespace, config) -> None:
    console = _rich_console()

    from .store.db import Database
    with Database(config.db_path) as db:
        from .analysis.baseline import BaselineStore
        baseline = BaselineStore(db)
        baseline.remove_from_allowlist(args.id)
    console.print(f"[green]Removed allowlist entry {args.id}[/green]")


def _cmd_allowlist_suggest(args: argparse.Namespace, config) -> None:
    from rich.table import Table
    from rich import box

    console = _rich_console()

    from .store.db import Database
    with Database(config.db_path) as db:
        all_scores = db.get_all_flow_scores()
        from .analysis.grouping import FlowTracker
        from .analysis.baseline import BaselineStore
        from .analysis.scoring import BeaconScore
        from .analysis.interval_stats import IntervalStats

        baseline = BaselineStore(db)

        # Reconstruct minimal Flow-like objects from DB records for suggestion
        from .analysis.grouping import Flow as FlowType
        from collections import deque
        from datetime import datetime, timezone

        flows = []
        scores = []
        for r in all_scores:
            f = FlowType(
                id=r.flow_id,
                process_path=r.process_path,
                process_name=r.process_name,
                dst_ip=r.dst_ip,
                dst_port=r.dst_port,
                proto=r.proto,
                first_seen=r.first_seen or datetime.now(tz=timezone.utc),
                last_seen=r.last_seen or datetime.now(tz=timezone.utc),
                connection_count=r.sample_count or 0,
                _timestamps_deque=deque(),
            )
            flows.append(f)

            dummy_stats = IntervalStats(
                sample_count=r.sample_count or 0,
                intervals=[],
                mean_interval=r.mean_interval or 0.0,
                median_interval=r.mean_interval or 0.0,
                stdev_interval=0.0,
                coefficient_of_variation=r.cv or 0.0,
                mad_interval=0.0,
                autocorrelation_peak=0.0,
                dominant_period=None,
                jitter_pct=(r.cv or 0.0) * 100,
            )
            scores.append(BeaconScore(
                flow_id=r.flow_id,
                score=r.score,
                classification=r.classification,
                reasons=r.reasons,
                stats=dummy_stats,
            ))

        suggestions = baseline.suggest_allowlist_candidates(flows, scores)

    if not suggestions:
        console.print("[dim]No allowlist suggestions (no suspicious flows matching known-benign patterns).[/dim]")
        return

    console.print("[bold]Suggested allowlist candidates[/bold] (REVIEW before adding):\n")
    for flow, score, reason in suggestions:
        proc = flow.process_name or flow.process_path or "unknown"
        dest = f"{flow.dst_ip}:{flow.dst_port}"
        console.print(
            f"  [yellow]{proc}[/yellow] → {dest} "
            f"(score={score.score:.0f}, {score.classification})\n"
            f"  Reason: {reason}\n"
            f"  Add: beaconwatch allowlist add --process '{flow.process_path or ''}' "
            f"--dst-port {flow.dst_port} --reason '{reason}'\n"
        )


def _cmd_alerts(args: argparse.Namespace, config) -> None:
    from rich.table import Table
    from rich import box

    console = _rich_console()

    from .store.db import Database
    with Database(config.db_path) as db:
        alerts = db.get_alerts(unacknowledged_only=args.unacknowledged)

    if not alerts:
        console.print("[dim]No alerts.[/dim]")
        return

    table = Table(title="Alert history", box=box.ROUNDED, show_header=True)
    table.add_column("ID", width=6)
    table.add_column("Flow ID", width=18)
    table.add_column("Score", width=6)
    table.add_column("Classification", width=22)
    table.add_column("Triggered", width=20)
    table.add_column("Ack", width=4)

    for a in alerts:
        color = _CLASSIFICATION_COLORS.get(a.classification, "")
        ack = "✓" if a.acknowledged else ""
        label = _CLASSIFICATION_LABELS.get(a.classification, a.classification)

        def _c(text: str) -> str:
            return f"[{color}]{text}[/{color}]" if color else text

        table.add_row(
            str(a.id),
            _c(a.flow_id),
            _c(f"{a.score:.0f}"),
            _c(label),
            a.triggered_at.strftime("%Y-%m-%d %H:%M:%S"),
            ack,
        )

    console.print(table)


def _cmd_ack(args: argparse.Namespace, config) -> None:
    console = _rich_console()

    from .store.db import Database
    with Database(config.db_path) as db:
        db.acknowledge_alert(args.alert_id)
    console.print(f"[green]Alert {args.alert_id} acknowledged.[/green]")


def _cmd_status(args: argparse.Namespace, config) -> None:
    from rich.panel import Panel

    console = _rich_console()

    from .store.db import Database
    with Database(config.db_path) as db:
        flow_count = db.get_flow_count()
        conn_count_24h = db.get_recent_connection_count(hours=24)
        last_conn = db.get_last_connection_time()
        top_flows = db.get_top_scoring_flows(limit=5, min_classification="suspicious")

    from datetime import datetime, timezone
    now = datetime.now(tz=timezone.utc)
    if last_conn is not None:
        last_conn_tz = last_conn.replace(tzinfo=timezone.utc) if last_conn.tzinfo is None else last_conn
        age_s = (now - last_conn_tz).total_seconds()
        if age_s < 30:
            daemon_status = "[green]● running[/green]"
        elif age_s < 120:
            daemon_status = "[yellow]● possibly idle[/yellow]"
        else:
            daemon_status = "[red]● daemon not running or idle[/red]"
        last_conn_str = last_conn.strftime("%H:%M:%S")
    else:
        daemon_status = "[red]● no data — daemon not running?[/red]"
        last_conn_str = "never"

    console.print(Panel(
        f"Daemon status: {daemon_status}\n"
        f"Flows tracked: {flow_count}\n"
        f"Connections (24h): {conn_count_24h:,}\n"
        f"Last connection: {last_conn_str}",
        title="beaconwatch status",
        border_style="blue",
    ))

    if top_flows:
        console.print("\n[bold]Top suspicious flows:[/bold]")
        for r in top_flows:
            color = _CLASSIFICATION_COLORS.get(r.classification, "")
            label = _CLASSIFICATION_LABELS.get(r.classification, r.classification)
            proc = r.process_name or r.process_path or "unknown"
            dest = f"{r.dst_ip}:{r.dst_port}"
            iv = _format_interval_with_jitter(r.mean_interval, r.cv)
            console.print(
                f"  [{color}]{r.score:.0f}[/{color}]  {label:<20} {proc:<22} {dest:<22} {iv}"
            )


# ── Argument parser ───────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="beaconwatch",
        description="Passive C2 beaconing detector — catches regular check-in patterns via timing analysis",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=(
            f"beaconwatch v{__version__}\n"
            "Passive C2 beaconing detector — catches regular check-in patterns\n"
            f"{__url__}"
        ),
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        metavar="FILE",
        help="Path to .beaconwatch.toml config file",
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=None,
        metavar="DIR",
        help="Override data directory (where DB lives)",
    )

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    # daemon
    p_daemon = sub.add_parser("daemon", help="Run the capture daemon (requires root/CAP_NET_ADMIN)")
    p_daemon.add_argument(
        "--foreground", "-f",
        action="store_true",
        help="Run in foreground instead of daemonizing",
    )

    # tui
    sub.add_parser("tui", help="Launch the interactive TUI (daemon must be running)")

    # list
    p_list = sub.add_parser("list", help="List flows sorted by score")
    p_list.add_argument(
        "--min-classification",
        default="suspicious",
        choices=["benign", "suspicious", "likely_beacon", "high_confidence_beacon"],
        help="Minimum classification to show (default: suspicious)",
    )
    p_list.add_argument("--limit", type=int, default=50, help="Max rows (default: 50)")

    # show
    p_show = sub.add_parser("show", help="Detailed view of one flow")
    p_show.add_argument("flow_id", help="Flow ID (from 'list' output)")

    # allowlist
    p_al = sub.add_parser("allowlist", help="Manage the process/destination allowlist")
    al_sub = p_al.add_subparsers(dest="allowlist_cmd", metavar="SUBCOMMAND")

    al_sub.add_parser("list", help="Show allowlist entries")

    p_al_add = al_sub.add_parser("add", help="Add an allowlist entry")
    p_al_add.add_argument("--process", default=None, metavar="PATH", help="Full process path")
    p_al_add.add_argument("--dst-ip", default=None, metavar="IP", help="Destination IP")
    p_al_add.add_argument("--dst-port", type=int, default=None, metavar="PORT", help="Destination port")
    p_al_add.add_argument("--reason", required=True, help="Human-readable reason")

    p_al_rem = al_sub.add_parser("remove", help="Remove an allowlist entry")
    p_al_rem.add_argument("id", help="Entry ID")

    al_sub.add_parser("suggest", help="Show suggested allowlist candidates")

    # alerts
    p_alerts = sub.add_parser("alerts", help="Show alert history")
    p_alerts.add_argument(
        "--unacknowledged", "-u",
        action="store_true",
        help="Show only unacknowledged alerts",
    )

    # ack
    p_ack = sub.add_parser("ack", help="Acknowledge an alert")
    p_ack.add_argument("alert_id", type=int, help="Alert ID")

    # status
    sub.add_parser("status", help="Show daemon status and top suspicious flows")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # Load config
    from .config import load_config
    config = load_config(args.config if hasattr(args, "config") else None)

    if hasattr(args, "data_dir") and args.data_dir is not None:
        config.data_dir = args.data_dir

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    if args.command == "daemon":
        _cmd_daemon(args, config)
    elif args.command == "tui":
        _cmd_tui(args, config)
    elif args.command == "list":
        _cmd_list(args, config)
    elif args.command == "show":
        _cmd_show(args, config)
    elif args.command == "allowlist":
        if args.allowlist_cmd == "list" or args.allowlist_cmd is None:
            _cmd_allowlist_list(args, config)
        elif args.allowlist_cmd == "add":
            _cmd_allowlist_add(args, config)
        elif args.allowlist_cmd == "remove":
            _cmd_allowlist_remove(args, config)
        elif args.allowlist_cmd == "suggest":
            _cmd_allowlist_suggest(args, config)
        else:
            parser.parse_args(["allowlist", "--help"])
    elif args.command == "alerts":
        _cmd_alerts(args, config)
    elif args.command == "ack":
        _cmd_ack(args, config)
    elif args.command == "status":
        _cmd_status(args, config)
    else:
        parser.print_help()
        sys.exit(1)
