"""
Textual TUI — reads from SQLite DB (read-only, WAL mode safe).
Polls every 3 seconds for updates from the running daemon.
Never crashes if the daemon isn't running — shows clear status.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Label,
    Static,
)
from textual.timer import Timer

if TYPE_CHECKING:
    from ..config import Config
    from ..store.db import FlowScoreRecord, Database


# Classification display
_CLASS_COLOR = {
    "high_confidence_beacon": "red",
    "likely_beacon": "dark_orange",
    "suspicious": "yellow",
    "benign": "dim",
}

_CLASS_LABEL = {
    "high_confidence_beacon": "HIGH CONFIDENCE",
    "likely_beacon": "LIKELY BEACON",
    "suspicious": "SUSPICIOUS",
    "benign": "benign",
}


def _format_interval(seconds: float | None, cv: float | None = None) -> str:
    if seconds is None or seconds <= 0:
        return "irregular"
    if seconds < 60:
        base = f"{seconds:.1f}s"
    elif seconds < 3600:
        base = f"{seconds / 60:.1f}m"
    else:
        base = f"{seconds / 3600:.1f}h"

    if cv is not None and seconds > 0:
        jitter = cv * seconds
        if jitter < 60:
            jitter_str = f"±{jitter:.1f}s"
        else:
            jitter_str = f"±{jitter / 60:.1f}m"
        return f"{base}{jitter_str}"
    return base


def _interval_sparkline(mean: float | None, cv: float | None) -> str:
    """Generate a compact sparkline-style representation using Unicode blocks."""
    if mean is None or mean <= 0:
        return "▁▁▁▁▁▁▁▁"  # flat/unknown
    if cv is None:
        return "▅▅▅▅▅▅▅▅"

    # Simulate a beacon's distribution as a visual hint
    if cv < 0.05:
        return "█████████"   # perfect beacon
    elif cv < 0.15:
        return "▇▇▇▇▇▇▇▇"   # very regular
    elif cv < 0.30:
        return "▅▅▅▆▅▅▅▆"   # moderate
    elif cv < 0.60:
        return "▂▄▆▂▅▃▆▂"   # irregular
    else:
        return "▁▄▂▇▁▅▂▃"   # noisy


# ── Detail modal screen ───────────────────────────────────────────────────────

class FlowDetailModal(ModalScreen):
    """Modal showing full score breakdown, interval histogram, and actions."""

    BINDINGS = [
        Binding("escape", "dismiss", "Close"),
        Binding("q", "dismiss", "Close"),
    ]

    def __init__(self, record: "FlowScoreRecord", db: "Database", config) -> None:
        super().__init__()
        self._record = record
        self._db = db
        self._config = config

    def compose(self) -> ComposeResult:
        r = self._record
        proc = r.process_name or r.process_path or "unknown"
        dest = f"{r.dst_ip}:{r.dst_port} ({r.proto.upper()})"
        color = _CLASS_COLOR.get(r.classification, "")
        label = _CLASS_LABEL.get(r.classification, r.classification)
        iv = _format_interval(r.mean_interval, r.cv)

        lines = [
            f"[bold]Flow ID:[/bold]     {r.flow_id}",
            f"[bold]Process:[/bold]     {proc}",
            f"[bold]Path:[/bold]        {r.process_path or '—'}",
            f"[bold]Destination:[/bold] {dest}",
            f"[bold]Score:[/bold]       [bold {color}]{r.score:.1f}/100 — {label}[/bold {color}]",
            f"[bold]Interval:[/bold]    {iv}",
            f"[bold]CV:[/bold]          {r.cv:.4f}" if r.cv is not None else "[bold]CV:[/bold]          —",
            f"[bold]Samples:[/bold]     {r.sample_count or '—'}",
            "",
            "[bold underline]Score breakdown:[/bold underline]",
        ]

        for i, reason in enumerate(r.reasons or []):
            marker = "▶" if i == 0 else " "
            lines.append(f"  {marker} {reason}")

        # Interval histogram from recent history
        history = self._db.get_flow_history(r.flow_id, hours=24)
        if history and len(history) >= 2:
            timestamps = sorted(c.timestamp for c in history)
            intervals = [
                (timestamps[i + 1] - timestamps[i]).total_seconds()
                for i in range(len(timestamps) - 1)
                if (timestamps[i + 1] - timestamps[i]).total_seconds() > 0
            ]
            if intervals:
                lines.append("")
                lines.append("[bold underline]Interval distribution:[/bold underline]")
                lines.append(_make_histogram(intervals))
                lines.append(
                    f"  n={len(intervals)}, mean={_format_interval(sum(intervals)/len(intervals))}"
                )

        if history:
            lines.append("")
            lines.append("[bold underline]Recent connections:[/bold underline]")
            for conn in history[-8:]:
                sent = f"↑{conn.bytes_sent}B" if conn.bytes_sent else ""
                recv = f"↓{conn.bytes_recv}B" if conn.bytes_recv else ""
                lines.append(
                    f"  {conn.timestamp.strftime('%H:%M:%S')}  {conn.state:<12}  {sent} {recv}"
                )

        content = "\n".join(lines)

        with Container(id="detail-modal"):
            yield Static(content, id="detail-content")
            with Horizontal(id="detail-buttons"):
                yield Button("Add to allowlist [A]", id="btn-allowlist", variant="warning")
                yield Button("Close [Esc]", id="btn-close", variant="default")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-close":
            self.dismiss()
        elif event.button.id == "btn-allowlist":
            self._do_allowlist()

    def _do_allowlist(self) -> None:
        r = self._record
        from ..store.db import Database
        from ..analysis.baseline import BaselineStore
        proc = r.process_name or r.process_path or "unknown"
        try:
            with Database(self._config.db_path) as db:
                baseline = BaselineStore(db)
                baseline.add_to_allowlist(
                    process_path=r.process_path,
                    process_name=r.process_name,
                    dst_ip=r.dst_ip,
                    dst_port=r.dst_port,
                    reason=f"User-approved from TUI: {proc} → {r.dst_ip}:{r.dst_port}",
                )
            self.app.notify(f"Added {proc} → {r.dst_ip}:{r.dst_port} to allowlist")
        except Exception as exc:
            self.app.notify(f"Failed to add allowlist entry: {exc}", severity="error")
        self.dismiss()


def _make_histogram(intervals: list[float], width: int = 40) -> str:
    if not intervals:
        return ""
    min_iv = min(intervals)
    max_iv = max(intervals)
    if max_iv == min_iv:
        return f"  All intervals = {_format_interval(min_iv)} (perfect beacon!)"

    bins = min(width, max(4, len(intervals)))
    bin_size = (max_iv - min_iv) / bins
    counts = [0] * bins
    for iv in intervals:
        idx = min(int((iv - min_iv) / bin_size), bins - 1)
        counts[idx] += 1

    max_count = max(counts) or 1
    bar_chars = "▁▂▃▄▅▆▇█"
    bars = "".join(bar_chars[int(c / max_count * (len(bar_chars) - 1))] for c in counts)

    return (
        f"  {_format_interval(min_iv)} {'─' * (bins // 2)} {_format_interval(max_iv)}\n"
        f"  [{bars}]"
    )


# ── Main TUI App ──────────────────────────────────────────────────────────────

_POLL_INTERVAL = 3.0  # seconds between DB polls

_CSS = """
Screen {
    background: $surface;
}

#header-bar {
    height: 3;
    background: $primary-background;
    padding: 0 2;
    align: left middle;
}

#status-label {
    color: $text;
}

#flow-table {
    height: 1fr;
}

#empty-label {
    text-align: center;
    margin-top: 4;
    color: $text-muted;
}

#detail-modal {
    background: $surface;
    border: thick $primary;
    width: 80%;
    height: 80%;
    margin: 2 4;
    padding: 1 2;
    overflow-y: auto;
}

#detail-content {
    padding: 1;
}

#detail-buttons {
    height: 3;
    align: center middle;
    margin-top: 1;
}
"""


class BeaconwatchApp(App):
    """Passive C2 beaconing detector — live TUI."""

    TITLE = "beaconwatch"
    CSS = _CSS
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
        Binding("enter", "show_detail", "Details"),
        Binding("a", "allowlist_selected", "Allowlist"),
    ]

    records: reactive[list] = reactive(list)
    daemon_running: reactive[bool] = reactive(False)
    flow_count: reactive[int] = reactive(0)
    conn_count: reactive[int] = reactive(0)

    def __init__(self, config: "Config") -> None:
        super().__init__()
        self._config = config
        self._db: Database | None = None
        self._poll_timer: Timer | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("", id="header-bar")
        yield DataTable(id="flow-table", cursor_type="row")
        yield Footer()

    def on_mount(self) -> None:
        self._open_db()
        self._setup_table()
        self._poll_timer = self.set_interval(_POLL_INTERVAL, self._poll_data)
        self._poll_data()  # immediate first load

    def _open_db(self) -> None:
        from ..store.db import Database
        try:
            self._db = Database(self._config.db_path)
            self._db.open()
        except Exception as exc:
            self._db = None
            self.sub_title = f"DB error: {exc}"

    def _setup_table(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns(
            "Score", "Classification", "Process", "Destination", "Interval", "Samples", "Flow ID"
        )

    def _poll_data(self) -> None:
        if self._db is None:
            return

        try:
            records = self._db.get_all_flow_scores(limit=200)
            flow_count = self._db.get_flow_count()
            conn_count = self._db.get_recent_connection_count(hours=24)
            last_conn = self._db.get_last_connection_time()

            now = datetime.now(tz=timezone.utc)
            if last_conn is not None:
                last_tz = last_conn.replace(tzinfo=timezone.utc) if last_conn.tzinfo is None else last_conn
                age = (now - last_tz).total_seconds()
                self.daemon_running = age < 30
            else:
                self.daemon_running = False

            self.flow_count = flow_count
            self.conn_count = conn_count
            self.records = records

            self._update_table(records)
            self._update_header()
        except Exception as exc:
            self.query_one("#header-bar", Static).update(
                f"[red]Database error: {exc}[/red]"
            )

    def _update_header(self) -> None:
        status = "[green]● running[/green]" if self.daemon_running else "[red]● daemon not running or idle[/red]"
        header = self.query_one("#header-bar", Static)
        header.update(
            f"{status}   "
            f"Flows: [bold]{self.flow_count}[/bold]   "
            f"Connections (24h): [bold]{self.conn_count:,}[/bold]"
        )

    def _update_table(self, records) -> None:
        table = self.query_one(DataTable)
        table.clear()

        if not records:
            return

        min_samples = self._config.min_samples

        for r in records:
            color = _CLASS_COLOR.get(r.classification, "")
            label = _CLASS_LABEL.get(r.classification, r.classification)
            proc = r.process_name or r.process_path or "unknown"
            dest = f"{r.dst_ip}:{r.dst_port}"
            iv = _format_interval(r.mean_interval, r.cv)

            if r.sample_count is not None and r.sample_count < min_samples:
                iv = "collecting…"

            sparkline = _interval_sparkline(r.mean_interval, r.cv)
            iv_display = f"{iv} {sparkline}"

            def _c(text: str) -> str:
                return f"[{color}]{text}[/{color}]" if color else text

            table.add_row(
                _c(f"{r.score:.0f}"),
                _c(label),
                _c(proc[:21]),
                _c(dest[:21]),
                _c(iv_display),
                _c(str(r.sample_count or "—")),
                _c(r.flow_id),
                key=r.flow_id,
            )

    def _get_selected_record(self):
        table = self.query_one(DataTable)
        if table.cursor_row < 0 or not self.records:
            return None
        try:
            row_key = table.get_row_at(table.cursor_row)
            # Rows are keyed by flow_id
        except Exception:
            return None
        # Match by position since DataTable gives us row index
        if table.cursor_row < len(self.records):
            return self.records[table.cursor_row]
        return None

    def action_show_detail(self) -> None:
        record = self._get_selected_record()
        if record is None:
            self.notify("Select a flow row first (use ↑↓)")
            return
        if self._db is None:
            self.notify("Database not available", severity="error")
            return
        self.push_screen(FlowDetailModal(record, self._db, self._config))

    def action_allowlist_selected(self) -> None:
        record = self._get_selected_record()
        if record is None:
            self.notify("Select a flow row first")
            return
        if self._db is None:
            self.notify("Database not available", severity="error")
            return

        proc = record.process_name or record.process_path or "unknown"
        dest = f"{record.dst_ip}:{record.dst_port}"
        try:
            from ..analysis.baseline import BaselineStore
            from ..store.db import Database
            with Database(self._config.db_path) as db:
                baseline = BaselineStore(db)
                baseline.add_to_allowlist(
                    process_path=record.process_path,
                    process_name=record.process_name,
                    dst_ip=record.dst_ip,
                    dst_port=record.dst_port,
                    reason=f"User-approved from TUI: {proc} → {dest}",
                )
            self.notify(f"Allowlisted: {proc} → {dest}")
        except Exception as exc:
            self.notify(f"Error: {exc}", severity="error")

    def action_refresh(self) -> None:
        self._poll_data()
        self.notify("Refreshed")

    def on_unmount(self) -> None:
        if self._db is not None:
            try:
                self._db.close()
            except Exception:
                pass

    def _check_empty_state(self) -> None:
        min_samples = self._config.min_samples
        if not self.records:
            self.query_one(DataTable).display = False
        else:
            self.query_one(DataTable).display = True
