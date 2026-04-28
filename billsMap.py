import sys
import time
import socket
import asyncio
import argparse
import json
import errno
import logging
import csv
import io
import re
from pathlib import Path
from datetime import datetime, timezone
from enum import Enum, auto
from dataclasses import dataclass, asdict
from typing import List, Tuple, Optional, Protocol

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, TaskID

try:
    import resource
    HAS_RESOURCE = True
except ImportError:
    HAS_RESOURCE = False

__version__ = "1.0.0"

log = logging.getLogger(__name__)

_PORT_RE = re.compile(r'^(\d+)(?:-(\d+))?$')

class BillsMapError(Exception):
    """Base exception for all BillsMap errors."""
    pass

class ConfigError(BillsMapError):
    pass

class ResolveError(BillsMapError):
    pass

class ScanError(BillsMapError):
    pass

class ExportError(BillsMapError):
    pass

def check_and_apply_fd_limit(requested_concurrency: int, console: Console, unsafe_adjust: bool) -> int:
    """
    Checks global OS File Descriptor limits (ulimit).
    Applies changes only if --unsafe-adjust-limits is provided.
    """
    if not HAS_RESOURCE:
        return requested_concurrency
    
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        needed = requested_concurrency + 100
        
        if needed <= soft:
            return requested_concurrency
            
        if not unsafe_adjust:
            allowed = max(soft - 100, 1)
            if allowed < requested_concurrency:
                console.print(f"[yellow][!] Concurrency reduced to {allowed} to respect OS FD limits. Use --unsafe-adjust-limits to override.[/yellow]")
                return allowed
            return requested_concurrency

        new_limit = min(needed, hard) if hard != resource.RLIM_INFINITY else needed
        resource.setrlimit(resource.RLIMIT_NOFILE, (new_limit, hard))
        return requested_concurrency
    except (ValueError, OSError) as e:
        log.warning("Failed to check or adjust FD limits (ulimit): %s", e)
        return min(requested_concurrency, 1024)

def load_ports(custom_path: Optional[str] = None) -> Tuple[List[int], List[int]]:
    if custom_path:
        path = Path(custom_path).resolve()
    else:
        path = Path(__file__).resolve().parent / "ports.json"
        
    if not path.exists():
        if custom_path:
            raise ConfigError(f"Custom ports file not found: {custom_path}")
        raise ConfigError(f"Default ports.json not found at {path}")

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data.get('TOP1K', []), data.get('TOP10K', [])
    except json.JSONDecodeError as e:
        raise ConfigError(f"Invalid JSON format in ports file {path}: {e}") from e
    except Exception as e:
        raise ConfigError(f"Failed to load ports file {path}: {e}") from e

BANNER_TEMPLATE = """
+=============================================================================+
|                                                                             |
|   ██████╗ ██╗██╗     ██╗     ███████╗███╗   ███╗ █████╗ ██████╗             |
|   ██╔══██╗██║██║     ██║     ██╔════╝████╗ ████║██╔══██╗██╔══██╗            |
|   ██████╔╝██║██║     ██║     ███████╗██╔████╔██║███████║██████╔╝            |
|   ██╔══██╗██║██║     ██║     ╚════██║██║╚██╔╝██║██╔══██║██╔═══╝             |
|   ██████╔╝██║███████╗███████╗███████║██║ ╚═╝ ██║██║  ██║██║                 |
|   ╚═════╝ ╚═╝╚══════╝╚══════╝╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝                 |
|                                                                             |
|   :: Automated Reconnaissance & Port Mapping Toolkit ::      v{version:<13} |
|   :: Engineered for High-Concurrency & Reliability ::                       |
+=============================================================================+
"""

def get_banner() -> str:
    return BANNER_TEMPLATE.format(version=__version__)

class PortState(Enum):
    OPEN = auto()
    CLOSED = auto()
    FILTERED = auto()
    ERROR = auto()

@dataclass(frozen=True)
class ScanResult:
    port: int
    state: PortState
    error_msg: str = ""

@dataclass(frozen=True)
class ScanReport:
    target: str
    resolved_ip: str
    open_ports: Tuple[int, ...]
    open_count: int
    closed_count: int
    filtered_count: int
    error_count: int
    elapsed_sec: float
    timestamp: str

@dataclass(frozen=True)
class ScanConfig:
    ports: Tuple[int, ...]
    timeout: float
    concurrency: int
    rate_limit: float

class ReportFormatter:
    @staticmethod
    def as_json(report: ScanReport) -> str:
        d = asdict(report)
        d["open_ports"] = list(d["open_ports"])
        return json.dumps(d, indent=2)

    @staticmethod
    def as_csv(report: ScanReport) -> str:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["Target", "IP", "OpenPorts", "OpenCount", "ClosedCount", "FilteredCount", "ErrorCount", "Time(s)", "Timestamp"])
        w.writerow([
            report.target, 
            report.resolved_ip,
            " ".join(map(str, report.open_ports)), 
            f"{report.open_count}",
            f"{report.closed_count}", 
            f"{report.filtered_count}", 
            f"{report.error_count}", 
            f"{report.elapsed_sec:.3f}", 
            report.timestamp
        ])
        return buf.getvalue()

    @staticmethod
    def as_txt(report: ScanReport) -> str:
        lines = [f"Scan Report for {report.target} ({report.resolved_ip})"]
        lines.append(f"Completed at: {report.timestamp} in {report.elapsed_sec:.3f}s")
        lines.append(f"Open Ports: {', '.join(map(str, report.open_ports))}")
        lines.append(f"Summary: {report.open_count} open, {report.closed_count} closed, {report.filtered_count} filtered, {report.error_count} errors.")
        return "\n".join(lines)

class ReportExporter:
    _FORMATTERS = {
        "txt": ReportFormatter.as_txt,
        "json": ReportFormatter.as_json,
        "csv": ReportFormatter.as_csv
    }
    
    @classmethod
    def export(cls, report: ScanReport, path: str, fmt: str) -> None:
        formatter = cls._FORMATTERS.get(fmt)
        if not formatter:
            raise ConfigError(f"Unsupported format: {fmt!r}. Valid: {list(cls._FORMATTERS)}")
        try:
            Path(path).write_text(formatter(report), encoding="utf-8")
        except IOError as e:
            raise ExportError(f"Error exporting file: {e}") from e


class ScanPresenter(Protocol):
    def on_starting(self, ip: str, total: int) -> None: ...
    def on_result(self, result: ScanResult) -> None: ...
    def generate_report(self, target: str, ip: str, elapsed: float) -> ScanReport: ...
    def on_done(self, report: ScanReport) -> None: ...
    async def __aenter__(self) -> 'ScanPresenter': ...
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None: ...


class TokenBucket:
    """A precise leaky-bucket rate limiter that avoids thundering herd busy-waits."""
    def __init__(self, rate: float):
        self.rate = rate
        self.time_per_token = 1.0 / rate if rate > 0 else 0
        self.next_allowed_time = time.monotonic()
        self._lock: Optional[asyncio.Lock] = None
        
    async def wait_for_token(self):
        if self.rate <= 0:
            return
            
        if self._lock is None:
            self._lock = asyncio.Lock()
            
        async with self._lock:
            now = time.monotonic()
            if self.next_allowed_time < now:
                self.next_allowed_time = now
            sleep_time = self.next_allowed_time - now
            self.next_allowed_time += self.time_per_token
            
        if sleep_time > 0:
            await asyncio.sleep(sleep_time)


class ScannerEngine:
    def __init__(self, target_name: str, target_ip: str, config: ScanConfig):
        self.target_name = target_name
        self.target_ip = target_ip
        self.config = config

    async def _check_port(self, ip: str, port: int) -> ScanResult:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), 
                timeout=self.config.timeout
            )
            writer.close()
            await writer.wait_closed()
            state, err = PortState.OPEN, ""
        except (ConnectionRefusedError, ConnectionResetError):
            state, err = PortState.CLOSED, ""
        except (TimeoutError, asyncio.TimeoutError):
            state, err = PortState.FILTERED, ""
        except OSError as e:
            if e.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH):
                state, err = PortState.FILTERED, ""
            else:
                state, err = PortState.ERROR, str(e)
            
        return ScanResult(port, state, err)

    async def run(self, presenter: ScanPresenter) -> Optional[ScanReport]:
        start_time = time.monotonic()
        presenter.on_starting(self.target_ip, len(self.config.ports))

        bucket = TokenBucket(self.config.rate_limit) if self.config.rate_limit > 0 else None
        sem = asyncio.Semaphore(self.config.concurrency)
        
        async def scan_task(port: int):
            async with sem:
                if bucket:
                    await bucket.wait_for_token()
                result = await self._check_port(self.target_ip, port)
                presenter.on_result(result)

        try:
            async with asyncio.TaskGroup() as tg:
                for p in self.config.ports:
                    tg.create_task(scan_task(p))
        except asyncio.CancelledError:
            raise
            
        elapsed = time.monotonic() - start_time
        report = presenter.generate_report(self.target_name, self.target_ip, elapsed)
        presenter.on_done(report)
        return report


class RichConsolePresenter:
    def __init__(self, console: Console):
        self.console = console
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console,
            transient=True
        )
        self.task_id: Optional[TaskID] = None
        self._started = False
        
        self._queue: asyncio.Queue = asyncio.Queue()
        self._consumer_task: Optional[asyncio.Task] = None
        
        self._open_ports: List[int] = []
        self._closed_count = 0
        self._filtered_count = 0
        self._error_count = 0

    async def _consume_results(self):
        while True:
            result = await self._queue.get()
            if result is None:
                self._queue.task_done()
                break
                
            match result.state:
                case PortState.OPEN:
                    self._open_ports.append(result.port)
                    self.progress.console.print(f"[bold green][+][/bold green] [cyan]{result.port:<5}[/cyan] → [green]OPEN[/green]")
                case PortState.CLOSED:
                    self._closed_count += 1
                case PortState.FILTERED:
                    self._filtered_count += 1
                case PortState.ERROR:
                    self._error_count += 1
                    
            if self.task_id is not None:
                self.progress.advance(self.task_id)
            self._queue.task_done()

    def on_starting(self, ip: str, total: int) -> None:
        self._started = True
        self.console.print(f"[green][*][/green] Target resolved to IP: [cyan]{ip}[/cyan]")
        self.console.print("\n[yellow] [   SCANNING RESULTS   ] [/yellow]")
        self.progress.start()
        self.task_id = self.progress.add_task("[cyan]Scanning...", total=total)
        self._consumer_task = asyncio.create_task(self._consume_results())

    def on_result(self, result: ScanResult) -> None:
        self._queue.put_nowait(result)
            
    def generate_report(self, target: str, ip: str, elapsed: float) -> ScanReport:
        open_list = sorted(self._open_ports)
        return ScanReport(
            target=target,
            resolved_ip=ip,
            open_ports=tuple(open_list),
            open_count=len(open_list),
            closed_count=self._closed_count,
            filtered_count=self._filtered_count,
            error_count=self._error_count,
            elapsed_sec=elapsed,
            timestamp=datetime.now(timezone.utc).isoformat()
        )

    def on_done(self, report: ScanReport) -> None:
        pass

    async def __aenter__(self) -> 'RichConsolePresenter':
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._consumer_task:
            self._queue.put_nowait(None)
            await self._consumer_task
            
        if self._started:
            self.progress.stop()
            self._started = False
            
        if exc_type is not None:
            self.console.print("\n[bold red][!] Scan was aborted before completion.[/bold red]")
        else:
            open_list = sorted(self._open_ports)
            table = Table(title="Scan Summary", show_header=True, header_style="bold magenta")
            table.add_column("State", style="dim", width=12)
            table.add_column("Count", justify="right")
            
            table.add_row("[green]OPEN[/green]", f"{len(open_list)}")
            table.add_row("[red]CLOSED[/red]", f"{self._closed_count}")
            table.add_row("[yellow]FILTERED[/yellow]", f"{self._filtered_count}")
            table.add_row("[magenta]ERRORS[/magenta]", f"{self._error_count}")
            
            self.console.print(table)


def parse_ports(port_str: str) -> list[int]:
    ports: set[int] = set()
    for part in port_str.split(','):
        if m := _PORT_RE.match(part.strip()):
            lo = int(m.group(1))
            hi = int(m.group(2) or lo)
            if lo > hi or not (1 <= lo <= 65535) or not (1 <= hi <= 65535):
                raise argparse.ArgumentTypeError(f"Invalid port range: {part!r}")
            ports.update(range(lo, hi + 1))
        elif part.strip():
            raise argparse.ArgumentTypeError(f"Invalid port: {part!r}")
    if not ports:
        raise argparse.ArgumentTypeError("No valid ports specified")
    return sorted(ports)


def positive_float(v: str) -> float:
    f = float(v)
    if f <= 0:
        raise argparse.ArgumentTypeError(f"must be positive, got {v}")
    return f


def bounded_int(lo: int, hi: int):
    def _check(v: str) -> int:
        i = int(v)
        if not (lo <= i <= hi):
            raise argparse.ArgumentTypeError(f"must be between {lo} and {hi}, got {v}")
        return i
    return _check


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Senior Async Port Scanner Toolkit (High-Performance Engine)'
    )
    parser.add_argument('-t', '--target', dest='hosts', nargs='+', required=True,
                        help='Target IP(s) or domain(s)')
    parser.add_argument('-p', '--ports', dest='ports_arg', type=parse_ports,
                        help='Custom ports to scan (e.g., 22,80,443,8000-9000)')
    parser.add_argument('--ports-file', dest='ports_file', type=str, default=None,
                        help='Override ports.json path')
    parser.add_argument('--timeout', dest='timeout', type=positive_float, default=1.0,
                        help='Timeout in seconds per port (default: 1.0)')
    parser.add_argument('--concurrency', dest='concurrency', type=bounded_int(1, 10000), default=1000,
                        help='Max concurrent connections (worker pool size) (default: 1000)')
    parser.add_argument('--rate', dest='rate', type=float, default=0.0,
                        help='Rate limit in Connections Per Second (default: 0 = unlimited)')
    parser.add_argument('-o', '--output', dest='output', default=None,
                        help='File to save report')
    parser.add_argument('--format', dest='fmt', choices=['txt', 'json', 'csv'], default='txt',
                        help='Output file format (txt, json, csv)')
    parser.add_argument('--top-10k', dest='top10k', action='store_true',
                        help='Scan top 10k ports instead of top 1k')
    parser.add_argument('--unsafe-adjust-limits', dest='unsafe_adjust', action='store_true',
                        help='Allow the scanner to permanently alter OS File Descriptor limits (ulimit)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose debug logging')
    return parser.parse_args()


def setup_logging(verbose: bool):
    if verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING)

def resolve_ports_config(args: argparse.Namespace) -> Tuple[int, ...]:
    if args.ports_arg:
        return tuple(args.ports_arg)
    top1k, top10k = load_ports(args.ports_file)
    return tuple(top10k if args.top10k else top1k)

async def resolve_host(host: str) -> str:
    """Resolves target host to IP, supporting both IPv4 and IPv6."""
    loop = asyncio.get_running_loop()
    try:
        info = await loop.getaddrinfo(
            host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
        )
        if not info:
            raise ResolveError(f"No IP address found for: {host}")
        return info[0][4][0]
    except socket.gaierror as e:
        raise ResolveError(f"DNS Resolution failed for '{host}': {e}") from e

def build_output_path(template: str, host: str) -> str:
    """Isolates the logic for determining the output filename from a given template and host."""
    safe_host = host.replace('.', '_').replace(':', '_')
    if "{host}" in template:
        return template.replace("{host}", safe_host)
    
    log.warning("Output template does not contain '{host}' placeholder. Files may be overwritten if scanning multiple targets.")
    return template


async def scan_single_target(host: str, target_ip: str, config: ScanConfig, output: Optional[str], fmt: str, console: Console):
    console.print(f'\nTarget      = [magenta]{host}[/magenta]')
    console.print(f'Timeout     = [magenta]{config.timeout}[/magenta] sec')
    console.print(f'Concurrency = [magenta]{config.concurrency}[/magenta] workers')
    if config.rate_limit > 0:
        console.print(f'Rate Limit  = [magenta]{config.rate_limit}[/magenta] connections/sec')
    console.print(f'Ports       = [magenta]{len(config.ports)}[/magenta]')
    console.print("-" * 50)
    
    scanner = ScannerEngine(
        target_name=host,
        target_ip=target_ip,
        config=config
    )
    
    presenter = RichConsolePresenter(console)
    report = None
    
    try:
        async with presenter:
            report = await scanner.run(presenter)
    except BillsMapError as e:
        console.print(f'\n[bold red][!] FATAL ERROR:[/bold red] {e}')
    except asyncio.CancelledError:
        console.print('\n[bold yellow][!] Scan cancelled by user...[/bold yellow]')
        raise

    if report and output:
        out_file = build_output_path(output, host)
        try:
            out_path = Path(out_file).resolve()
            out_path.parent.mkdir(parents=True, exist_ok=True)
            ReportExporter.export(report, out_file, fmt)
            console.print(f"\n[bold green][*][/bold green] Report exported to [cyan]{out_file}[/cyan]")
        except ExportError as e:
            console.print(f'\n[bold red][!] {e}[/bold red]')


async def async_main():
    console = Console()
    try:
        args = parse_args()
    except Exception as e:
        console.print(f"[bold red]Configuration error: {e}[/bold red]")
        sys.exit(1)
        
    setup_logging(args.verbose)

    actual_concurrency = check_and_apply_fd_limit(args.concurrency, console, args.unsafe_adjust)

    console.print(get_banner(), style="bold blue")
    
    if args.output:
        out = Path(args.output).resolve()
        try:
            out.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            console.print(f"[bold red][!] Cannot create output directory {out.parent}: {e}[/bold red]")
            sys.exit(1)

    try:
        port_list = resolve_ports_config(args)
    except BillsMapError as e:
        console.print(f"[bold red][!][/bold red] {e}")
        sys.exit(1)

    if not port_list:
        console.print("[bold red][!] No ports specified to scan.[/bold red]")
        sys.exit(1)
        
    config = ScanConfig(
        ports=port_list,
        timeout=args.timeout,
        concurrency=actual_concurrency,
        rate_limit=args.rate
    )
        
    for host in args.hosts:
        console.print(f"[yellow][*][/yellow] Resolving target domain '{host}'...")
        try:
            target_ip = await resolve_host(host)
        except BillsMapError as e:
            console.print(f"[bold red][!][/bold red] {e}")
            continue
            
        await scan_single_target(host, target_ip, config, args.output, args.fmt, console)

def main():
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        sys.exit(130)

if __name__ == '__main__':
    main()
