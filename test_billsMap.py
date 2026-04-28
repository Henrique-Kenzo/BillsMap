import pytest
import asyncio
import argparse
import time
from typing import List
from datetime import datetime, timezone

from billsMap import (
    ScannerEngine, 
    ScanPresenter, 
    ScanResult, 
    ScanReport, 
    PortState, 
    ScanConfig,
    ReportExporter,
    ReportFormatter,
    parse_ports,
    TokenBucket,
    build_output_path
)

class MockPresenter:
    def __init__(self):
        self.started = False
        self.open_ports = []
        self.closed_count = 0
        self.filtered_count = 0
        self.error_count = 0
        self.report: ScanReport = None

    def on_starting(self, ip: str, total: int) -> None:
        self.started = True

    def on_result(self, result: ScanResult) -> None:
        if result.state == PortState.OPEN:
            self.open_ports.append(result.port)
        elif result.state == PortState.CLOSED:
            self.closed_count += 1
        elif result.state == PortState.FILTERED:
            self.filtered_count += 1
        else:
            self.error_count += 1
            
    def generate_report(self, target: str, ip: str, elapsed: float) -> ScanReport:
        open_list = sorted(self.open_ports)
        return ScanReport(
            target=target,
            resolved_ip=ip,
            open_ports=tuple(open_list),
            open_count=len(open_list),
            closed_count=self.closed_count,
            filtered_count=self.filtered_count,
            error_count=self.error_count,
            elapsed_sec=elapsed,
            timestamp=datetime.now(timezone.utc).isoformat()
        )

    def on_done(self, report: ScanReport) -> None:
        self.report = report
        
    async def __aenter__(self):
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass

@pytest.mark.asyncio
async def test_scanner_engine_open_and_closed():
    config = ScanConfig(timeout=0.1, concurrency=2, rate_limit=0, ports=(22, 80, 443))
    engine = ScannerEngine("localhost", "127.0.0.1", config)
    
    async def mock_check_port(ip, port):
        if port == 80:
            return ScanResult(port, PortState.OPEN)
        elif port == 443:
            return ScanResult(port, PortState.FILTERED)
        return ScanResult(port, PortState.CLOSED)
        
    engine._check_port = mock_check_port
    
    presenter = MockPresenter()
    report = await engine.run(presenter)
    
    assert presenter.started is True
    assert report.open_ports == (80,)
    assert report.closed_count == 1
    assert report.filtered_count == 1
    assert report.error_count == 0

@pytest.mark.asyncio
async def test_integration_tcp_server():
    # True integration test proving it can find a real open port
    async def handle_client(reader, writer):
        writer.close()
        await writer.wait_closed()
        
    server = await asyncio.start_server(handle_client, '127.0.0.1', 0)
    addr = server.sockets[0].getsockname()
    open_port = addr[1]
    
    config = ScanConfig(timeout=0.2, concurrency=1, rate_limit=0, ports=(open_port, open_port + 1))
    engine = ScannerEngine("localhost", "127.0.0.1", config)
    
    presenter = MockPresenter()
    async with server:
        report = await engine.run(presenter)
        
    assert open_port in report.open_ports
    assert (open_port + 1) not in report.open_ports

def test_parse_ports():
    assert parse_ports("80") == [80]
    assert parse_ports("80,443") == [80, 443]
    assert parse_ports("80-82") == [80, 81, 82]
    assert parse_ports("22, 80-81") == [22, 80, 81]

def test_parse_ports_invalid():
    with pytest.raises(argparse.ArgumentTypeError):
        parse_ports("65536")
    with pytest.raises(argparse.ArgumentTypeError):
        parse_ports("80-79")
    with pytest.raises(argparse.ArgumentTypeError):
        parse_ports("0")
    with pytest.raises(argparse.ArgumentTypeError):
        parse_ports(",,")
        
def test_report_formatter_json():
    report = ScanReport(
        target="example.com",
        resolved_ip="1.2.3.4",
        open_ports=(80, 443),
        open_count=2,
        closed_count=10,
        filtered_count=5,
        error_count=0,
        elapsed_sec=1.23,
        timestamp="2024-01-01T00:00:00Z"
    )
    
    json_out = ReportFormatter.as_json(report)
    assert '"open_ports": [\n    80,\n    443\n  ]' in json_out
    assert '"target": "example.com"' in json_out

@pytest.mark.asyncio
async def test_token_bucket():
    bucket = TokenBucket(rate=10.0)
    start = time.monotonic()
    
    for _ in range(5):
        await bucket.wait_for_token()
        
    elapsed = time.monotonic() - start
    
    # 5 tokens at 10 tokens/sec. 
    # Because of the leaky bucket algorithm with time_per_token, the first token is instantaneous.
    # The remaining 4 tokens take 4 * 0.1s = 0.4s.
    assert 0.35 <= elapsed <= 0.55

def test_build_output_path():
    assert build_output_path("results_{host}.csv", "1.1.1.1") == "results_1_1_1_1.csv"
    assert build_output_path("output.txt", "localhost") == "output.txt"
