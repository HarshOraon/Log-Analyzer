#!/usr/bin/env python3
"""
Log Analyzer CLI
Advanced multi-format log analysis with anomaly detection, ML clustering, and rich reporting.
"""
import sys
import time
from pathlib import Path

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

console = Console()

sys.path.insert(0, str(Path(__file__).parent))

from parsers.parser import LogParser
from analyzers.anomaly import AnomalyDetector
from analyzers.stats import LogAnalyzer
from analyzers.clustering import LogClusterer, TemplateExtractor
from exporters.reporter import print_parse_summary, print_full_report
from exporters.exporter import export_json, export_html


@click.group()
def cli():
    """🔍 Log Analyzer — Advanced multi-format log analysis tool."""
    pass


@cli.command()
@click.argument("log_file", type=click.Path(exists=True))
@click.option("--json-out", "-j", type=click.Path(), default=None, help="Export JSON report")
@click.option("--html-out", "-H", type=click.Path(), default=None, help="Export HTML report")
@click.option("--cluster", "-c", is_flag=True, default=False, help="Run ML clustering")
@click.option("--templates", "-t", is_flag=True, default=False, help="Extract log templates (Drain)")
@click.option("--top-n", "-n", default=15, show_default=True, help="Show top N results in tables")
@click.option("--z-threshold", default=3.0, show_default=True, help="Z-score threshold for anomalies")
@click.option("--no-anomaly", is_flag=True, default=False, help="Skip anomaly detection")
@click.option("--filter-level", "-l", default=None, help="Filter to level: DEBUG,INFO,WARNING,ERROR,CRITICAL")
@click.option("--filter-source", "-s", default=None, help="Filter entries by source/logger substring")
@click.option("--limit", default=0, help="Limit to first N entries (0=all)")
def analyze(log_file, json_out, html_out, cluster, templates, top_n,
            z_threshold, no_anomaly, filter_level, filter_source, limit):
    """Analyze a log file and print a rich report."""
    path = Path(log_file)
    console.print(f"\n[bold blue]Analyzing:[/] {path.name} ({path.stat().st_size / 1024:.1f} KB)")

    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
        BarColumn(), TimeElapsedColumn(), console=console
    ) as progress:
        task = progress.add_task("Parsing...", total=None)
        parser = LogParser()
        result = parser.parse_file(path)
        progress.update(task, description="Parsed ✓", completed=1, total=1)

    print_parse_summary(result)

    entries = result.entries

    if filter_level:
        lvl_name = filter_level.upper()
        entries = [e for e in entries if e.level.name == lvl_name]
        console.print(f"  Filter level={lvl_name}: {len(entries):,} entries")

    if filter_source:
        entries = [e for e in entries if filter_source.lower() in (e.source + e.logger + e.host).lower()]
        console.print(f"  Filter source={filter_source!r}: {len(entries):,} entries")

    if limit and limit > 0:
        entries = entries[:limit]
        console.print(f"  Limited to first {limit:,} entries")

    if not entries:
        console.print("[yellow]No entries to analyze after filtering.[/]")
        return

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  console=console) as progress:
        task = progress.add_task("Detecting anomalies...", total=None)
        anomalies = []
        if not no_anomaly:
            detector = AnomalyDetector(z_threshold=z_threshold)
            anomalies = detector.detect_all(entries)
        progress.update(task, description=f"Anomalies: {len(anomalies)} detected ✓")

        progress.update(task, description="Running statistical analysis...")
        analyzer = LogAnalyzer()
        report = analyzer.analyze(entries, anomalies)
        progress.update(task, description="Analysis complete ✓")

    cluster_summaries = None
    if cluster and len(entries) >= 10:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      console=console) as progress:
            task = progress.add_task("ML clustering...", total=None)
            clusterer = LogClusterer(n_clusters=min(15, len(entries) // 5))
            clusterer.fit(entries)
            cluster_summaries = clusterer.cluster_summaries_
            progress.update(task, description=f"Clustering done: {len(cluster_summaries)} clusters ✓")

    if templates and len(entries) >= 5:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      console=console) as progress:
            task = progress.add_task("Extracting templates...", total=None)
            extractor = TemplateExtractor()
            tmpls = extractor.extract_templates(entries)
            progress.update(task, description=f"Templates extracted: {len(tmpls)} ✓")
        from rich.table import Table
        from rich import box
        t = Table(title="Log Templates (Drain)", box=box.SIMPLE_HEAVY, header_style="bold magenta")
        t.add_column("Count", justify="right")
        t.add_column("Level")
        t.add_column("Template")
        for tmpl in tmpls[:20]:
            t.add_row(str(tmpl["count"]), tmpl["sample_entry_level"], tmpl["template"][:120])
        console.print(t)

    print_full_report(report, show_clusters=cluster_summaries)

    if json_out:
        export_json(report, result, json_out)
        console.print(f"[green]JSON report saved:[/] {json_out}")

    if html_out:
        export_html(report, result, html_out)
        console.print(f"[green]HTML report saved:[/] {html_out}")


@cli.command()
@click.argument("log_files", nargs=-1, type=click.Path(exists=True))
@click.option("--json-out", "-j", type=click.Path(), default=None)
@click.option("--html-out", "-H", type=click.Path(), default=None)
def merge(log_files, json_out, html_out):
    """Merge and analyze multiple log files together."""
    if not log_files:
        console.print("[red]Provide at least one log file.[/]")
        return
    parser = LogParser()
    all_entries = []
    for lf in log_files:
        console.print(f"Parsing {lf}...")
        result = parser.parse_file(lf)
        all_entries.extend(result.entries)
        print_parse_summary(result)

    console.print(f"\n[bold]Merged: {len(all_entries):,} total entries from {len(log_files)} files[/]")
    detector = AnomalyDetector()
    anomalies = detector.detect_all(all_entries)
    analyzer = LogAnalyzer()
    last_result = parser.parse_file(log_files[-1])
    report = analyzer.analyze(all_entries, anomalies)
    print_full_report(report)

    if json_out:
        export_json(report, last_result, json_out)
        console.print(f"[green]JSON saved:[/] {json_out}")
    if html_out:
        export_html(report, last_result, html_out)
        console.print(f"[green]HTML saved:[/] {html_out}")


@cli.command()
@click.option("--output-dir", "-o", default="sample_logs", show_default=True)
def generate_samples(output_dir):
    """Generate diverse sample log files for testing."""
    from utils.sample_generator import generate_all
    generate_all(Path(output_dir))
    console.print(f"[green]Sample logs generated in [bold]{output_dir}/[/][/]")


@cli.command()
@click.argument("log_file", type=click.Path(exists=True))
@click.option("--tail", "-f", is_flag=True, help="Tail-follow mode (watch for new lines)")
@click.option("--lines", "-n", default=50, show_default=True)
@click.option("--level", default="WARNING", show_default=True, help="Minimum level to show")
def watch(log_file, tail, lines, level):
    """Watch a log file and print new anomalous entries in real-time."""
    from core.models import LogLevel
    from analyzers.anomaly import SENSITIVE_PATTERNS
    import re
    min_level = LogLevel.from_string(level)
    path = Path(log_file)
    parser = LogParser()

    def check_entry(entry):
        if entry.level.value >= min_level.value:
            return True
        for pat, _ in SENSITIVE_PATTERNS:
            if pat.search(entry.raw):
                return True
        return False

    console.print(f"[bold]Watching:[/] {path} (level>={level})")
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        all_lines = f.readlines()
        start = max(0, len(all_lines) - lines)
        sample = [l.rstrip() for l in all_lines[:200] if l.strip()]
        from parsers.parser import _detect_format
        fmt = _detect_format(sample)
        for i, line in enumerate(all_lines[start:], start=start + 1):
            entry = parser._parse_line(line, fmt, i)
            if entry and check_entry(entry):
                lvl_style = {"ERROR": "red", "CRITICAL": "bold red", "WARNING": "yellow",
                             "FATAL": "bold bright_red"}.get(entry.level.name, "white")
                console.print(f"[{lvl_style}][{entry.level.name}][/] {entry.message or entry.raw[:120]}")
        if not tail:
            return
        import time as _time
        console.print("[dim]Following... (Ctrl+C to stop)[/]")
        try:
            while True:
                new_line = f.readline()
                if new_line:
                    entry = parser._parse_line(new_line, fmt, 0)
                    if entry and check_entry(entry):
                        lvl_style = {"ERROR": "red", "CRITICAL": "bold red", "WARNING": "yellow",
                                     "FATAL": "bold bright_red"}.get(entry.level.name, "white")
                        console.print(f"[{lvl_style}][{entry.level.name}][/] {entry.message or entry.raw[:120]}")
                else:
                    _time.sleep(0.2)
        except KeyboardInterrupt:
            console.print("\n[dim]Watch stopped.[/]")


if __name__ == "__main__":
    cli()
