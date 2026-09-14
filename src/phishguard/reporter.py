"""Terminal presentation and file reporting module for PhishGuard-CLI.

Renders cybersecurity-styled Rich panels and tables, and exports
structured reports in JSON and CSV formats.
"""

import csv
import json
import os
from typing import Any, Dict, List, Union

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from phishguard.scanner import ScanResult

console = Console()


def get_risk_style(risk: str) -> str:
    """Return appropriate Rich color style for a risk tier."""
    if risk == "CRITICAL":
        return "bold red"
    if risk == "HIGH":
        return "bold magenta"
    if risk == "MEDIUM":
        return "bold yellow"
    return "bold green"


def get_classification_style(classification: str) -> str:
    """Return appropriate Rich color style for a classification verdict."""
    if classification == "PHISHING":
        return "bold red"
    if classification == "SUSPICIOUS":
        return "bold yellow"
    return "bold green"


def render_scan_result(res: ScanResult) -> None:
    """Format and print single scan result in professional terminal layout."""
    content = Text()

    # Target
    content.append("Target:\n", style="bold white")
    content.append(f"{res.target}\n\n", style="cyan")

    # Result & Probability
    content.append("Result:\n", style="bold white")
    content.append(f"{res.classification}\n\n", style=get_classification_style(res.classification))

    content.append("Phishing Probability:\n", style="bold white")
    content.append(f"{res.phishing_probability * 100:.1f}%\n\n", style="bold white")

    content.append("Risk Level:\n", style="bold white")
    content.append(f"{res.risk_level}\n\n", style=get_risk_style(res.risk_level))

    # Lookalike information if applicable
    if res.brand_lookalike.is_lookalike and res.brand_lookalike.matched_brand:
        content.append("Brand Lookalike:\n", style="bold white")
        brand_str = f"Targeting '{res.brand_lookalike.matched_brand}' ({res.brand_lookalike.similarity_score:.1f}% similarity)"
        content.append(f"{brand_str}\n\n", style="yellow")

    # Security Signals
    content.append("Important Security Signals:\n", style="bold white")
    if res.signals:
        for sig in res.signals:
            if "[CRITICAL]" in sig or "[HIGH]" in sig:
                sig_style = "bold red"
            elif "[MEDIUM]" in sig:
                sig_style = "yellow"
            else:
                sig_style = "white"
            content.append(f" {sig}\n", style=sig_style)
    else:
        content.append(" [INFO] No suspicious heuristics detected\n", style="dim green")

    # Optional web analysis findings
    if res.web_analysis:
        content.append("\nLive Web Analysis:\n", style="bold white")
        if res.web_analysis.is_accessible:
            title_str = res.web_analysis.title or "N/A"
            content.append(f" Page Title : {title_str}\n", style="dim white")
            content.append(
                f" Login Form : {'Yes' if res.web_analysis.has_login_form else 'No'}\n",
                style="dim white",
            )
            content.append(
                f" Password In: {'Yes' if res.web_analysis.has_password_input else 'No'}\n",
                style="dim white",
            )
        else:
            content.append(
                f" {res.web_analysis.error_message or 'Web analysis unavailable'}\n",
                style="dim yellow",
            )

    panel = Panel(
        content,
        title="[bold white]PHISHGUARD CLI[/bold white] [cyan]— PHISHING DOMAIN SCANNER[/cyan]",
        border_style="bright_blue",
        padding=(1, 2),
        expand=False,
    )
    console.print(panel)


def render_batch_table(results: List[ScanResult]) -> None:
    """Render batch scanning results in a clean terminal table."""
    table = Table(
        title="[bold white]PhishGuard Automated Batch Scan Results[/bold white]",
        border_style="bright_blue",
        header_style="bold cyan",
        show_lines=True,
    )

    table.add_column("TARGET DOMAIN", style="white", min_width=25)
    table.add_column("PROBABILITY", justify="right", min_width=12)
    table.add_column("RESULT", justify="center", min_width=12)
    table.add_column("RISK", justify="center", min_width=10)
    table.add_column("TOP SIGNALS", style="dim", min_width=30)

    for r in results:
        top_sig = r.signals[0] if r.signals else "Clean"
        if len(r.signals) > 1:
            top_sig += f" (+{len(r.signals) - 1} more)"

        table.add_row(
            r.target,
            f"{r.phishing_probability * 100:.1f}%",
            Text(r.classification, style=get_classification_style(r.classification)),
            Text(r.risk_level, style=get_risk_style(r.risk_level)),
            top_sig,
        )

    console.print(table)


def export_to_json(data: Union[Dict[str, Any], List[Dict[str, Any]]], file_path: str) -> None:
    """Save scan data to a formatted JSON report file."""
    os.makedirs(os.path.dirname(file_path) or ".", exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    console.print(f"✔ JSON report saved to: [bold green]{file_path}[/bold green]")


def export_to_csv(results: List[ScanResult], file_path: str) -> None:
    """Save scan results to a formatted CSV report file."""
    os.makedirs(os.path.dirname(file_path) or ".", exist_ok=True)
    fieldnames = [
        "domain",
        "hostname",
        "classification",
        "phishing_probability",
        "risk_level",
        "signal_count",
        "signals",
    ]

    with open(file_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "domain": r.target,
                "hostname": r.hostname,
                "classification": r.classification,
                "phishing_probability": round(r.phishing_probability, 4),
                "risk_level": r.risk_level,
                "signal_count": len(r.signals),
                "signals": "; ".join(r.signals),
            })
    console.print(f"✔ CSV report saved to: [bold green]{file_path}[/bold green]")


def inspect_report_file(file_path: str) -> None:
    """Inspect and display an existing JSON or CSV report file in the terminal."""
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Report file not found: '{file_path}'")

    ext = os.path.splitext(file_path)[1].lower()

    if ext == ".json":
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        console.print(f"\n[cyan]Inspecting JSON Report:[/cyan] [bold]{file_path}[/bold]")
        if isinstance(data, list):
            console.print(f"Total domains recorded: [bold]{len(data)}[/bold]\n")
            table = Table(title="Report Summary", border_style="bright_blue", header_style="bold cyan")
            table.add_column("TARGET", style="white")
            table.add_column("RESULT", justify="center")
            table.add_column("PROBABILITY", justify="right")
            table.add_column("RISK", justify="center")

            for item in data:
                prob_val = item.get("phishing_probability", 0.0)
                prob_str = f"{prob_val * 100:.1f}%" if isinstance(prob_val, (int, float)) else str(prob_val)
                cls_str = str(item.get("classification", "UNKNOWN"))
                risk_str = str(item.get("risk_level", "UNKNOWN"))

                table.add_row(
                    str(item.get("target", item.get("domain", "N/A"))),
                    Text(cls_str, style=get_classification_style(cls_str)),
                    prob_str,
                    Text(risk_str, style=get_risk_style(risk_str)),
                )
            console.print(table)
        else:
            # Single scan dictionary
            console.print_json(data=data)

    elif ext == ".csv":
        with open(file_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        console.print(f"\n[cyan]Inspecting CSV Report:[/cyan] [bold]{file_path}[/bold]")
        console.print(f"Total records found: [bold]{len(rows)}[/bold]\n")

        table = Table(title="CSV Report Summary", border_style="bright_blue", header_style="bold cyan")
        table.add_column("DOMAIN", style="white")
        table.add_column("RESULT", justify="center")
        table.add_column("PROBABILITY", justify="right")
        table.add_column("RISK", justify="center")
        table.add_column("SIGNALS", style="dim")

        for r in rows:
            prob_raw = r.get("phishing_probability", "0")
            try:
                prob_float = float(prob_raw)
                prob_str = f"{prob_float * 100:.1f}%"
            except ValueError:
                prob_str = prob_raw

            cls_str = r.get("classification", "UNKNOWN")
            risk_str = r.get("risk_level", "UNKNOWN")

            table.add_row(
                r.get("domain", "N/A"),
                Text(cls_str, style=get_classification_style(cls_str)),
                prob_str,
                Text(risk_str, style=get_risk_style(risk_str)),
                r.get("signals", "N/A")[:45],
            )
        console.print(table)

    else:
        raise ValueError(f"Unsupported report format '{ext}'. Supported extensions are .json and .csv")
