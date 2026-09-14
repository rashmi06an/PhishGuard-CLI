"""Terminal presentation and file reporting module for PhishGuard-CLI.

Renders high-aesthetic, cybersecurity-styled Rich panels, metric meters,
and tables, and exports structured reports in JSON and CSV formats.
"""

import csv
import json
import os
from typing import Any, Dict, List, Union

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from phishguard.scanner import ScanResult

console = Console()


def create_meter(prob: float, width: int = 14) -> Text:
    """Render a modern visual progress bar for probability percentages."""
    percentage = max(0.0, min(1.0, prob))
    filled_len = int(round(percentage * width))
    empty_len = width - filled_len

    if percentage >= 0.70:
        bar_color = "bright_red"
    elif percentage >= 0.40:
        bar_color = "bright_yellow"
    else:
        bar_color = "bright_green"

    meter = Text()
    meter.append(f"{percentage * 100:>5.1f}% ", style="bold white")
    meter.append("▕", style="dim white")
    meter.append("█" * filled_len, style=f"bold {bar_color}")
    meter.append("░" * empty_len, style="dim white")
    meter.append("▏", style="dim white")
    return meter


def get_risk_badge(risk: str) -> Text:
    """Format risk level as a colorful terminal badge."""
    badge = Text()
    if risk == "CRITICAL":
        badge.append(" CRITICAL ", style="bold white on red")
    elif risk == "HIGH":
        badge.append(" HIGH RISK ", style="bold white on dark_magenta")
    elif risk == "MEDIUM":
        badge.append(" MEDIUM ", style="bold black on yellow")
    else:
        badge.append(" LOW RISK ", style="bold white on dark_green")
    return badge


def get_verdict_badge(classification: str) -> Text:
    """Format classification verdict as a high-contrast badge."""
    badge = Text()
    if classification == "PHISHING":
        badge.append(" ✖ PHISHING ", style="bold white on red")
    elif classification == "SUSPICIOUS":
        badge.append(" ⚠ SUSPICIOUS ", style="bold black on yellow")
    else:
        badge.append(" ✔ SAFE ", style="bold white on green")
    return badge


def render_scan_result(res: ScanResult) -> None:
    """Format and print a single scan result in a premium cybersecurity card layout."""
    card = Table(show_header=False, show_edge=False, box=None, expand=True, padding=(0, 0))

    # Top Assessment Summary Grid (2 rows for comfortable fit without truncation)
    summary_grid = Table(box=None, show_header=False, expand=True, padding=(0, 1))
    summary_grid.add_column("label", style="bold bright_cyan", width=15)
    summary_grid.add_column("val", style="white")

    summary_grid.add_row("Target Host", f"[bold white]{res.hostname or res.target}[/bold white]")

    # Assessment Row (Verdict and Risk)
    verdict_row = Text()
    verdict_row.append_text(get_verdict_badge(res.classification))
    verdict_row.append("   Threat Level: ", style="bold cyan")
    verdict_row.append_text(get_risk_badge(res.risk_level))
    summary_grid.add_row("Verdict", verdict_row)

    # Probability Row (Progress meter)
    prob_row = Text()
    prob_row.append_text(create_meter(res.phishing_probability, width=16))
    prob_row.append(f"  ({res.risk_level.title()} Confidence)", style="dim white")
    summary_grid.add_row("Probability", prob_row)

    card.add_row(summary_grid)

    # Horizontal divider
    card.add_row(Text("─" * 70, style="dim blue"))

    # Section 1: Domain Structural Profile
    entropy_val = res.features.get("entropy", 0.0)
    entropy_desc = "(Elevated / Random)" if entropy_val >= 3.5 else "(Normal Lexical)"
    sub_count = res.features.get("num_subdomains", 0)
    hyphen_count = res.features.get("num_hyphens", 0)
    digit_count = res.features.get("num_digits", 0)
    url_len = res.features.get("url_length", len(res.target))

    profile_text = Text.from_markup(
        f"🌐 [bold cyan]Domain Profile:[/] Registered: [bold white]{res.registered_domain or 'N/A'}[/bold white]  •  "
        f"Entropy: [white]{entropy_val:.2f} bits[/white] [dim]{entropy_desc}[/dim]\n"
        f"   [bold cyan]Lexical Stats :[/] Length: [white]{url_len} chars[/white]  •  "
        f"Subdomains: [white]{sub_count}[/white]  •  Hyphens: [white]{hyphen_count}[/white]  •  Digits: [white]{digit_count}[/white]"
    )
    card.add_row(profile_text)

    # Section 2: Brand Lookalike Pattern (if triggered)
    if res.brand_lookalike.is_lookalike and res.brand_lookalike.matched_brand:
        card.add_row(Text("─" * 70, style="dim blue"))
        lookalike_text = Text.from_markup(
            f"🎯 [bold yellow]Brand Lookalike:[/] Targeting '[bold white]{res.brand_lookalike.matched_brand}[/]' "
            f"([bold cyan]{res.brand_lookalike.similarity_score:.1f}% visual lookalike match[/]) "
            f"[bold red][{res.brand_lookalike.verdict}][/bold red]"
        )
        card.add_row(lookalike_text)

    # Section 3: Threat Signals
    card.add_row(Text("─" * 70, style="dim blue"))
    card.add_row(Text.from_markup(f"🔍 [bold bright_cyan]Key Security Signals & Indicators ({len(res.signals)})[/bold bright_cyan]"))

    if res.signals:
        for sig in res.signals:
            if "[CRITICAL]" in sig:
                clean = sig.replace("[CRITICAL]", "").strip()
                card.add_row(Text.from_markup(f"   [bold red]⛔ {clean}[/bold red]"))
            elif "[HIGH]" in sig:
                clean = sig.replace("[HIGH]", "").strip()
                card.add_row(Text.from_markup(f"   [bright_red]🔴 {clean}[/bright_red]"))
            elif "[MEDIUM]" in sig:
                clean = sig.replace("[MEDIUM]", "").strip()
                card.add_row(Text.from_markup(f"   [bright_yellow]🟡 {clean}[/bright_yellow]"))
            else:
                clean = sig.replace("[LOW]", "").strip()
                card.add_row(Text.from_markup(f"   [white]⚪ {clean}[/white]"))
    else:
        card.add_row(Text.from_markup("   [dim green]🟢 No anomalous lexical patterns, brand homoglyphs, or phishing keywords detected.[/dim green]"))

    # Section 4: Web Analysis (if active)
    if res.web_analysis:
        card.add_row(Text("─" * 70, style="dim blue"))
        if res.web_analysis.is_accessible:
            has_form = "[bold red]Yes[/bold red]" if res.web_analysis.has_login_form else "[green]No[/green]"
            has_pwd = "[bold red]Yes[/bold red]" if res.web_analysis.has_password_input else "[green]No[/green]"
            card.add_row(Text.from_markup(
                f"🌐 [bold cyan]Live Webpage Heuristics:[/] Title='[white]{res.web_analysis.title or 'N/A'}[/]' • "
                f"Login Form={has_form} • Password Field={has_pwd}"
            ))
        else:
            msg = res.web_analysis.error_message or "Analysis unavailable (Safe Offline Mode)"
            card.add_row(Text.from_markup(f"🌐 [bold cyan]Live Webpage Heuristics:[/] [dim yellow]{msg}[/dim yellow]"))

    # Section 5: Actionable Recommendation
    card.add_row(Text("─" * 70, style="dim blue"))
    if res.classification == "PHISHING":
        card.add_row(Text.from_markup("💡 [bold cyan]Actionable Guidance:[/] [bold red]🚨 HIGH THREAT — Block domain immediately. Likely deceptive site or credential theft.[/bold red]"))
    elif res.classification == "SUSPICIOUS":
        card.add_row(Text.from_markup("💡 [bold cyan]Actionable Guidance:[/] [bold yellow]⚠️  SUSPICIOUS — Elevated risk patterns. Verify TLS certificate and domain owner.[/bold yellow]"))
    else:
        card.add_row(Text.from_markup("💡 [bold cyan]Actionable Guidance:[/] [green]✅ BENIGN — Standard lexical characteristics. No brand impersonation detected.[/green]"))

    panel = Panel(
        card,
        title="[bold white]🛡️  PHISHGUARD[/bold white] [cyan]• SECURITY SCAN REPORT[/cyan]",
        subtitle=f"[dim cyan]{res.target}[/dim cyan]",
        border_style="bright_blue",
        box=box.ROUNDED,
        padding=(1, 2),
        expand=False,
    )
    console.print(panel)


def render_batch_table(results: List[ScanResult]) -> None:
    """Render batch scanning results in a clean, high-contrast terminal table."""
    table = Table(
        title="[bold white]🛡️  PhishGuard Automated Batch Threat Assessment[/bold white]",
        border_style="bright_blue",
        header_style="bold bright_cyan",
        box=box.ROUNDED,
        show_lines=True,
    )

    table.add_column("#", justify="center", style="dim", width=4)
    table.add_column("TARGET DOMAIN", style="bold white", min_width=22, max_width=30, no_wrap=True)
    table.add_column("VERDICT", justify="center", width=14)
    table.add_column("PROBABILITY", justify="center", width=15)
    table.add_column("RISK", justify="center", width=12)

    include_signals = console.width >= 105
    if include_signals:
        table.add_column("KEY SECURITY SIGNAL", style="dim white", min_width=22)

    for idx, r in enumerate(results, 1):
        row_items = [
            str(idx),
            r.target,
            get_verdict_badge(r.classification),
            create_meter(r.phishing_probability, width=5),
            get_risk_badge(r.risk_level),
        ]
        if include_signals:
            top_sig = "Clean (Benign)"
            if r.signals:
                clean_first = (
                    r.signals[0]
                    .replace("[CRITICAL]", "")
                    .replace("[HIGH]", "")
                    .replace("[MEDIUM]", "")
                    .replace("[LOW]", "")
                    .strip()
                )
                top_sig = clean_first
                if len(r.signals) > 1:
                    top_sig += f" [cyan](+{len(r.signals) - 1})[/cyan]"
            row_items.append(top_sig)

        table.add_row(*row_items)

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

        console.print(f"\n[bold cyan]▶ Inspecting JSON Report File:[/bold cyan] [bold white]{file_path}[/bold white]")
        if isinstance(data, list):
            console.print(f"Total domains recorded: [bold cyan]{len(data)}[/bold cyan]\n")
            table = Table(
                title="🛡️  PhishGuard Report Summary",
                border_style="bright_blue",
                header_style="bold bright_cyan",
                box=box.ROUNDED,
                show_lines=True,
            )
            table.add_column("TARGET DOMAIN", style="bold white", min_width=22, max_width=30, no_wrap=True)
            table.add_column("VERDICT", justify="center", width=14)
            table.add_column("PROBABILITY", justify="center", width=15)
            table.add_column("RISK", justify="center", width=12)

            for item in data:
                prob_val = item.get("phishing_probability", 0.0)
                cls_str = str(item.get("classification", "UNKNOWN"))
                risk_str = str(item.get("risk_level", "UNKNOWN"))

                table.add_row(
                    str(item.get("target", item.get("domain", "N/A"))),
                    get_verdict_badge(cls_str),
                    create_meter(float(prob_val) if isinstance(prob_val, (int, float)) else 0.0, width=5),
                    get_risk_badge(risk_str),
                )
            console.print(table)
        else:
            console.print_json(data=data)

    elif ext == ".csv":
        with open(file_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        console.print(f"\n[bold cyan]▶ Inspecting CSV Report File:[/bold cyan] [bold white]{file_path}[/bold white]")
        console.print(f"Total records found: [bold cyan]{len(rows)}[/bold cyan]\n")

        table = Table(
            title="🛡️  PhishGuard CSV Report Summary",
            border_style="bright_blue",
            header_style="bold bright_cyan",
            box=box.ROUNDED,
            show_lines=True,
        )
        table.add_column("TARGET DOMAIN", style="bold white", min_width=22, max_width=30, no_wrap=True)
        table.add_column("VERDICT", justify="center", width=14)
        table.add_column("PROBABILITY", justify="center", width=15)
        table.add_column("RISK", justify="center", width=12)

        for r in rows:
            prob_raw = r.get("phishing_probability", "0")
            try:
                prob_float = float(prob_raw)
            except ValueError:
                prob_float = 0.0

            cls_str = r.get("classification", "UNKNOWN")
            risk_str = r.get("risk_level", "UNKNOWN")

            table.add_row(
                r.get("domain", "N/A"),
                get_verdict_badge(cls_str),
                create_meter(prob_float, width=5),
                get_risk_badge(risk_str),
            )
        console.print(table)

    else:
        raise ValueError(f"Unsupported report format '{ext}'. Supported extensions are .json and .csv")
