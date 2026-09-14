"""Command Line Interface entrypoint for PhishGuard-CLI."""

import argparse
import sys
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from phishguard import __app_name__, __version__

console = Console()
error_console = Console(stderr=True)


def display_banner(subtitle: Optional[str] = None) -> None:
    """Render a clean, cybersecurity-styled CLI header banner."""
    header_text = Text()
    header_text.append("🛡️  ", style="bold cyan")
    header_text.append(__app_name__.upper(), style="bold white")
    header_text.append(f" [v{__version__}]\n", style="cyan")
    header_text.append(
        "Intelligent Phishing Domain & Lookalike Detection Utility",
        style="dim white",
    )
    if subtitle:
        header_text.append(f"\n{subtitle}", style="bold yellow")

    panel = Panel(
        header_text,
        border_style="bright_blue",
        expand=False,
        padding=(0, 2),
    )
    console.print(panel)


def print_error(message: str, suggestion: Optional[str] = None) -> None:
    """Print a clean, user-friendly error box without a Python traceback."""
    err_text = Text()
    err_text.append("✖ [ERROR] ", style="bold red")
    err_text.append(message, style="white")
    if suggestion:
        err_text.append(f"\n💡 Hint: {suggestion}", style="yellow")

    error_panel = Panel(
        err_text,
        border_style="red",
        title="Command Error",
        title_align="left",
        expand=False,
    )
    error_console.print(error_panel)


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser and subcommands."""
    parser = argparse.ArgumentParser(
        prog="phishguard",
        description=(
            "PhishGuard-CLI: A professional terminal application for detecting "
            "phishing domains, visual lookalikes, and typosquatting risks."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  phishguard scan example.com\n"
            "  phishguard scan paypal-secure-login-example.com --format json\n"
            "  phishguard batch data/demo_domains.csv --output reports/results.json\n"
            "  phishguard compare paypal.com paypa1-login.com\n"
            "  phishguard train --dataset data/train_dataset.csv\n"
            "  phishguard demo\n"
        ),
    )

    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="Show version information and exit",
    )

    subparsers = parser.add_subparsers(
        title="Available Commands",
        dest="command",
        metavar="<command>",
        help="Run 'phishguard <command> --help' for command-specific options",
    )

    # 1. SCAN
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a single domain or URL for phishing indicators",
        description="Analyzes lexical structure, brand similarity, and ML phishing probability for a target.",
    )
    scan_parser.add_argument(
        "target",
        help="Domain or URL to scan (e.g., example.com, https://secure-login.net)",
    )
    scan_parser.add_argument(
        "-f", "--format",
        choices=["terminal", "json", "csv"],
        default="terminal",
        help="Output format (default: terminal)",
    )
    scan_parser.add_argument(
        "-o", "--output",
        metavar="PATH",
        help="Path to save scan result file (e.g., reports/scan_result.json)",
    )
    scan_parser.add_argument(
        "-w", "--analyze-web",
        action="store_true",
        help="Perform optional live webpage analysis (checks login inputs, forms; fails safely if offline)",
    )

    # 2. BATCH
    batch_parser = subparsers.add_parser(
        "batch",
        help="Scan multiple domains from a CSV file in automated batch mode",
        description="Reads a list of domains from a CSV and runs automated phishing evaluations.",
    )
    batch_parser.add_argument(
        "csv_path",
        metavar="CSV_FILE",
        help="Path to input CSV containing a 'domain' or 'url' column",
    )
    batch_parser.add_argument(
        "-f", "--format",
        choices=["terminal", "json", "csv"],
        default="terminal",
        help="Output format for batch summary (default: terminal)",
    )
    batch_parser.add_argument(
        "-o", "--output",
        metavar="PATH",
        help="Path to save batch report (e.g., reports/batch_results.json)",
    )

    # 3. COMPARE
    compare_parser = subparsers.add_parser(
        "compare",
        help="Compare a suspicious domain against a genuine brand domain",
        description="Evaluates string distance, typosquatting patterns, and lookalike risk between two domains.",
    )
    compare_parser.add_argument(
        "genuine",
        help="Legitimate domain (e.g., paypal.com)",
    )
    compare_parser.add_argument(
        "suspicious",
        help="Suspicious lookalike domain (e.g., paypa1-login.com)",
    )

    # 4. TRAIN
    train_parser = subparsers.add_parser(
        "train",
        help="Train the machine learning model on a public phishing dataset",
        description="Extracts lexical features, trains a classifier, evaluates metrics, and saves the model.",
    )
    train_parser.add_argument(
        "-d", "--dataset",
        default="data/train_dataset.csv",
        help="Path to training CSV dataset (default: data/train_dataset.csv)",
    )
    train_parser.add_argument(
        "-m", "--model-type",
        choices=["random_forest", "logistic_regression"],
        default="random_forest",
        help="ML algorithm to train (default: random_forest)",
    )
    train_parser.add_argument(
        "-o", "--output-model",
        default="models/phishguard_model.joblib",
        help="Destination path for serialized model (default: models/phishguard_model.joblib)",
    )

    # 5. REPORT
    report_parser = subparsers.add_parser(
        "report",
        help="Inspect and display an existing JSON or CSV report file",
        description="Parses a previously exported PhishGuard scan/batch report and displays a formatted summary.",
    )
    report_parser.add_argument(
        "report_file",
        help="Path to report file (.json or .csv)",
    )

    # 6. DEMO
    subparsers.add_parser(
        "demo",
        help="Run an offline, college evaluation demonstration scenario",
        description="Executes a self-contained offline demo showcasing safe, suspicious, and lookalike domain detection.",
    )

    return parser


def main() -> None:
    """Main CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        display_banner()
        parser.print_help()
        sys.exit(0)

    try:
        if args.command == "scan":
            console.print(f"[cyan]Scan command invoked for target:[/cyan] [bold]{args.target}[/bold]")
        elif args.command == "batch":
            console.print(f"[cyan]Batch command invoked for file:[/cyan] [bold]{args.csv_path}[/bold]")
        elif args.command == "compare":
            console.print(
                f"[cyan]Compare command invoked:[/cyan] genuine=[bold]{args.genuine}[/bold], "
                f"suspicious=[bold]{args.suspicious}[/bold]"
            )
        elif args.command == "train":
            console.print(f"[cyan]Train command invoked with dataset:[/cyan] [bold]{args.dataset}[/bold]")
        elif args.command == "report":
            console.print(f"[cyan]Report command invoked for file:[/cyan] [bold]{args.report_file}[/bold]")
        elif args.command == "demo":
            console.print("[cyan]Demo command invoked.[/cyan]")
        else:
            parser.print_help()
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user.[/yellow]")
        sys.exit(130)
    except Exception as exc:
        print_error(str(exc), suggestion="Check your command parameters or run 'phishguard --help'")
        sys.exit(1)


if __name__ == "__main__":
    main()
