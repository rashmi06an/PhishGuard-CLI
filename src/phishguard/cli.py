"""Command Line Interface entrypoint for PhishGuard-CLI."""

import argparse
import sys
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from phishguard import __app_name__, __version__
from phishguard.predictor import ModelNotFoundError, train_model
from phishguard.reporter import (
    export_to_csv,
    export_to_json,
    inspect_report_file,
    render_batch_table,
    render_scan_result,
)
from phishguard.scanner import scan_target
from phishguard.similarity import compare_two_domains
from phishguard.utils import validate_target

console = Console()
error_console = Console(stderr=True)


def handle_scan(
    target_raw: str,
    output_format: str = "terminal",
    output_path: Optional[str] = None,
    analyze_web: bool = False,
) -> int:
    """Execute domain scan and format output according to user preferences."""
    try:
        scan_res = scan_target(target_raw, analyze_web=analyze_web)
    except ValueError as exc:
        print_error(f"Invalid domain '{target_raw}': {exc}", suggestion="Try: phishguard scan example.com")
        return 1
    except ModelNotFoundError as exc:
        print_error(str(exc), suggestion="Run 'phishguard train' to train the detection model first.")
        return 1
    except Exception as exc:
        print_error(f"Scan failed: {exc}", suggestion="Check domain structure and try again.")
        return 1

    # Output formatting
    if output_format == "json":
        console.print_json(data=scan_res.to_dict())
    elif output_format == "csv":
        console.print(f"domain,classification,probability,risk_level")
        console.print(
            f"{scan_res.target},{scan_res.classification},"
            f"{scan_res.phishing_probability:.4f},{scan_res.risk_level}"
        )
    else:
        render_scan_result(scan_res)

    # File export if requested
    if output_path:
        ext = output_path.lower()
        if ext.endswith(".csv"):
            export_to_csv([scan_res], output_path)
        else:
            export_to_json(scan_res.to_dict(), output_path)

    return 0


def handle_batch(
    csv_path: str,
    output_format: str = "terminal",
    output_path: Optional[str] = None,
) -> int:
    """Read a list of domains from CSV, run batch scans, and output results."""
    import os
    import pandas as pd

    if not os.path.isfile(csv_path):
        print_error(f"Batch input CSV not found: '{csv_path}'", suggestion="Provide a valid CSV file path, e.g., data/demo_domains.csv")
        return 1

    try:
        df = pd.read_csv(csv_path, comment="#")
    except Exception as exc:
        print_error(f"Malformed CSV file '{csv_path}': {exc}", suggestion="Ensure CSV contains a valid header row with 'domain' or 'url'")
        return 1

    # Detect domain column
    col_candidates = ["domain", "url", "target", "hostname"]
    domain_col = None
    for col in df.columns:
        if str(col).lower().strip() in col_candidates:
            domain_col = col
            break

    if not domain_col:
        print_error(
            f"CSV '{csv_path}' is missing a 'domain' or 'url' column.",
            suggestion=f"Found columns: {list(df.columns)}. Rename target column to 'domain'.",
        )
        return 1

    raw_domains = df[domain_col].dropna().astype(str).str.strip().tolist()
    raw_domains = [d for d in raw_domains if d]

    if not raw_domains:
        print_error(f"CSV file '{csv_path}' contains no valid domain entries.", suggestion="Add at least one domain to scan.")
        return 1

    console.print(f"[cyan]Initiating batch scan for [bold white]{len(raw_domains)}[/bold white] targets from:[/cyan] [bold]{csv_path}[/bold]\n")

    results: List[Any] = []
    failed_count = 0

    with console.status("[bold green]Scanning targets...[/bold green]"):
        for target in raw_domains:
            try:
                res = scan_target(target)
                results.append(res)
            except Exception as exc:
                failed_count += 1
                console.print(f"[dim red]✖ Skipping invalid target '{target}': {exc}[/dim red]")

    if not results:
        print_error("All domain targets in the CSV failed validation or scanning.", suggestion="Check domain syntax.")
        return 1

    # Output rendering
    if output_format == "json":
        console.print_json(data=[r.to_dict() for r in results])
    elif output_format == "csv":
        console.print("domain,classification,probability,risk_level")
        for r in results:
            console.print(f"{r.target},{r.classification},{r.phishing_probability:.4f},{r.risk_level}")
    else:
        render_batch_table(results)

    # Summary statistics
    safe_cnt = sum(1 for r in results if r.classification == "SAFE")
    susp_cnt = sum(1 for r in results if r.classification == "SUSPICIOUS")
    phish_cnt = sum(1 for r in results if r.classification == "PHISHING")

    console.print(
        f"\n[bold white]Batch Summary:[/bold white] "
        f"[green]Safe: {safe_cnt}[/green] | "
        f"[yellow]Suspicious: {susp_cnt}[/yellow] | "
        f"[red]Phishing: {phish_cnt}[/red] "
        f"(Total Evaluated: {len(results)})"
    )

    # File export
    if output_path:
        ext = output_path.lower()
        if ext.endswith(".csv"):
            export_to_csv(results, output_path)
        else:
            export_to_json([r.to_dict() for r in results], output_path)

    return 0


def handle_report(report_file: str) -> int:
    """Inspect and format an existing JSON or CSV report file."""
    try:
        inspect_report_file(report_file)
        return 0
    except FileNotFoundError as exc:
        print_error(f"Report not found: {exc}", suggestion="Provide an existing .json or .csv report path")
        return 1
    except Exception as exc:
        print_error(f"Unable to read report: {exc}", suggestion="Ensure file was generated by PhishGuard in .json or .csv format")
        return 1


def handle_compare(genuine_raw: str, suspicious_raw: str) -> int:
    """Execute the domain comparison workflow and display rich visual results."""
    # 1. Input validation
    try:
        gen_info = validate_target(genuine_raw)
    except ValueError as exc:
        print_error(f"Invalid genuine domain '{genuine_raw}': {exc}", suggestion="Provide a valid domain, e.g., paypal.com")
        return 1

    try:
        susp_info = validate_target(suspicious_raw)
    except ValueError as exc:
        print_error(f"Invalid suspicious domain '{suspicious_raw}': {exc}", suggestion="Provide a valid domain, e.g., paypa1-login.com")
        return 1

    # 2. Perform comparison
    result = compare_two_domains(gen_info.original_input, susp_info.original_input)

    # 3. Format terminal output
    content = Text()
    content.append("GENUINE DOMAIN:\n", style="bold cyan")
    content.append(f"{gen_info.registered_domain or gen_info.hostname}\n\n", style="white")

    content.append("SUSPICIOUS TARGET:\n", style="bold magenta")
    content.append(f"{susp_info.registered_domain or susp_info.hostname}\n\n", style="white")

    content.append("SIMILARITY SCORE:\n", style="bold yellow")
    content.append(f"{result.similarity_score:.1f}% ", style="bold white")
    content.append("(normalized visual / lookalike score)\n\n", style="dim italic white")

    content.append("DETECTED SIGNALS:\n", style="bold cyan")
    if result.signals:
        for sig in result.signals:
            content.append(f" • {sig}\n", style="yellow")
    else:
        content.append(" • No significant lookalike patterns detected\n", style="dim")
    content.append("\n")

    content.append("VERDICT:\n", style="bold white")
    if "HIGH" in result.verdict:
        verdict_style = "bold red"
    elif "SUSPICIOUS" in result.verdict:
        verdict_style = "bold yellow"
    elif "IDENTICAL" in result.verdict:
        verdict_style = "bold green"
    else:
        verdict_style = "bold cyan"

    content.append(f"{result.verdict}\n", style=verdict_style)

    panel = Panel(
        content,
        title="[bold white]PHISHGUARD[/bold white] [cyan]— LOOKALIKE DOMAIN COMPARATOR[/cyan]",
        border_style="bright_blue",
        padding=(1, 2),
        expand=False,
    )
    console.print(panel)
    return 0


def handle_train(dataset_path: str, model_type: str, output_model: str) -> int:
    """Execute model training and print evaluation metrics."""
    console.print(f"[cyan]Loading dataset from:[/cyan] [bold white]{dataset_path}[/bold white]")
    console.print(f"[cyan]Classifier algorithm:[/cyan] [bold yellow]{model_type.replace('_', ' ').title()}[/bold yellow]")

    with console.status("[bold green]Extracting features & training model...[/bold green]"):
        try:
            metrics = train_model(
                dataset_path=dataset_path,
                model_type=model_type,
                output_path=output_model,
            )
        except Exception as exc:
            print_error(f"Training failed: {exc}", suggestion="Verify dataset path and column format ('url', 'label')")
            return 1

    content = Text()
    content.append("Model Training Complete\n", style="bold green")
    content.append("──────────────────────────────────────────\n", style="bright_blue")
    content.append(f"Dataset Samples: {metrics['dataset_samples']} URLs\n", style="white")
    content.append(f"Train / Test Split: {metrics['train_samples']} / {metrics['test_samples']}\n\n", style="dim white")

    content.append(f"Accuracy : {metrics['accuracy']:.1f}%\n", style="bold white")
    content.append(f"Precision: {metrics['precision']:.1f}%\n", style="bold white")
    content.append(f"Recall   : {metrics['recall']:.1f}%\n", style="bold white")
    content.append(f"F1 Score : {metrics['f1_score']:.1f}%\n\n", style="bold white")

    content.append("✔ Model saved successfully to: ", style="cyan")
    content.append(f"{output_model}\n", style="bold green")

    panel = Panel(
        content,
        title="[bold white]PHISHGUARD[/bold white] [cyan]— MACHINE LEARNING PIPELINE[/cyan]",
        border_style="bright_blue",
        padding=(1, 2),
        expand=False,
    )
    console.print(panel)
    return 0


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
            code = handle_scan(args.target, args.format, args.output, args.analyze_web)
            sys.exit(code)
        elif args.command == "batch":
            code = handle_batch(args.csv_path, args.format, args.output)
            sys.exit(code)
        elif args.command == "compare":
            code = handle_compare(args.genuine, args.suspicious)
            sys.exit(code)
        elif args.command == "train":
            code = handle_train(args.dataset, args.model_type, args.output_model)
            sys.exit(code)
        elif args.command == "report":
            code = handle_report(args.report_file)
            sys.exit(code)
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
