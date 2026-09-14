# PhishGuard-CLI

> **A Modular Cybersecurity Terminal Application for Phishing Domain & Lookalike Detection**  
> Developed for the *Application Development* course curriculum.

---

## 1. Project Overview

**PhishGuard-CLI** is a command-line interface (CLI) application engineered to identify suspicious and phishing domains, detect brand lookalikes, and compute threat probabilities.

While the core problem statement incorporates Machine Learning for risk prediction, the primary focus of this project is **Terminal Application Software Engineering**:
- Clean command hierarchy with subcommands (`scan`, `batch`, `compare`, `train`, `report`, `demo`)
- Strict input validation and URL/domain normalization
- User-centric terminal UX using the [Rich](https://github.com/Textualize/rich) library
- Automation pipelines (batch file ingestion and multi-format report generation)
- Robust error handling with informative hints instead of raw Python tracebacks
- Completely offline, self-contained demonstration flow for college evaluation

---

## 2. Problem Statement

Cyber adversaries register deceptive domain names that imitate the look and feel of reputable brands (e.g., banks, e-commerce, cloud platforms) to harvest credentials and deceive users. 

**Objective:** Build an intelligent command-line utility that:
1. Analyzes lexical characteristics and structural properties of domain names.
2. Identifies brand typosquatting, character substitutions (homoglyphs), and deceptive affixes.
3. Applies a machine learning classifier trained on public phishing data to output a probability score.
4. Generates structured reports (Terminal, JSON, CSV) in a matter of seconds.
5. Operates entirely without complex cloud or database infrastructure.

---

## 3. Key Features

- **Lexical Security Feature Extractor**: Computes 10 explainable structural features including Shannon entropy, length ratios, hyphen/dot counts, subdomain depths, and credential keyword frequencies.
- **Brand Lookalike & Homoglyph Engine**: Leverages `RapidFuzz` string distance algorithms combined with visual homoglyph normalization (e.g., `0` for `o`, `1` for `l`, `rn` for `m`) to catch typosquatting.
- **Explainable Threat Signals**: Highlights human-readable security indicators (e.g., `[HIGH] Contains suspicious phishing keyword: 'verification'`).
- **Machine Learning Inference**: Uses an explainable `RandomForestClassifier` trained on public domain feeds to estimate phishing likelihood from `0.0%` to `100.0%`.
- **Automated Batch Processing**: Ingests multi-line domain lists from CSV files and displays a color-coded summary table.
- **Flexible Report Generation**: Exports structured reports in JSON and CSV formats for audit trails and SIEM ingestion.
- **100% Offline College Demo**: Built-in `phishguard demo` command runs an entire end-to-end evaluation flow offline with zero network dependencies.

---

## 4. Architecture & Directory Structure

```
PhishGuard-CLI/
├── README.md                  # Complete documentation and viva guide
├── requirements.txt           # Python dependencies
├── pyproject.toml             # Packaging metadata & console script entrypoint
├── phishguard                 # Direct root executable launcher script
├── .gitignore
│
├── data/
│   ├── train_dataset.csv      # Documented public dataset (PhishTank & Tranco)
│   └── demo_domains.csv       # Pre-configured sample domains for batch demo
│
├── models/
│   └── phishguard_model.joblib # Serialized RandomForest classifier
│
├── reports/
│   ├── demo_results.json      # Sample JSON scan report
│   └── demo_results.csv       # Sample CSV scan report
│
├── src/
│   └── phishguard/
│       ├── __init__.py        # Package version metadata
│       ├── cli.py             # CLI parser, command routing, Rich interface
│       ├── utils.py           # Domain validation, normalization, and IP checking
│       ├── features.py        # Lexical feature extraction and Shannon entropy
│       ├── similarity.py      # RapidFuzz brand lookalike and typosquatting logic
│       ├── predictor.py       # ML model training, evaluation metrics, and inference
│       ├── web_analyzer.py    # Optional, safe live webpage heuristic analyzer
│       ├── scanner.py         # Unified orchestrator combining all modules
│       └── reporter.py        # Rich terminal panels/tables and JSON/CSV exporters
│
└── tests/
    ├── test_features.py       # 14 tests: validation, protocols, features, entropy
    ├── test_similarity.py     # 12 tests: brand lookalikes, homoglyphs, pairwise diffs
    ├── test_predictor.py      # 6 tests: model training, metrics, bounds, errors
    ├── test_scanner.py        # 6 tests: unified scanner and risk tier calculations
    └── test_cli.py            # 5 tests: subcommands, exports, and offline demo flow
```

---

## 5. Installation (macOS & Linux)

### Prerequisites
- Python 3.9 or higher (Tested on Python 3.14 on macOS)
- `pip` package manager

### Step 1: Clone Repository
```bash
git clone https://github.com/rashmi06an/PhishGuard-CLI.git
cd PhishGuard-CLI
```

### Step 2: Create Virtual Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3: Install Package
```bash
pip install -r requirements.txt
pip install -e .
```

*Tip:* You can now run `phishguard` directly from anywhere in your shell, or use `./phishguard` from the project root.

---

## 6. CLI Command Reference & Examples

### Global Help & Version
```bash
phishguard --help
phishguard --version
```

### 1. Single Target Scan (`scan`)
Scans an individual domain or URL:
```bash
# Scan a legitimate domain
phishguard scan example.com

# Scan a suspicious domain
phishguard scan paypal-secure-login-example.com

# Export scan result directly to JSON
phishguard scan paypal-secure-login-example.com --format json

# Export scan result to a report file
phishguard scan paypal-secure-login-example.com --output reports/result.json
```

**Terminal Output Example:**
```text
╭────────────────── PHISHGUARD CLI — PHISHING DOMAIN SCANNER ──────────────────╮
│                                                                              │
│  Target:                                                                     │
│  paypal-secure-login-example.com                                             │
│                                                                              │
│  Result:                                                                     │
│  PHISHING                                                                    │
│                                                                              │
│  Phishing Probability:                                                       │
│  100.0%                                                                      │
│                                                                              │
│  Risk Level:                                                                 │
│  CRITICAL                                                                    │
│                                                                              │
│  Brand Lookalike:                                                            │
│  Targeting 'paypal' (100.0% similarity)                                      │
│                                                                              │
│  Important Security Signals:                                                 │
│   [HIGH] Contains suspicious phishing keyword(s): 'login', 'secure'          │
│   [MEDIUM] Multiple hyphens in domain (3)                                    │
│   [MEDIUM] High character entropy (3.89) indicates potential algorithmic     │
│  generation                                                                  │
│   [HIGH] Brand name 'paypal' is embedded with suspicious affix/keywords      │
│                                                                              │
╰──────────────────────────────────────────────────────────────────────────────╯
```

---

### 2. Pairwise Domain Comparison (`compare`)
Compares a known genuine brand domain against a suspected lookalike:
```bash
phishguard compare paypal.com paypa1-login.com
```

**Terminal Output Example:**
```text
╭─────────── PHISHGUARD — LOOKALIKE DOMAIN COMPARATOR ────────────╮
│                                                                 │
│  GENUINE DOMAIN:                                                │
│  paypal.com                                                     │
│                                                                 │
│  SUSPICIOUS TARGET:                                             │
│  paypa1-login.com                                               │
│                                                                 │
│  SIMILARITY SCORE:                                              │
│  100.0% (normalized visual / lookalike score)                   │
│                                                                 │
│  DETECTED SIGNALS:                                              │
│   • Target contains the entire brand string 'paypal'            │
│   • Visual character substitution/homoglyph mimicking 'paypal'  │
│                                                                 │
│  VERDICT:                                                       │
│  HIGH LOOKALIKE RISK                                            │
│                                                                 │
╰─────────────────────────────────────────────────────────────────╯
```

---

### 3. Automated Batch Scan (`batch`)
Scans multiple domains listed in a CSV file and outputs a summary table:
```bash
phishguard batch data/demo_domains.csv --output reports/batch_report.json
```

**Output Summary Table:**
```text
                                 PhishGuard Automated Batch Scan Results        
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━
┃ TARGET DOMAIN             ┃  PROBABILITY ┃    RESULT    ┃    RISK    ┃ TOP SIG
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━
│ google.com                │         0.0% │     SAFE     │    LOW     │ Clean  
│ wikipedia.org             │         0.0% │     SAFE     │    LOW     │ Clean  
│ paypal.com                │         0.0% │     SAFE     │    LOW     │ Clean  
│ github.com                │         0.0% │     SAFE     │    LOW     │ Clean  
│ account-verification-ser… │       100.0% │   PHISHING   │  CRITICAL  │ [HIGH] 
│ secure-banking-portal-up… │       100.0% │   PHISHING   │  CRITICAL  │ [HIGH] 
│ paypa1-security-center.c… │        98.0% │   PHISHING   │  CRITICAL  │ [HIGH] 
│ g00gle-account-verificat… │       100.0% │   PHISHING   │  CRITICAL  │ [HIGH] 
│ apple-id-verify-manage.i… │       100.0% │   PHISHING   │  CRITICAL  │ [HIGH] 
│ http://192.168.1.105/log… │        25.0% │     SAFE     │   MEDIUM   │ [CRITIC
└───────────────────────────┴──────────────┴──────────────┴────────────┴────────

Batch Summary: Safe: 5 | Suspicious: 0 | Phishing: 5 (Total Evaluated: 10)
✔ JSON report saved to: reports/batch_report.json
```

---

### 4. Machine Learning Model Training (`train`)
Trains the classifier using the public dataset and calculates precision, recall, and F1-score:
```bash
phishguard train --dataset data/train_dataset.csv
```

---

### 5. Report Inspector (`report`)
Displays and summarizes any previously exported JSON or CSV report:
```bash
phishguard report reports/batch_report.json
phishguard report reports/demo_results.csv
```

---

### 6. College Demonstration Mode (`demo`)
Executes an interactive, complete offline demonstration tailored for evaluation:
```bash
phishguard demo
```
*Requires zero internet connection. Evaluates safe domains, phishing domains, lookalike comparisons, runs a batch scan, and saves demo reports.*

---

## 7. Machine Learning Component

- **Algorithm**: `RandomForestClassifier` (with configurable `LogisticRegression` alternative).
- **Features Extracted (10 Dimensions)**:
  1. `url_length`: Total character length of URL.
  2. `domain_length`: Length of hostname.
  3. `num_dots`: Number of dots (subdomain and TLD count indicators).
  4. `num_hyphens`: Number of hyphens (often used to concatenate deceptive terms).
  5. `num_digits`: Number of numeric digits.
  6. `num_special_chars`: Count of `@`, `_`, `~`, `?`, `=`, `%`, `&`, `#`.
  7. `num_subdomains`: Depth of subdomain labels.
  8. `has_ip`: Binary flag indicating whether the host is a raw IPv4/IPv6 address.
  9. `entropy`: Shannon entropy measuring character randomness (detects DGAs).
  10. `suspicious_keyword_count`: Frequency of credential harvesting keywords.
- **Dataset**: Documented 202 samples curated from public PhishTank archives and Tranco Top 1M domains.
- **Validation**: 80/20 stratified train/test split.

---

## 8. Error Handling Design

PhishGuard implements an exception interception layer. User errors do not produce confusing Python tracebacks:

| Error Scenario | Terminal Handling |
| :--- | :--- |
| **Invalid/Malformed Domain** | Displays `[ERROR] Invalid domain: abc@@.com` with a clear suggestion hint. |
| **Missing Model File** | Displays `[ERROR] Model not found. Run 'phishguard train' first.` |
| **Missing CSV Dataset** | Displays clean notification indicating the file could not be opened. |
| **Unreachable Webpage** | Fails safely: prints `Web analysis unavailable (offline/unreachable)` and continues the scan. |
| **Keyboard Interrupt (`Ctrl+C`)** | Catches `SIGINT` gracefully and prints `Operation cancelled by user.` (exit code 130). |

---

## 9. Automated Testing

The project includes a 43-test suite with 100% pass rate:
```bash
pytest tests/ -v
```

**Test Coverage Summary:**
- `tests/test_features.py`: URL parsing, edge cases, whitespace, IP hosts, entropy calculation.
- `tests/test_similarity.py`: Typosquatting, homoglyph normalization, affixes, pairwise comparison.
- `tests/test_predictor.py`: Missing model exceptions, train pipeline, probability bounds.
- `tests/test_scanner.py`: Orchestrator execution, risk level thresholds, dict serialization.
- `tests/test_cli.py`: Subcommand parsing, batch processing, JSON/CSV exports, offline demo.

---

## 10. Limitations & Future Scope

### Limitations
- **Lexical Focus**: PhishGuard evaluates lexical structure, brand distance, and page metadata; it does not render JavaScript or execute dynamic DOM sandbox analysis.
- **Brand Catalog**: The built-in brand list includes 17 high-profile global targets; regional or niche brands require addition to the database.

### Future Scope
- Integration with live certificate transparency logs.
- Dynamic DNS lookup resolution (WHOIS registration age checking).
- Threat intelligence feed API connectors (VirusTotal, AlienVault OTX).

<!-- --- -->
<!-- 

## 11. College Evaluation Viva Guide (15 Q&As)

1. **Q: Why is this project built as a CLI instead of a web dashboard?**  
   *A:* The assignment specifically focuses on terminal application software engineering: POSIX-compliant argument parsing, exit codes, file streams, pipeable stdout formats, terminal layout engines, and scriptable automation.

2. **Q: How does the application normalize user input?**  
   *A:* Using `urllib.parse` and `tldextract` in `utils.py`. It strips protocols, paths, query parameters, and extracts the registered domain and subdomain labels uniformly.

3. **Q: How can `g00gle.com` have 100% similarity to `google`?**  
   *A:* The 100% score represents *normalized lookalike similarity*, not literal character equality. The system maps visual homoglyphs (`0` to `o`, `1` to `l`) prior to calculating Levenshtein distance, correctly flagging the visual imitation.

4. **Q: What is Shannon entropy and why is it used here?**  
   *A:* Shannon entropy measures information randomness. Random string domains generated by Domain Generation Algorithms (DGAs) have higher entropy (> 3.8) compared to natural language domain names.

5. **Q: What happens if the machine learning model has not been trained?**  
   *A:* The system raises a clean `ModelNotFoundError` advising the user to run `phishguard train`. There is no hidden heuristic bypass in the prediction path.

6. **Q: Why did you use Random Forest instead of Deep Learning?**  
   *A:* Random Forest provides fast training, zero GPU overhead, explainable decision paths, and strong performance on tabular lexical features without risk of extreme overfitting on small datasets.

7. **Q: How does the `batch` command demonstrate automation?**  
   *A:* It ingests CSV files, scans domains sequentially with progress tracking, catches per-row errors without halting execution, and auto-exports structured JSON or CSV reports.

8. **Q: Is internet access required to run the demo?**  
   *A:* No. `phishguard demo` runs 100% offline, using pre-computed feature rules, the local serialized model, and pre-packaged sample domain datasets.

9. **Q: How does the optional web analyzer operate safely?**  
   *A:* It uses read-only HTTP GET requests with a strict 3-second timeout and 256KB read limit. It never enters credentials, submits forms, or executes scripts.

10. **Q: How are risk tiers (LOW, MEDIUM, HIGH, CRITICAL) calculated?**  
    *A:* Using a composite scoring rule in `scanner.py` that balances model probability, brand lookalike status, and critical indicators (e.g., raw IP address host).

11. **Q: What exit codes does the CLI use?**  
    *A:* `0` for successful execution, `1` for user/input errors, `2` for invalid CLI syntax, and `130` for user cancellation (`Ctrl+C`).

12. **Q: How did you ensure cross-platform compatibility on macOS?**  
    *A:* Standard Python libraries, POSIX pathing, UTF-8 character encoding, and packaging via `pyproject.toml` console script entrypoints.

13. **Q: How does PhishGuard prevent false positives on legitimate brands?**  
    *A:* Exact matches to genuine brand names (e.g., `google.com`) are recognized as `EXACT MATCH (GENUINE BRAND)` and flagged with `LOW` risk.

14. **Q: What output formats are supported?**  
    *A:* Terminal UI (Rich panels & tables), machine-readable JSON, and tabular CSV.

15. **Q: How are tests organized?**  
    *A:* Tests are modularized in `tests/` using `pytest`, testing unit features, similarity logic, ML predictions, and CLI integration.

---
<!-- 
## 12. 2-Minute Evaluator Presentation Script

> *"Good morning. Today I am presenting **PhishGuard-CLI**, a terminal application developed for detecting phishing domains and deceptive brand lookalikes.*
> 
> *Our focus was building a professional command-line utility prioritizing software engineering: clean command structure, input validation, automation, Rich terminal UX, and error handling.*
> 
> *The application provides 6 commands:*
> 1. *`scan`: Evaluates an individual domain or URL.*
> 2. *`compare`: Uses RapidFuzz and homoglyph normalization to identify typosquatting against popular brands.*
> 3. *`batch`: Automates scanning of domain lists from CSV files.*
> 4. *`train`: Trains an explainable Random Forest classifier on public phishing datasets.*
> 5. *`report`: Displays and inspects generated JSON and CSV reports.*
> 6. *`demo`: Runs an offline demonstration designed for evaluation without needing internet connectivity.*
> 
> *Let me run `phishguard demo` to demonstrate the end-to-end workflow.*
> *(Run `./phishguard demo`)*
> 
> *As you can see on the terminal, the system validates the domain, extracts 10 lexical features including Shannon entropy, checks brand similarity, runs model inference, and outputs color-coded risk levels and JSON/CSV reports.*
> 
> *All 43 automated unit tests pass, and normal user errors are intercepted with helpful hints instead of Python tracebacks. Thank you."* --> -->
