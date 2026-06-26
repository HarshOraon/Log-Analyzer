# Log Analyzer

Advanced multi-format log analysis with anomaly detection, ML clustering, and rich reporting.

## Features

- **Auto-detects** Apache Common/Combined, Nginx, Syslog, Log4j, Python, JSON log formats
- **Compressed file support**: `.gz` and `.bz2`
- **Anomaly detection**:
  - Security patterns: SQL injection, XSS, path traversal, LFI, credential leaks, TLS errors
  - Traffic bursts (z-score based)
  - Latency spike detection from embedded durations
  - Repeated error clustering
  - High-frequency source detection
- **ML clustering**: TF-IDF + LSA + MiniBatchKMeans on log messages
- **Template extraction**: Drain-inspired log template mining
- **Exports**: rich terminal output, JSON, dark-themed HTML dashboard
- **Watch mode**: tail-follow with real-time anomaly flagging

## Project Structure

```
log_analyzer/
├── main.py                  # CLI entry point
├── core/
│   └── models.py            # LogEntry, ParseResult, AnalysisReport
├── parsers/
│   └── parser.py            # Multi-format auto-detecting parser
├── analyzers/
│   ├── anomaly.py           # Rule + statistical anomaly detection
│   ├── stats.py             # Pattern extraction, throughput, distribution
│   └── clustering.py        # TF-IDF + KMeans, Drain templates
├── exporters/
│   ├── reporter.py          # Rich terminal report
│   └── exporter.py          # JSON + HTML export
├── utils/
│   └── sample_generator.py  # Generate test logs
└── tests/
    └── test_all.py          # 22-test suite
```

## Setup

```bash
pip install -r requirements.txt
```

## Usage

### Generate sample logs

```bash
python main.py generate-samples
```

### Analyze a log file

```bash
python main.py analyze sample_logs/app.log
```

### Export to JSON + HTML

```bash
python main.py analyze sample_logs/access.log --html-out report.html --json-out report.json
```

### Enable ML clustering and template extraction

```bash
python main.py analyze sample_logs/service.log --cluster --templates
```

### Filter by level or source

```bash
python main.py analyze app.log --filter-level ERROR --filter-source auth
```

### Merge multiple files

```bash
python main.py merge sample_logs/*.log --html-out merged.html
```

### Watch / tail a live log

```bash
python main.py watch app.log --level WARNING
python main.py watch app.log --tail --level ERROR     # follow mode
```

## Run Tests

```bash
cd log_analyzer
python tests/test_all.py
```

## Anomaly Score Reference

| Score | Severity     | Typical type                     |
|-------|--------------|----------------------------------|
| 9–10  | Critical     | SQL injection, code execution     |
| 7–9   | High         | Other security patterns, bursts  |
| 5–7   | Medium       | Repeated errors, latency spikes  |
| 3–5   | Low          | Unusual source frequency          |
