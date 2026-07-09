import re
import json
import gzip
import bz2
import time
from datetime import datetime
from pathlib import Path
from typing import Iterator
from dateutil import parser as dateutil_parser

from core.models import LogEntry, LogLevel, LogFormat, ParseResult


APACHE_COMMON_RE = re.compile(
    r'(?P<host>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<request>[^"]+)"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
)
APACHE_COMBINED_RE = re.compile(
    r'(?P<host>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<request>[^"]+)"\s+(?P<status>\d{3})\s+(?P<size>\S+)\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"'
)
SYSLOG_RE = re.compile(
    r'(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<proc>[^\[:]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.+)'
)
LOG4J_RE = re.compile(
    r'(?P<ts>\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{4})?)\s+(?P<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|CRITICAL|FATAL)\s+(?:\[(?P<thread>[^\]]*)\]\s+)?(?P<logger>\S+)\s*[-:]?\s*(?P<msg>.*)'
)
PYTHON_LOG_RE = re.compile(
    r'(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:,\d+)?)\s+(?P<level>DEBUG|INFO|WARNING|ERROR|CRITICAL)\s+(?P<logger>\S+):\s+(?P<msg>.*)'
)
NGINX_RE = re.compile(
    r'(?P<host>\S+)\s+-\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+"(?P<request>[^"]+)"\s+(?P<status>\d{3})\s+(?P<size>\d+)\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"'
)
NGINX_ERROR_RE = re.compile(
    r'(?P<ts>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(?P<level>\w+)\]\s+(?P<pid>\d+)#\d+:\s+(?P<msg>.+)'
)


def _parse_apache_time(s: str) -> datetime | None:
    try:
        return datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None


def _parse_flexible_ts(s: str) -> datetime | None:
    try:
        return dateutil_parser.parse(s, fuzzy=False)
    except Exception:
        return None


def _detect_format(sample_lines: list[str]) -> LogFormat:
    scores: dict[LogFormat, int] = {f: 0 for f in LogFormat}
    for line in sample_lines[:50]:
        if not line.strip():
            continue
        if APACHE_COMBINED_RE.match(line):
            scores[LogFormat.APACHE_COMBINED] += 2
        elif APACHE_COMMON_RE.match(line):
            scores[LogFormat.APACHE_COMMON] += 2
        if NGINX_RE.match(line):
            scores[LogFormat.NGINX] += 1
        if NGINX_ERROR_RE.match(line):
            scores[LogFormat.NGINX] += 1
        if SYSLOG_RE.match(line):
            scores[LogFormat.SYSLOG] += 2
        # Python log check before log4j: Python format uses comma for ms (,NNN) while log4j uses dot or similar
        if PYTHON_LOG_RE.match(line):
            scores[LogFormat.PYTHON] += 3
        elif LOG4J_RE.match(line):
            scores[LogFormat.LOG4J] += 2
        stripped = line.strip()
        if stripped.startswith("{") and stripped.endswith("}"):
            try:
                json.loads(stripped)
                scores[LogFormat.JSON] += 3
            except json.JSONDecodeError:
                pass
    best = max(scores, key=lambda f: scores[f])
    return best if scores[best] > 0 else LogFormat.UNKNOWN


class LogParser:
    def __init__(self, encoding: str = "utf-8", errors: str = "replace"):
        self.encoding = encoding
        self.errors = errors

    def _open_file(self, path: Path):
        suffix = path.suffix.lower()
        if suffix == ".gz":
            return gzip.open(path, "rt", encoding=self.encoding, errors=self.errors)
        if suffix in (".bz2", ".bzip2"):
            return bz2.open(path, "rt", encoding=self.encoding, errors=self.errors)
        return open(path, "r", encoding=self.encoding, errors=self.errors)

    def _read_lines(self, path: Path) -> list[str]:
        with self._open_file(path) as f:
            return f.readlines()

    def _parse_line(self, line: str, fmt: LogFormat, lineno: int) -> LogEntry | None:
        raw = line.rstrip("\n")
        if not raw.strip():
            return None

        entry = LogEntry(raw=raw, line_number=lineno, format=fmt)

        if fmt == LogFormat.JSON:
            return self._parse_json(raw, entry)
        if fmt in (LogFormat.APACHE_COMBINED, LogFormat.APACHE_COMMON):
            return self._parse_apache(raw, entry)
        if fmt == LogFormat.NGINX:
            return self._parse_nginx(raw, entry)
        if fmt == LogFormat.SYSLOG:
            return self._parse_syslog(raw, entry)
        if fmt == LogFormat.LOG4J:
            return self._parse_log4j(raw, entry)
        if fmt == LogFormat.PYTHON:
            return self._parse_python(raw, entry)

        return self._parse_generic(raw, entry)

    def _parse_json(self, raw: str, entry: LogEntry) -> LogEntry | None:
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            return None
        ts_keys = ("timestamp", "ts", "time", "@timestamp", "datetime", "date")
        for k in ts_keys:
            if k in obj:
                entry.timestamp = _parse_flexible_ts(str(obj[k]))
                break
        lvl_keys = ("level", "severity", "loglevel", "log_level")
        for k in lvl_keys:
            if k in obj:
                entry.level = LogLevel.from_string(str(obj[k]))
                break
        msg_keys = ("message", "msg", "text", "body", "log")
        for k in msg_keys:
            if k in obj:
                entry.message = str(obj[k])
                break
        entry.host = str(obj.get("host", obj.get("hostname", "")))
        entry.source = str(obj.get("source", obj.get("service", obj.get("app", ""))))
        entry.logger = str(obj.get("logger", obj.get("name", "")))
        entry.extra = {k: v for k, v in obj.items()}
        return entry

    def _parse_apache(self, raw: str, entry: LogEntry) -> LogEntry | None:
        m = APACHE_COMBINED_RE.match(raw) or APACHE_COMMON_RE.match(raw)
        if not m:
            return None
        d = m.groupdict()
        entry.host = d.get("host", "")
        entry.timestamp = _parse_apache_time(d.get("time", ""))
        req = d.get("request", "")
        entry.message = req
        status = int(d.get("status", 0))
        entry.extra["status"] = status
        entry.extra["size"] = d.get("size", "-")
        entry.extra["request"] = req
        if status >= 500:
            entry.level = LogLevel.ERROR
        elif status >= 400:
            entry.level = LogLevel.WARNING
        else:
            entry.level = LogLevel.INFO
        if "ua" in d:
            entry.extra["user_agent"] = d["ua"]
        if "referer" in d:
            entry.extra["referer"] = d["referer"]
        return entry

    def _parse_nginx(self, raw: str, entry: LogEntry) -> LogEntry | None:
        m = NGINX_RE.match(raw) or NGINX_ERROR_RE.match(raw)
        if not m:
            return self._parse_apache(raw, entry)
        d = m.groupdict()
        if "ts" in d:
            entry.timestamp = _parse_flexible_ts(d["ts"].replace("/", "-"))
            entry.level = LogLevel.from_string(d.get("level", "info"))
            entry.message = d.get("msg", "")
            entry.pid = int(d["pid"]) if d.get("pid") else None
        else:
            entry.host = d.get("host", "")
            entry.timestamp = _parse_apache_time(d.get("time", ""))
            status = int(d.get("status", 0))
            entry.message = d.get("request", "")
            entry.extra["status"] = status
            entry.level = LogLevel.ERROR if status >= 500 else (LogLevel.WARNING if status >= 400 else LogLevel.INFO)
        return entry

    def _parse_syslog(self, raw: str, entry: LogEntry) -> LogEntry | None:
        m = SYSLOG_RE.match(raw)
        if not m:
            return None
        d = m.groupdict()
        ts_str = f"{d['month']} {d['day']} {d['time']} {datetime.now().year}"
        entry.timestamp = _parse_flexible_ts(ts_str)
        entry.host = d.get("host", "")
        entry.source = d.get("proc", "").strip()
        entry.pid = int(d["pid"]) if d.get("pid") else None
        entry.message = d.get("msg", "")
        msg_lower = entry.message.lower()
        if any(w in msg_lower for w in ("error", "fail", "crit")):
            entry.level = LogLevel.ERROR
        elif any(w in msg_lower for w in ("warn",)):
            entry.level = LogLevel.WARNING
        else:
            entry.level = LogLevel.INFO
        return entry

    def _parse_log4j(self, raw: str, entry: LogEntry) -> LogEntry | None:
        m = LOG4J_RE.match(raw)
        if not m:
            return None
        d = m.groupdict()
        entry.timestamp = _parse_flexible_ts(d.get("ts", ""))
        entry.level = LogLevel.from_string(d.get("level", ""))
        entry.thread = d.get("thread", "")
        entry.logger = d.get("logger", "")
        entry.message = d.get("msg", "")
        entry.source = entry.logger
        return entry

    def _parse_python(self, raw: str, entry: LogEntry) -> LogEntry | None:
        m = PYTHON_LOG_RE.match(raw)
        if not m:
            return None
        d = m.groupdict()
        entry.timestamp = _parse_flexible_ts(d.get("ts", ""))
        entry.level = LogLevel.from_string(d.get("level", ""))
        entry.logger = d.get("logger", "")
        entry.message = d.get("msg", "")
        entry.source = entry.logger
        return entry

    def _parse_generic(self, raw: str, entry: LogEntry) -> LogEntry:
        level_pat = re.compile(
            r'\b(TRACE|DEBUG|INFO|WARN(?:ING)?|ERROR|ERR|CRIT(?:ICAL)?|FATAL)\b', re.I
        )
        ts_pat = re.compile(
            r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}'
        )
        m = ts_pat.search(raw)
        if m:
            entry.timestamp = _parse_flexible_ts(m.group())
        lm = level_pat.search(raw)
        if lm:
            entry.level = LogLevel.from_string(lm.group())
        entry.message = raw
        return entry

    def parse_file(self, path: str | Path) -> ParseResult:
        path = Path(path)
        t0 = time.perf_counter()
        lines = self._read_lines(path)
        sample = [l.rstrip() for l in lines[:200] if l.strip()]
        fmt = _detect_format(sample)

        entries: list[LogEntry] = []
        failed = 0
        parse_errors: list[str] = []

        for i, line in enumerate(lines, 1):
            try:
                entry = self._parse_line(line, fmt, i)
                if entry:
                    entries.append(entry)
                elif line.strip():
                    failed += 1
            except Exception as e:
                failed += 1
                if len(parse_errors) < 20:
                    parse_errors.append(f"Line {i}: {e}")

        duration_ms = (time.perf_counter() - t0) * 1000
        return ParseResult(
            entries=entries,
            total_lines=len(lines),
            parsed_lines=len(entries),
            failed_lines=failed,
            detected_format=fmt,
            parse_duration_ms=duration_ms,
            errors=parse_errors,
        )

    def parse_lines(self, lines: list[str], fmt: LogFormat = LogFormat.UNKNOWN) -> ParseResult:
        t0 = time.perf_counter()
        if fmt == LogFormat.UNKNOWN:
            sample = [l.rstrip() for l in lines[:200] if l.strip()]
            fmt = _detect_format(sample)
        entries: list[LogEntry] = []
        failed = 0
        errors: list[str] = []
        for i, line in enumerate(lines, 1):
            try:
                entry = self._parse_line(line, fmt, i)
                if entry:
                    entries.append(entry)
                elif line.strip():
                    failed += 1
            except Exception as e:
                failed += 1
                if len(errors) < 20:
                    errors.append(f"Line {i}: {e}")
        duration_ms = (time.perf_counter() - t0) * 1000
        return ParseResult(
            entries=entries,
            total_lines=len(lines),
            parsed_lines=len(entries),
            failed_lines=failed,
            detected_format=fmt,
            parse_duration_ms=duration_ms,
            errors=errors,
        )

    def stream_file(self, path: str | Path) -> Iterator[LogEntry]:
        path = Path(path)
        sample_lines: list[str] = []
        fmt = LogFormat.UNKNOWN
        with self._open_file(path) as f:
            for i, line in enumerate(f, 1):
                if i <= 100:
                    sample_lines.append(line.rstrip())
                    if i == 100:
                        fmt = _detect_format(sample_lines)
                entry = self._parse_line(line, fmt, i)
                if entry:
                    yield entry
