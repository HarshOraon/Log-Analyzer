import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
import numpy as np
from scipy import stats

from core.models import LogEntry, LogLevel, AnomalyResult


SENSITIVE_PATTERNS = [
    (re.compile(r'sql\s*(injection|error|syntax)', re.I), "SQL Injection Attempt"),
    (re.compile(r'(union\s+select|drop\s+table|insert\s+into)', re.I), "SQL Injection"),
    (re.compile(r'<script[^>]*>.*?</script>', re.I | re.S), "XSS Attempt"),
    (re.compile(r'(\.\.\/|\.\.\\){2,}', re.I), "Path Traversal"),
    (re.compile(r'/etc/passwd|/etc/shadow|/proc/self', re.I), "LFI Attempt"),
    (re.compile(r'(eval|exec|system|passthru|shell_exec)\s*\(', re.I), "Code Execution"),
    (re.compile(r'(wget|curl|python|perl|bash|sh)\s+https?://', re.I), "Remote Code Execution"),
    (re.compile(r'(password|passwd|secret|token|apikey|api_key)\s*[:=]\s*\S+', re.I), "Credential Exposure"),
    (re.compile(r'\b(401|403|429)\b'), "Auth/Rate Limit Error"),
    (re.compile(r'(segfault|segmentation fault|stack overflow|heap corruption)', re.I), "Memory Error"),
    (re.compile(r'(out of memory|oom|cannot allocate)', re.I), "Memory Exhaustion"),
    (re.compile(r'(connection refused|connection timed out|no route to host)', re.I), "Network Error"),
    (re.compile(r'(certificate|ssl|tls).*(error|invalid|expired|fail)', re.I), "TLS/SSL Error"),
]


class AnomalyDetector:
    def __init__(self, z_threshold: float = 3.0, burst_multiplier: float = 5.0):
        self.z_threshold = z_threshold
        self.burst_multiplier = burst_multiplier

    def detect_all(self, entries: list[LogEntry]) -> list[AnomalyResult]:
        anomalies: list[AnomalyResult] = []
        anomalies.extend(self.detect_security_patterns(entries))
        anomalies.extend(self.detect_error_bursts(entries))
        anomalies.extend(self.detect_statistical_outliers(entries))
        anomalies.extend(self.detect_repeated_errors(entries))
        anomalies.extend(self.detect_high_frequency_sources(entries))
        return sorted(anomalies, key=lambda a: a.score, reverse=True)

    def detect_security_patterns(self, entries: list[LogEntry]) -> list[AnomalyResult]:
        results = []
        for entry in entries:
            text = entry.raw
            for pattern, label in SENSITIVE_PATTERNS:
                if pattern.search(text):
                    results.append(AnomalyResult(
                        entry=entry,
                        anomaly_type="security",
                        score=9.0 if "Injection" in label or "Execution" in label else 7.0,
                        description=f"Security pattern detected: {label}",
                        suggested_action="Investigate immediately; check WAF/IDS rules and block offending IP if applicable.",
                    ))
                    break
        return results

    def detect_error_bursts(self, entries: list[LogEntry]) -> list[AnomalyResult]:
        if not entries:
            return []
        timestamped = [e for e in entries if e.timestamp]
        if len(timestamped) < 10:
            return []
        timestamped.sort(key=lambda e: e.timestamp)
        bucket_size = timedelta(minutes=1)
        buckets: dict[datetime, int] = defaultdict(int)
        error_buckets: dict[datetime, int] = defaultdict(int)
        for e in timestamped:
            key = e.timestamp.replace(second=0, microsecond=0)
            buckets[key] += 1
            if e.level in (LogLevel.ERROR, LogLevel.CRITICAL, LogLevel.FATAL):
                error_buckets[key] += 1
        if len(buckets) < 5:
            return []
        counts = list(buckets.values())
        mean, std = np.mean(counts), np.std(counts)
        results = []
        for ts, count in buckets.items():
            z = (count - mean) / std if std > 0 else 0
            if z > self.z_threshold and count > mean * self.burst_multiplier:
                first_entry = next((e for e in timestamped if e.timestamp and e.timestamp.replace(second=0, microsecond=0) == ts), None)
                if first_entry:
                    results.append(AnomalyResult(
                        entry=first_entry,
                        anomaly_type="traffic_burst",
                        score=min(10.0, z),
                        description=f"Log burst: {count} entries/min (z={z:.1f}, mean={mean:.1f})",
                        suggested_action="Check for DDoS, runaway process, or misconfigured logging.",
                    ))
        return results

    def detect_statistical_outliers(self, entries: list[LogEntry]) -> list[AnomalyResult]:
        response_times: list[tuple[LogEntry, float]] = []
        rt_pat = re.compile(r'(?:response_time|duration|latency|elapsed|took)[=:\s]+(\d+(?:\.\d+)?)\s*(?:ms|s|seconds)?', re.I)
        for e in entries:
            m = rt_pat.search(e.raw)
            if m:
                val = float(m.group(1))
                if "ms" not in e.raw[m.start():m.end() + 5].lower():
                    val *= 1000
                response_times.append((e, val))
        if len(response_times) < 10:
            return []
        values = [rt for _, rt in response_times]
        mean, std = np.mean(values), np.std(values)
        results = []
        for entry, rt in response_times:
            z = (rt - mean) / std if std > 0 else 0
            if z > self.z_threshold:
                results.append(AnomalyResult(
                    entry=entry,
                    anomaly_type="latency_spike",
                    score=min(10.0, z),
                    description=f"Latency spike: {rt:.0f}ms (z={z:.1f}, mean={mean:.0f}ms, std={std:.0f}ms)",
                    suggested_action="Profile the slow endpoint. Check DB queries, external calls, GC pauses.",
                ))
        return results

    def detect_repeated_errors(self, entries: list[LogEntry]) -> list[AnomalyResult]:
        error_messages: list[str] = []
        error_entries: dict[str, LogEntry] = {}
        for e in entries:
            if e.level in (LogLevel.ERROR, LogLevel.CRITICAL, LogLevel.FATAL):
                key = re.sub(r'\d+', 'N', e.message)[:120]
                error_messages.append(key)
                error_entries[key] = e
        if not error_messages:
            return []
        counter = Counter(error_messages)
        total = len(error_messages)
        results = []
        for msg, count in counter.most_common(10):
            if count >= max(5, total * 0.05):
                entry = error_entries[msg]
                score = min(9.0, 5.0 + (count / total) * 10)
                results.append(AnomalyResult(
                    entry=entry,
                    anomaly_type="repeated_error",
                    score=score,
                    description=f"Recurring error ({count}x, {count/total*100:.1f}%): {msg[:100]}",
                    suggested_action="Fix root cause — this error is dominating the error log.",
                ))
        return results

    def detect_high_frequency_sources(self, entries: list[LogEntry]) -> list[AnomalyResult]:
        source_counts = Counter(e.host or e.source for e in entries if e.host or e.source)
        if len(source_counts) < 3:
            return []
        values = list(source_counts.values())
        mean, std = np.mean(values), np.std(values)
        results = []
        for source, count in source_counts.most_common(5):
            z = (count - mean) / std if std > 0 else 0
            if z > self.z_threshold + 1:
                entry = next((e for e in entries if (e.host or e.source) == source), entries[0])
                results.append(AnomalyResult(
                    entry=entry,
                    anomaly_type="high_frequency_source",
                    score=min(8.0, z),
                    description=f"High-frequency source: {source!r} ({count} entries, z={z:.1f})",
                    suggested_action="Investigate if this host/service has unusual activity or logging misconfiguration.",
                ))
        return results
