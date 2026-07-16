import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
import numpy as np

from core.models import LogEntry, LogLevel, AnalysisReport, AnomalyResult


COMMON_KEYWORDS = [
    "error", "fail", "exception", "timeout", "retry", "reconnect",
    "denied", "refused", "invalid", "critical", "crash", "panic",
    "overflow", "deadlock", "corrupt", "unauthorized", "forbidden",
]

LOG_PATTERN_TEMPLATES = [
    (re.compile(r'(\d{1,3}\.){3}\d{1,3}'), "<IP>"),
    (re.compile(r'"[^"]{8,}"'), "<QUOTED>"),
    (re.compile(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', re.I), "<UUID>"),
    (re.compile(r'\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}'), "<DATETIME>"),
    (re.compile(r'\d+\.\d+s|\d+ms'), "<DURATION>"),
    (re.compile(r'#\d+|\bID[=:]\d+|\bid[=:]\d+'), "<ID>"),
    (re.compile(r'\b\d{5,}\b'), "<NUM>"),
    (re.compile(r'/[a-zA-Z0-9_/.-]{8,}'), "<PATH>"),
]


def _templatize(msg: str) -> str:
    for pat, replacement in LOG_PATTERN_TEMPLATES:
        msg = pat.sub(replacement, msg)
    return re.sub(r'\s+', ' ', msg).strip()[:150]


class LogAnalyzer:
    def analyze(self, entries: list[LogEntry], anomalies: list[AnomalyResult]) -> AnalysisReport:
        if not entries:
            return AnalysisReport(
                total_entries=0, time_range=None,
                level_distribution={}, top_sources=[], top_errors=[],
                anomalies=anomalies, patterns=[], throughput_stats={},
                hourly_distribution={}, error_rate_timeline=[],
                unique_hosts=[], keyword_frequency={},
                summary="No entries to analyze.",
            )

        time_range = self._time_range(entries)
        level_dist = self._level_distribution(entries)
        top_sources = self._top_sources(entries)
        top_errors = self._top_errors(entries)
        patterns = self._extract_patterns(entries)
        throughput = self._throughput_stats(entries)
        hourly = self._hourly_distribution(entries)
        error_timeline = self._error_rate_timeline(entries)
        unique_hosts = self._unique_hosts(entries)
        keywords = self._keyword_frequency(entries)
        summary = self._generate_summary(entries, level_dist, anomalies, throughput)

        return AnalysisReport(
            total_entries=len(entries),
            time_range=time_range,
            level_distribution=level_dist,
            top_sources=top_sources,
            top_errors=top_errors,
            anomalies=anomalies,
            patterns=patterns,
            throughput_stats=throughput,
            hourly_distribution=hourly,
            error_rate_timeline=error_timeline,
            unique_hosts=unique_hosts,
            keyword_frequency=keywords,
            summary=summary,
        )

    def _time_range(self, entries: list[LogEntry]) -> tuple[datetime, datetime] | None:
        ts_list = [e.timestamp for e in entries if e.timestamp]
        if not ts_list:
            return None
        return min(ts_list), max(ts_list)

    def _level_distribution(self, entries: list[LogEntry]) -> dict[str, int]:
        counts = Counter(e.level.name for e in entries)
        return dict(sorted(counts.items()))

    def _top_sources(self, entries: list[LogEntry], n: int = 15) -> list[tuple[str, int]]:
        counter = Counter()
        for e in entries:
            key = e.source or e.logger or e.host or "unknown"
            counter[key] += 1
        return counter.most_common(n)

    def _top_errors(self, entries: list[LogEntry], n: int = 20) -> list[tuple[str, int]]:
        error_entries = [e for e in entries if e.level in (LogLevel.ERROR, LogLevel.CRITICAL, LogLevel.FATAL)]
        templates = Counter(_templatize(e.message) for e in error_entries if e.message)
        return templates.most_common(n)

    def _extract_patterns(self, entries: list[LogEntry], min_count: int = 3) -> list[dict]:
        template_map: dict[str, list[LogEntry]] = defaultdict(list)
        for e in entries:
            if e.message:
                tmpl = _templatize(e.message)
                template_map[tmpl].append(e)
        patterns = []
        for tmpl, matched in sorted(template_map.items(), key=lambda x: -len(x[1])):
            if len(matched) < min_count:
                continue
            levels = Counter(e.level.name for e in matched)
            patterns.append({
                "template": tmpl,
                "count": len(matched),
                "levels": dict(levels),
                "dominant_level": levels.most_common(1)[0][0] if levels else "UNKNOWN",
                "first_seen": min((e.timestamp for e in matched if e.timestamp), default=None),
                "last_seen": max((e.timestamp for e in matched if e.timestamp), default=None),
            })
        return patterns[:50]

    def _throughput_stats(self, entries: list[LogEntry]) -> dict:
        ts_list = sorted(e.timestamp for e in entries if e.timestamp)
        if len(ts_list) < 2:
            return {}
        total_duration = (ts_list[-1] - ts_list[0]).total_seconds()
        if total_duration <= 0:
            return {}
        buckets: dict[datetime, int] = defaultdict(int)
        for ts in ts_list:
            key = ts.replace(second=0, microsecond=0)
            buckets[key] += 1
        rates = list(buckets.values())
        return {
            "total_duration_s": round(total_duration, 2),
            "avg_rate_per_min": round(np.mean(rates), 2),
            "peak_rate_per_min": int(np.max(rates)),
            "min_rate_per_min": int(np.min(rates)),
            "std_rate_per_min": round(float(np.std(rates)), 2),
            "p95_rate_per_min": round(float(np.percentile(rates, 95)), 2),
            "total_entries": len(ts_list),
            "entries_per_second": round(len(ts_list) / total_duration, 4),
        }

    def _hourly_distribution(self, entries: list[LogEntry]) -> dict[int, int]:
        dist: dict[int, int] = defaultdict(int)
        for e in entries:
            if e.timestamp:
                dist[e.timestamp.hour] += 1
        return dict(sorted(dist.items()))

    def _error_rate_timeline(self, entries: list[LogEntry]) -> list[dict]:
        timestamped = [e for e in entries if e.timestamp]
        if not timestamped:
            return []
        timestamped.sort(key=lambda e: e.timestamp)
        bucket_size = timedelta(minutes=5)
        start = timestamped[0].timestamp.replace(second=0, microsecond=0)
        end = timestamped[-1].timestamp.replace(second=0, microsecond=0) + bucket_size
        buckets: dict[datetime, dict] = {}
        t = start
        while t <= end:
            buckets[t] = {"total": 0, "errors": 0}
            t += bucket_size
        for e in timestamped:
            ts = e.timestamp.replace(second=0, microsecond=0)
            bucket_key = start + ((ts - start) // bucket_size) * bucket_size
            if bucket_key in buckets:
                buckets[bucket_key]["total"] += 1
                if e.level in (LogLevel.ERROR, LogLevel.CRITICAL, LogLevel.FATAL):
                    buckets[bucket_key]["errors"] += 1
        timeline = []
        for ts, data in sorted(buckets.items()):
            rate = data["errors"] / data["total"] * 100 if data["total"] else 0
            timeline.append({
                "timestamp": ts.isoformat(),
                "total": data["total"],
                "errors": data["errors"],
                "error_rate_pct": round(rate, 2),
            })
        return timeline

    def _unique_hosts(self, entries: list[LogEntry]) -> list[str]:
        hosts = {e.host for e in entries if e.host}
        return sorted(hosts)

    def _keyword_frequency(self, entries: list[LogEntry]) -> dict[str, int]:
        counts: dict[str, int] = defaultdict(int)
        for e in entries:
            text = (e.message or e.raw).lower()
            for kw in COMMON_KEYWORDS:
                if kw in text:
                    counts[kw] += 1
        return dict(sorted(counts.items(), key=lambda x: -x[1]))

    def _generate_summary(
        self,
        entries: list[LogEntry],
        level_dist: dict[str, int],
        anomalies: list[AnomalyResult],
        throughput: dict,
    ) -> str:
        total = len(entries)
        errors = level_dist.get("ERROR", 0) + level_dist.get("CRITICAL", 0) + level_dist.get("FATAL", 0)
        warns = level_dist.get("WARNING", 0)
        error_pct = errors / total * 100 if total else 0
        health = "HEALTHY" if error_pct < 1 else ("DEGRADED" if error_pct < 5 else "CRITICAL")
        rate = throughput.get("avg_rate_per_min", 0)
        peak = throughput.get("peak_rate_per_min", 0)
        high_anomalies = sum(1 for a in anomalies if a.score >= 7.0)
        security_anomalies = sum(1 for a in anomalies if a.anomaly_type == "security")

        lines = [
            f"System health: {health}",
            f"Analyzed {total:,} log entries | {errors:,} errors ({error_pct:.1f}%) | {warns:,} warnings",
            f"Throughput: avg {rate:.1f} entries/min, peak {peak} entries/min",
            f"Anomalies detected: {len(anomalies)} total ({high_anomalies} high-severity, {security_anomalies} security)",
        ]
        if security_anomalies:
            lines.append(f"⚠ {security_anomalies} SECURITY anomalies require immediate attention!")
        return " | ".join(lines)
