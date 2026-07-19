from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from enum import Enum


class LogLevel(Enum):
    TRACE = 0
    DEBUG = 1
    INFO = 2
    WARNING = 3
    ERROR = 4
    CRITICAL = 5
    FATAL = 6
    UNKNOWN = -1

    @classmethod
    def from_string(cls, s: str) -> "LogLevel":
        mapping = {
            "trace": cls.TRACE,
            "debug": cls.DEBUG,
            "info": cls.INFO,
            "information": cls.INFO,
            "warn": cls.WARNING,
            "warning": cls.WARNING,
            "error": cls.ERROR,
            "err": cls.ERROR,
            "critical": cls.CRITICAL,
            "crit": cls.CRITICAL,
            "fatal": cls.FATAL,
        }
        return mapping.get(s.lower().strip(), cls.UNKNOWN)


class LogFormat(Enum):
    APACHE_COMMON = "apache_common"
    APACHE_COMBINED = "apache_combined"
    NGINX = "nginx"
    SYSLOG = "syslog"
    JSON = "json"
    LOG4J = "log4j"
    PYTHON = "python"
    WINDOWS_EVENT = "windows_event"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


@dataclass
class LogEntry:
    raw: str
    timestamp: datetime | None = None
    level: LogLevel = LogLevel.UNKNOWN
    source: str = ""
    message: str = ""
    host: str = ""
    pid: int | None = None
    thread: str = ""
    logger: str = ""
    extra: dict[str, Any] = field(default_factory=dict)
    line_number: int = 0
    format: LogFormat = LogFormat.UNKNOWN

    def severity_score(self) -> int:
        return self.level.value


@dataclass
class ParseResult:
    entries: list[LogEntry]
    total_lines: int
    parsed_lines: int
    failed_lines: int
    detected_format: LogFormat
    parse_duration_ms: float
    errors: list[str] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        return (self.parsed_lines / self.total_lines * 100) if self.total_lines else 0.0


@dataclass
class AnomalyResult:
    entry: LogEntry
    anomaly_type: str
    score: float
    description: str
    suggested_action: str = ""


@dataclass
class AnalysisReport:
    total_entries: int
    time_range: tuple[datetime, datetime] | None
    level_distribution: dict[str, int]
    top_sources: list[tuple[str, int]]
    top_errors: list[tuple[str, int]]
    anomalies: list[AnomalyResult]
    patterns: list[dict]
    throughput_stats: dict
    hourly_distribution: dict[int, int]
    error_rate_timeline: list[dict]
    unique_hosts: list[str]
    keyword_frequency: dict[str, int]
    summary: str = ""
