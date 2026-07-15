import re
import hashlib
import numpy as np
from collections import Counter
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import MiniBatchKMeans, DBSCAN
from sklearn.preprocessing import normalize
from sklearn.decomposition import TruncatedSVD

from core.models import LogEntry, LogLevel


def _clean_message(msg: str) -> str:
    msg = re.sub(r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?', 'DATETIME', msg)
    msg = re.sub(r'(\d{1,3}\.){3}\d{1,3}(:\d+)?', 'IPADDR', msg)
    msg = re.sub(r'\b[0-9a-f]{8,}\b', 'HEX', msg, flags=re.I)
    msg = re.sub(r'\b\d{4,}\b', 'NUM', msg)
    msg = re.sub(r'"[^"]{10,}"', 'QUOTED', msg)
    msg = re.sub(r"'[^']{10,}'", 'QUOTED', msg)
    msg = re.sub(r'[^a-zA-Z0-9\s_]', ' ', msg)
    msg = re.sub(r'\s+', ' ', msg)
    return msg.lower().strip()


class LogClusterer:
    def __init__(self, n_clusters: int = 10, min_samples: int = 2):
        self.n_clusters = n_clusters
        self.min_samples = min_samples
        self._vectorizer: TfidfVectorizer | None = None
        self._svd: TruncatedSVD | None = None
        self._model = None
        self.labels_: np.ndarray | None = None
        self.cluster_summaries_: list[dict] = []

    def fit(self, entries: list[LogEntry]) -> "LogClusterer":
        messages = [_clean_message(e.message or e.raw) for e in entries]
        non_empty = [m for m in messages if m.strip()]
        if len(non_empty) < 5:
            self.labels_ = np.zeros(len(entries), dtype=int)
            return self

        self._vectorizer = TfidfVectorizer(
            max_features=2000,
            ngram_range=(1, 2),
            min_df=1,
            sublinear_tf=True,
            analyzer="word",
        )
        X = self._vectorizer.fit_transform(messages)

        n_components = min(50, X.shape[1] - 1, len(non_empty) - 1)
        if n_components < 2:
            self.labels_ = np.zeros(len(entries), dtype=int)
            return self

        self._svd = TruncatedSVD(n_components=n_components, random_state=42)
        X_reduced = self._svd.fit_transform(X)
        X_normalized = normalize(X_reduced)

        k = min(self.n_clusters, len(non_empty) // 2, 20)
        k = max(k, 2)
        self._model = MiniBatchKMeans(n_clusters=k, random_state=42, n_init=3, batch_size=256)
        self.labels_ = self._model.fit_predict(X_normalized)
        self._build_summaries(entries)
        return self

    def _build_summaries(self, entries: list[LogEntry]) -> None:
        if self.labels_ is None:
            return
        cluster_entries: dict[int, list[LogEntry]] = {}
        for label, entry in zip(self.labels_, entries):
            cluster_entries.setdefault(int(label), []).append(entry)
        summaries = []
        for cluster_id, members in sorted(cluster_entries.items()):
            levels = Counter(e.level.name for e in members)
            dominant_level = levels.most_common(1)[0][0] if levels else "UNKNOWN"
            sources = Counter(e.source or e.logger or e.host for e in members if e.source or e.logger or e.host)
            top_source = sources.most_common(1)[0][0] if sources else ""
            timestamps = [e.timestamp for e in members if e.timestamp]
            sample_msgs = [e.message or e.raw for e in members[:5]]
            words: Counter = Counter()
            for msg in (e.message or e.raw for e in members):
                for w in _clean_message(msg).split():
                    if len(w) > 3:
                        words[w] += 1
            top_words = [w for w, _ in words.most_common(8)]
            summaries.append({
                "cluster_id": cluster_id,
                "size": len(members),
                "dominant_level": dominant_level,
                "level_distribution": dict(levels),
                "top_source": top_source,
                "top_words": top_words,
                "first_seen": min(timestamps) if timestamps else None,
                "last_seen": max(timestamps) if timestamps else None,
                "sample_messages": sample_msgs[:3],
                "severity": LogLevel.from_string(dominant_level).value,
            })
        self.cluster_summaries_ = sorted(summaries, key=lambda s: -s["size"])

    def get_cluster_for_entry(self, index: int) -> int:
        if self.labels_ is None or index >= len(self.labels_):
            return -1
        return int(self.labels_[index])


class TemplateExtractor:
    """Drain-inspired log template extraction."""

    def __init__(self, depth: int = 4, sim_threshold: float = 0.4, max_children: int = 100):
        self.depth = depth
        self.sim_threshold = sim_threshold
        self.max_children = max_children
        self._prefix_tree: dict = {}
        self._clusters: dict[str, dict] = {}

    def _tokenize(self, message: str) -> list[str]:
        message = re.sub(r'(\d{1,3}\.){3}\d{1,3}', '<IP>', message)
        message = re.sub(r'\d+', '<NUM>', message)
        return message.split()

    def _seq_dist(self, seq1: list[str], seq2: list[str]) -> tuple[float, list[str]]:
        if len(seq1) != len(seq2):
            return 0.0, []
        sim_tokens = sum(1 for a, b in zip(seq1, seq2) if a == b)
        similarity = sim_tokens / len(seq1) if seq1 else 1.0
        template = [a if a == b else "<*>" for a, b in zip(seq1, seq2)]
        return similarity, template

    def process(self, message: str) -> str:
        tokens = self._tokenize(message)
        length = len(tokens)
        if length not in self._prefix_tree:
            self._prefix_tree[length] = {}
        node = self._prefix_tree[length]
        for i, token in enumerate(tokens[:self.depth]):
            key = token if not re.match(r'<[A-Z*]+>', token) else "<*>"
            if key not in node:
                node[key] = {} if i < self.depth - 1 else []
            node = node[key]

        if isinstance(node, list):
            best_sim, best_idx, best_tmpl = 0.0, -1, tokens[:]
            for idx, cluster_tokens in enumerate(node):
                sim, tmpl = self._seq_dist(tokens, cluster_tokens)
                if sim > best_sim:
                    best_sim, best_idx, best_tmpl = sim, idx, tmpl
            if best_sim >= self.sim_threshold and best_idx >= 0:
                node[best_idx] = best_tmpl
                return " ".join(best_tmpl)
            else:
                if len(node) < self.max_children:
                    node.append(tokens[:])
                return " ".join(tokens)
        return " ".join(tokens)

    def extract_templates(self, entries: list[LogEntry]) -> list[dict]:
        template_counter: Counter = Counter()
        template_examples: dict[str, LogEntry] = {}
        for e in entries:
            msg = e.message or e.raw
            tmpl = self.process(msg)
            key = hashlib.md5(tmpl.encode()).hexdigest()[:8]
            labeled = f"{key}: {tmpl}"
            template_counter[labeled] += 1
            template_examples[labeled] = e
        results = []
        for tmpl, count in template_counter.most_common(30):
            entry = template_examples[tmpl]
            results.append({
                "template": tmpl,
                "count": count,
                "sample_entry_level": entry.level.name,
                "sample_source": entry.source or entry.logger,
            })
        return results
