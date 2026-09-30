"""Local deterministic embeddings for the RAG index (guide 13.7, docs/specs/PHASE-7.md decision 10).

``hashing-v1`` is a feature-hashing text embedder: lower-cased word tokens, sub-tokens split on
``. - _ / \\ :``, word bigrams and character trigrams are hashed (BLAKE2b) into 384 signed
buckets, weighted ``1 + log(tf)``, and L2-normalized. It is lexical (no semantics), needs no
model download or GPU/RAM, is identical on every host, and keeps tests offline. Hosted or local
neural embeddings are available through the gateway (``EMBEDDING_PROVIDER``).
"""

from __future__ import annotations

import hashlib
import itertools
import math
import re
from collections import Counter
from typing import Protocol

WORD_RE = re.compile(r"[a-z0-9][a-z0-9_.\-/\\:]{0,63}")
SPLIT_RE = re.compile(r"[._\-/\\:]+")
MAX_CHARS = 20_000
TRIGRAM_WEIGHT = 0.35


class Embedder(Protocol):
    model: str
    dim: int

    def embed(self, texts: list[str]) -> list[list[float] | None]: ...


def _bucket(token: str, dim: int) -> tuple[int, float]:
    h = int.from_bytes(hashlib.blake2b(token.encode(), digest_size=8).digest(), "big")
    return h % dim, (1.0 if (h >> 63) & 1 else -1.0)


def features(text: str) -> Counter[str]:
    words: list[str] = []
    for raw in WORD_RE.findall(text[:MAX_CHARS].lower()):
        raw = raw.strip(".-/\\:")
        if not raw:
            continue
        words.append(raw)
        parts = [p for p in SPLIT_RE.split(raw) if p]
        if len(parts) > 1:
            words.extend(parts)
    feats: Counter[str] = Counter(f"w:{w}" for w in words)
    feats.update(f"b:{a} {b}" for a, b in itertools.pairwise(words))
    for w in words:
        padded = f"^{w}$"
        feats.update(f"c:{padded[i : i + 3]}" for i in range(len(padded) - 2))
    return feats


class HashingEmbedder:
    model = "hashing-v1"

    def __init__(self, dim: int = 384) -> None:
        self.dim = dim

    def embed_one(self, text: str) -> list[float] | None:
        vec = [0.0] * self.dim
        for feat, tf in features(text).items():
            idx, sign = _bucket(feat, self.dim)
            weight = 1.0 + math.log(tf)
            if feat.startswith("c:"):
                weight *= TRIGRAM_WEIGHT
            vec[idx] += sign * weight
        norm = math.sqrt(sum(v * v for v in vec))
        if norm == 0.0:
            return None  # nothing to embed (no vector search for this text)
        return [v / norm for v in vec]

    def embed(self, texts: list[str]) -> list[list[float] | None]:
        return [self.embed_one(t) for t in texts]


def cosine(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b, strict=True))
