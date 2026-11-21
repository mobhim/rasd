"""Offset-preserving text transformations.

Detection runs on normalised text, but analysts must see evidence highlighted
in the message exactly as the victim received it. OffsetText keeps, for every
character of the transformed text, the [start, end) range it came from in the
original, through any chain of deletions, 1:n mappings and regex rewrites."""
from __future__ import annotations

import re
import unicodedata
from typing import Callable

from .models import Span

# Zero-width / bidi-control / soft-hyphen characters used to split keywords
# and URLs so that naive filters miss them.
INVISIBLE = frozenset(
    "​‌‍‎‏‪‫‬‭‮"
    "⁠⁡⁢⁣⁤⁦⁧⁨⁩﻿­؜᠎"
)
_DIGIT_FOLD = {**{chr(0x0660 + i): str(i) for i in range(10)},   # Arabic-Indic
               **{chr(0x06F0 + i): str(i) for i in range(10)}}   # Eastern Arabic-Indic


class OffsetText:
    __slots__ = ("text", "starts", "ends", "orig")

    def __init__(self, text: str, starts: list[int], ends: list[int], orig: str):
        self.text, self.starts, self.ends, self.orig = text, starts, ends, orig

    @classmethod
    def from_raw(cls, raw: str) -> "OffsetText":
        n = len(raw)
        return cls(raw, list(range(n)), list(range(1, n + 1)), raw)

    def span(self, start: int, end: int) -> Span:
        if end <= start or not self.text:
            pos = self.starts[start] if start < len(self.starts) else len(self.orig)
            return Span(pos, pos, "")
        s = self.starts[start]
        e = max(self.ends[start:end])
        return Span(s, e, self.orig[s:e])

    def map_chars(self, fn: Callable[[str], str]) -> "OffsetText":
        out, st, en = [], [], []
        for ch, s, e in zip(self.text, self.starts, self.ends):
            for r in fn(ch):
                out.append(r); st.append(s); en.append(e)
        return OffsetText("".join(out), st, en, self.orig)

    def regex_sub(self, pattern: re.Pattern, repl: str | Callable[[re.Match], str]) -> "OffsetText":
        out, st, en = [], [], []
        pos = 0
        for m in pattern.finditer(self.text):
            if m.end() == m.start():
                continue
            out.append(self.text[pos:m.start()])
            st.extend(self.starts[pos:m.start()]); en.extend(self.ends[pos:m.start()])
            r = repl(m) if callable(repl) else m.expand(repl)
            ms, me = self.starts[m.start()], max(self.ends[m.start():m.end()])
            out.append(r); st.extend([ms] * len(r)); en.extend([me] * len(r))
            pos = m.end()
        out.append(self.text[pos:])
        st.extend(self.starts[pos:]); en.extend(self.ends[pos:])
        return OffsetText("".join(out), st, en, self.orig)


def clean(raw: str) -> tuple[OffsetText, list[Span]]:
    """Script-agnostic level-1 normalisation shared by every language pack:
    strip invisible characters, apply NFKC (presentation forms, full-width and
    'mathematical' letters), fold Eastern digits. Returns the cleaned text and
    the spans of removed invisible characters (an evasion signal by itself)."""
    invisible: list[Span] = []

    def fn(ch: str) -> str:
        if ch in INVISIBLE:
            return ""
        if ch in _DIGIT_FOLD:
            return _DIGIT_FOLD[ch]
        if ord(ch) > 0x7F:
            ch = unicodedata.normalize("NFKC", ch)
            return "".join(_DIGIT_FOLD.get(c, c) for c in ch if c not in INVISIBLE)
        return ch

    for i, ch in enumerate(raw):
        if ch in INVISIBLE:
            invisible.append(Span(i, i + 1, ch))
    return OffsetText.from_raw(raw).map_chars(fn), invisible


def script_of(ch: str) -> str:
    o = ord(ch)
    if 0x0600 <= o <= 0x06FF or 0x0750 <= o <= 0x077F or 0xFB50 <= o <= 0xFDFF or 0xFE70 <= o <= 0xFEFF:
        return "arabic" if ch.isalpha() else "other"
    if ch.isascii():
        return "latin" if ch.isalpha() else "other"
    if 0x0400 <= o <= 0x04FF:
        return "cyrillic"
    if 0x0370 <= o <= 0x03FF:
        return "greek"
    if 0x00C0 <= o <= 0x024F and ch.isalpha():
        return "latin"
    return "other"


def script_profile(text: str) -> dict[str, float]:
    counts: dict[str, int] = {}
    for ch in text:
        s = script_of(ch)
        if s != "other":
            counts[s] = counts.get(s, 0) + 1
    total = sum(counts.values()) or 1
    return {k: v / total for k, v in counts.items()}
