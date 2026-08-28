"""Gather and chunk the knowledge sources into embeddable pieces.

Two sources, both authoritative for *this* tool's methodology:
  1. Course notes  — the author's OWASP Mobile Top 10 write-ups (M1-M10), local.
     Rich with real exploit walkthroughs; tagged source="course".
  2. OWASP MASVS  — the official Mobile App Security Verification Standard
     controls (STORAGE/CRYPTO/AUTH/NETWORK/PLATFORM/CODE/RESILIENCE/PRIVACY),
     fetched from GitHub once and cached locally; tagged source="masvs".

Each source is split on Markdown headings into ~paragraph-sized chunks so a
query retrieves a focused control/subtopic rather than a whole document.
"""
from __future__ import annotations

import re
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

# Local course notes — the PLAYBOOK (how to find/confirm issues). Static-analysis
# relevant sections only; MASVS below is the separate rulebook (what to cite).
_SECTIONS = Path.home() / "notes/mobile-security"


@dataclass
class CourseSource:
    tag: str            # short citation tag, e.g. "Static" -> ref "Course:Static"
    subdir: str         # section folder under _SECTIONS
    files: list[str] | None = None   # explicit filenames; None = all M*/*.md via matcher
    pattern: str = "*.md"


# Which course sections feed the playbook, and how each is cited.
COURSE_SOURCES = [
    CourseSource("Static", "Android_Application_Static_Analysis"),
    CourseSource("Malware", "Android_Application_Malware_Analysis"),
    CourseSource("OWASP", "OWASP", pattern="M*_*.md"),   # keeps per-M citation below
    CourseSource("MobSF", "Android_Penetration_Testing_Automation", files=["MobSF.md"]),
    CourseSource("Quark", "Android_Penetration_Testing_Automation", files=["Quark.md"]),
]

# Non-content files to skip when globbing a section.
_SKIP_FILES = {"internal_notes.md"}

# OWASP MASVS control files (raw GitHub). Fetched once, then cached in data/.
MASVS_BASE = "https://raw.githubusercontent.com/OWASP/masvs/master/Document/"
MASVS_FILES = [
    "05-MASVS-STORAGE.md", "06-MASVS-CRYPTO.md", "07-MASVS-AUTH.md",
    "08-MASVS-NETWORK.md", "09-MASVS-PLATFORM.md", "10-MASVS-CODE.md",
    "11-MASVS-RESILIENCE.md", "12-MASVS-PRIVACY.md",
]

_MAX_WORDS = 320    # split chunks larger than this along paragraph boundaries
_MIN_WORDS = 12     # drop trivially short fragments (stray headings, etc.)


@dataclass
class Chunk:
    text: str
    source: str            # "course" | "masvs"
    category: str          # e.g. "M10 Insufficient Cryptography" | "MASVS-CRYPTO"
    title: str             # heading of this chunk
    ref: str = field(default="")  # short citation label, e.g. "Course:M10" / "MASVS-CRYPTO"

    def embed_text(self) -> str:
        # Prefix with category/title so the vector carries topical context.
        return f"[{self.ref}] {self.title}\n{self.text}"

    def citation(self) -> str:
        return self.ref if self.ref else self.category


def _split_markdown(md: str, source: str, category: str, ref: str) -> list[Chunk]:
    """Split a markdown doc into chunks at headings; further split long ones."""
    lines = md.splitlines()
    chunks: list[Chunk] = []
    title = category
    buf: list[str] = []

    def flush() -> None:
        body = "\n".join(buf).strip()
        if not body:
            return
        for piece in _cap_words(body):
            if len(piece.split()) >= _MIN_WORDS:
                chunks.append(Chunk(text=piece, source=source, category=category,
                                    title=title, ref=ref))

    for line in lines:
        h = re.match(r"^(#{1,6})\s+(.*)", line)
        if h:
            flush()
            buf = []
            title = h.group(2).strip()
        else:
            buf.append(line)
    flush()
    return chunks


def _cap_words(body: str) -> list[str]:
    """Keep chunks embeddable: if a section exceeds _MAX_WORDS, split on blank lines."""
    if len(body.split()) <= _MAX_WORDS:
        return [body]
    out, cur, n = [], [], 0
    for para in re.split(r"\n\s*\n", body):
        w = len(para.split())
        if n + w > _MAX_WORDS and cur:
            out.append("\n\n".join(cur))
            cur, n = [], 0
        cur.append(para)
        n += w
    if cur:
        out.append("\n\n".join(cur))
    return out


def _files_for(src: CourseSource) -> list[Path]:
    d = _SECTIONS / src.subdir
    if not d.is_dir():
        print(f"  ! course section not found: {src.subdir}")
        return []
    if src.files:
        return [d / n for n in src.files if (d / n).is_file()]
    return [f for f in sorted(d.glob(src.pattern)) if f.name not in _SKIP_FILES]


def _course_chunks() -> list[Chunk]:
    chunks: list[Chunk] = []
    for src in COURSE_SOURCES:
        for f in _files_for(src):
            # OWASP files carry a per-category id (M1..M10); others cite by section tag.
            m = re.match(r"(M\d+)_(.*)\.md", f.name)
            if src.tag == "OWASP" and m:
                ref = f"Course:{m.group(1)}"
                cat = f"{m.group(1)} {m.group(2).replace('_', ' ')}"
            else:
                ref = f"Course:{src.tag}"
                cat = f"{src.tag}: {f.stem.replace('_', ' ')}"
            chunks += _split_markdown(f.read_text(errors="replace"), "course", cat, ref=ref)
    return chunks


def _masvs_chunks(cache_dir: Path) -> list[Chunk]:
    cache_dir.mkdir(parents=True, exist_ok=True)
    chunks: list[Chunk] = []
    for name in MASVS_FILES:
        cat = name.split("-", 1)[1].replace(".md", "")     # "MASVS-CRYPTO"
        cat = "MASVS-" + name.split("MASVS-")[1].replace(".md", "")
        cache = cache_dir / name
        md = None
        if cache.is_file():
            md = cache.read_text(errors="replace")
        else:
            try:
                with urllib.request.urlopen(MASVS_BASE + name, timeout=20) as r:
                    md = r.read().decode("utf-8", "replace")
                cache.write_text(md)
            except Exception as e:  # offline / fetch failure: skip this file
                print(f"  ! could not fetch {name}: {e}")
                continue
        chunks += _split_markdown(md, "masvs", cat, ref=cat)
    return chunks


def gather_chunks(cache_dir: Path) -> list[Chunk]:
    """Collect all knowledge chunks from every source."""
    course = _course_chunks()
    masvs = _masvs_chunks(cache_dir)
    print(f"  gathered {len(course)} course chunk(s), {len(masvs)} MASVS chunk(s)")
    return course + masvs
