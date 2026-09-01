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

# OWASP MASVS category intros (raw GitHub). Fetched once, then cached in data/.
# These give broad per-category context; the control files below add the depth.
MASVS_BASE = "https://raw.githubusercontent.com/OWASP/masvs/master/Document/"
MASVS_FILES = [
    "05-MASVS-STORAGE.md", "06-MASVS-CRYPTO.md", "07-MASVS-AUTH.md",
    "08-MASVS-NETWORK.md", "09-MASVS-PLATFORM.md", "10-MASVS-CODE.md",
    "11-MASVS-RESILIENCE.md", "12-MASVS-PRIVACY.md",
]

# Individual MASVS controls (the specific, citable IDs — MASVS-CRYPTO-2 etc.).
# Each file is tiny (# id / ## Control / ## Description) and becomes one chunk
# whose ref IS the control id, so findings cite the precise control, not just the
# category. Fetched from controls/ and cached under masvs_cache/controls/.
MASVS_CONTROLS_BASE = "https://raw.githubusercontent.com/OWASP/masvs/master/controls/"
MASVS_CONTROL_FILES = [
    "MASVS-STORAGE-1.md", "MASVS-STORAGE-2.md",
    "MASVS-CRYPTO-1.md", "MASVS-CRYPTO-2.md",
    "MASVS-AUTH-1.md", "MASVS-AUTH-2.md", "MASVS-AUTH-3.md",
    "MASVS-NETWORK-1.md", "MASVS-NETWORK-2.md",
    "MASVS-PLATFORM-1.md", "MASVS-PLATFORM-2.md", "MASVS-PLATFORM-3.md",
    "MASVS-CODE-1.md", "MASVS-CODE-2.md", "MASVS-CODE-3.md", "MASVS-CODE-4.md",
    "MASVS-RESILIENCE-1.md", "MASVS-RESILIENCE-2.md", "MASVS-RESILIENCE-3.md",
    "MASVS-RESILIENCE-4.md",
    "MASVS-PRIVACY-1.md", "MASVS-PRIVACY-2.md", "MASVS-PRIVACY-3.md", "MASVS-PRIVACY-4.md",
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


def _fetch_cached(url: str, cache: Path) -> str | None:
    """Return a file's text from local cache, else fetch it once and cache it."""
    if cache.is_file():
        return cache.read_text(errors="replace")
    try:
        with urllib.request.urlopen(url, timeout=20) as r:
            md = r.read().decode("utf-8", "replace")
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(md)
        return md
    except Exception as e:  # offline / fetch failure: caller skips this file
        print(f"  ! could not fetch {cache.name}: {e}")
        return None


def _masvs_chunks(cache_dir: Path) -> list[Chunk]:
    cache_dir.mkdir(parents=True, exist_ok=True)
    chunks: list[Chunk] = []
    # Category intros (broad context), cited at category level.
    for name in MASVS_FILES:
        cat = "MASVS-" + name.split("MASVS-")[1].replace(".md", "")   # "MASVS-CRYPTO"
        md = _fetch_cached(MASVS_BASE + name, cache_dir / name)
        if md is None:
            continue
        chunks += _split_markdown(md, "masvs", cat, ref=cat)
    # Individual controls (the depth), each cited by its own control id.
    ctrl_dir = cache_dir / "controls"
    for name in MASVS_CONTROL_FILES:
        control_id = name.replace(".md", "")                          # "MASVS-CRYPTO-2"
        category = control_id.rsplit("-", 1)[0]                       # "MASVS-CRYPTO"
        md = _fetch_cached(MASVS_CONTROLS_BASE + name, ctrl_dir / name)
        if md is None:
            continue
        chunks.append(_control_chunk(md, control_id, category))
    return chunks


def _control_chunk(md: str, control_id: str, category: str) -> Chunk:
    """One MASVS control file -> one self-contained chunk cited by control id.

    Files are uniform: `# <id>` / `## Control` (the requirement) / `## Description`.
    We title the chunk with the requirement sentence and keep the full body so a
    query matches on both the control statement and its rationale."""
    statement = ""
    m = re.search(r"##\s*Control\s*\n+(.+?)(?:\n#|\Z)", md, re.S)
    if m:
        statement = " ".join(m.group(1).split())
    body = re.sub(r"^#\s*.*\n", "", md).strip()   # drop the redundant `# <id>` heading
    return Chunk(
        text=body,
        source="masvs",
        category=category,
        title=statement or control_id,
        ref=control_id,
    )


def gather_chunks(cache_dir: Path) -> list[Chunk]:
    """Collect all knowledge chunks from every source."""
    course = _course_chunks()
    masvs = _masvs_chunks(cache_dir)
    n_controls = sum(1 for c in masvs if c.ref[-2:-1] == "-" or c.ref.rsplit("-", 1)[-1].isdigit())
    print(f"  gathered {len(course)} course chunk(s), {len(masvs)} MASVS chunk(s) "
          f"({n_controls} control-level)")
    return course + masvs
