"""Gather and chunk the knowledge sources into embeddable pieces.

The knowledge base has two halves, all sourced from public OWASP standards:

  RULEBOOK — what to cite:
    * OWASP MASVS — the Mobile App Security Verification Standard controls
      (STORAGE/CRYPTO/AUTH/NETWORK/PLATFORM/CODE/RESILIENCE/PRIVACY), fetched
      from GitHub once and cached; tagged source="masvs".

  PLAYBOOK — how to find/confirm an issue:
    * OWASP MASWE — the Mobile Application Security Weakness Enumeration
      (the catalog of concrete weaknesses); tagged source="maswe".
    * OWASP MASTG (V2) — the Android testing guide's test procedures
      (the "Static Analysis" steps per control); tagged source="mastg".
    * Optional local notes — any Markdown you drop in the playbook/ folder (or
      point APK_ANALYST_PLAYBOOK_DIR at); tagged source="course". Empty by
      default, so a clean clone builds a fully OWASP-sourced base.

Each source is split on Markdown headings into ~paragraph-sized chunks so a
query retrieves a focused control/subtopic rather than a whole document.
"""
from __future__ import annotations

import json
import os
import re
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

# Load .env so APK_ANALYST_PLAYBOOK_DIR (and friends) are visible here too.
load_dotenv(Path(__file__).resolve().parents[2] / ".env")

# The PLAYBOOK source — your own static-analysis methodology notes (how to find/
# confirm issues). MASVS below is the separate rulebook (what to cite).
#
# Location is fully user-configurable and defaults to a repo-local `playbook/`
# folder, so nothing points at any one machine's private paths:
#   • set APK_ANALYST_PLAYBOOK_DIR to any folder of Markdown notes (~ is expanded), or
#   • drop `.md` files into the repo's `playbook/` directory.
# If the folder is absent the build simply proceeds MASVS-only (see _course_chunks).
_DEFAULT_PLAYBOOK = Path(__file__).resolve().parents[2] / "playbook"

# The RULEBOOK also accepts your own local sources (in addition to OWASP MASVS):
# any `.md` under this folder is embedded as a rulebook entry and cited by its
# id/filename. Ships empty; configurable like the playbook.
_DEFAULT_RULEBOOK = Path(__file__).resolve().parents[2] / "rulebook"


def playbook_dir() -> Path:
    """Resolve the playbook directory from the env var, else the repo default."""
    raw = os.getenv("APK_ANALYST_PLAYBOOK_DIR")
    return Path(raw).expanduser() if raw else _DEFAULT_PLAYBOOK


def rulebook_dir() -> Path:
    """Resolve the local rulebook directory from the env var, else repo default."""
    raw = os.getenv("APK_ANALYST_RULEBOOK_DIR")
    return Path(raw).expanduser() if raw else _DEFAULT_RULEBOOK


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

# OWASP MASWE — Mobile Application Security Weakness Enumeration (the PLAYBOOK's
# "what can go wrong" catalog). Files live under weaknesses/MASVS-<CAT>/MASWE-*.md.
MASWE_REPO = "OWASP/maswe"
MASWE_BRANCH = "main"
MASWE_RAW = f"https://raw.githubusercontent.com/{MASWE_REPO}/{MASWE_BRANCH}/"

# OWASP MASTG V2 — the Android test procedures (the PLAYBOOK's "how to confirm"
# steps). V2 tests live under tests-beta/android/MASVS-<CAT>/MASTG-TEST-*.md;
# the older tests/ tree is mostly deprecated, so we use tests-beta.
MASTG_REPO = "OWASP/mastg"
MASTG_BRANCH = "master"
MASTG_RAW = f"https://raw.githubusercontent.com/{MASTG_REPO}/{MASTG_BRANCH}/"
MASTG_TESTS_PREFIX = "tests-beta/android/"

_MAX_WORDS = 320    # split chunks larger than this along paragraph boundaries
_MIN_WORDS = 12     # drop trivially short fragments (stray headings, etc.)


@dataclass
class Chunk:
    text: str
    source: str            # "masvs" | "maswe" | "mastg" | "course" | "rulebook"
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


def _course_chunks() -> list[Chunk]:
    """Chunk every `.md` note under the playbook dir (any folder structure).

    Absent playbook dir -> [] (build proceeds MASVS-only). Otherwise each file
    is cited by a generic rule (see _cite_for), so a user just drops their own
    methodology notes in without matching any prescribed layout.
    """
    base = playbook_dir()
    if not base.is_dir():
        print(f"  i no local playbook dir at {base} - using OWASP MASWE+MASTG only. "
              f"Optional: add .md notes there, or point APK_ANALYST_PLAYBOOK_DIR at a folder.")
        return []

    files = [f for f in sorted(base.rglob("*.md")) if f.name.lower() != "readme.md"]
    chunks: list[Chunk] = []
    for f in files:
        ref, cat = _cite_for(f, base)
        chunks += _split_markdown(f.read_text(encoding="utf-8", errors="replace"), "course", cat, ref=ref)
    if files:
        print(f"  local notes: {len(files)} .md file(s) at {base}")
    else:
        print(f"  i no local .md notes in {base} - using OWASP MASWE+MASTG only "
              f"(add notes there to supplement the playbook).")
    return chunks


def _cite_for(f: Path, base: Path) -> tuple[str, str]:
    """Derive (ref, category) for a playbook file from its name/path alone.

    A file named `M<n>_Title.md` (any folder) gets the tidy id label
    `Course:M<n>`; every other file is cited by its path relative to the
    playbook dir. No prescribed folder names — just conventions on the names."""
    m = re.match(r"(M\d+)_(.*)\.md$", f.name)
    if m:
        return f"Course:{m.group(1)}", f"{m.group(1)} {m.group(2).replace('_', ' ')}"
    rel = "/".join(f.relative_to(base).with_suffix("").parts)   # e.g. "crypto/aes-misuse"
    return f"Course:{rel}", rel.replace("_", " ")


def _local_rulebook_chunks() -> list[Chunk]:
    """Chunk every `.md` under the local rulebook dir (optional, empty by default).

    Lets a user add their *own* standard/controls to cite, alongside OWASP MASVS.
    Each file is cited by its filename stem (name your files after your control
    ids, e.g. `ACME-CRYPTO-1.md` -> cited `ACME-CRYPTO-1`). Absent dir -> []."""
    base = rulebook_dir()
    if not base.is_dir():
        return []
    files = [f for f in sorted(base.rglob("*.md")) if f.name.lower() != "readme.md"]
    chunks: list[Chunk] = []
    for f in files:
        ref = f.stem                                     # e.g. "ACME-CRYPTO-1"
        chunks += _split_markdown(f.read_text(encoding="utf-8", errors="replace"), "rulebook", ref, ref=ref)
    if files:
        print(f"  local rulebook: {len(files)} .md file(s) at {base}")
    return chunks


def _fetch_cached(url: str, cache: Path) -> str | None:
    """Return a file's text from local cache, else fetch it once and cache it."""
    if cache.is_file():
        return cache.read_text(encoding="utf-8", errors="replace")
    try:
        with urllib.request.urlopen(url, timeout=20) as r:
            md = r.read().decode("utf-8", "replace")
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(md, encoding="utf-8")
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


def _github_tree(repo: str, branch: str) -> list[str]:
    """Return every file path in a GitHub repo/branch (one API call, recursive).

    Used to enumerate the MASWE/MASTG markdown files without hardcoding hundreds
    of names. Network failure -> [] (caller then contributes nothing)."""
    url = f"https://api.github.com/repos/{repo}/git/trees/{branch}?recursive=1"
    headers = {"Accept": "application/vnd.github+json",
               "User-Agent": "apkanalyst-kb-build"}
    # The unauthenticated GitHub API allows only 60 requests/hour. A GITHUB_TOKEN
    # (a plain read-only token is enough) raises that to 5,000/hour, so repeated
    # rebuilds don't fail with 0 files fetched.
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        return [e["path"] for e in data.get("tree", []) if e.get("type") == "blob"]
    except Exception as e:
        print(f"  ! could not list {repo}@{branch}: {e}")
        return []


def _split_frontmatter(md: str) -> tuple[dict, str]:
    """Split a `--- ... ---` YAML front-matter header from the markdown body."""
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n?(.*)$", md, re.S)
    if not m:
        return {}, md
    try:
        import yaml
        meta = yaml.safe_load(m.group(1)) or {}
        if not isinstance(meta, dict):
            meta = {}
    except Exception:
        meta = {}
    return meta, m.group(2)


def _category_from_path(path: str) -> str:
    """Pull the MASVS-<CAT> segment out of a MASWE/MASTG file path (else '')."""
    m = re.search(r"(MASVS-[A-Z]+)", path)
    return m.group(1) if m else ""


def _owasp_note_chunks(paths: list[str], raw_base: str, cache_dir: Path,
                       source: str, id_regex: str) -> list[Chunk]:
    """Fetch + chunk a set of OWASP playbook files (MASWE or MASTG).

    Each file: strip YAML front-matter, skip anything marked deprecated, cite by
    its id (e.g. MASWE-0007 / MASTG-TEST-0327) taken from the frontmatter title
    or the filename, and categorize by the MASVS-<CAT> in its path."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    chunks: list[Chunk] = []
    kept = 0
    for path in paths:
        cache = cache_dir / Path(path).name
        md = _fetch_cached(raw_base + path, cache)
        if md is None:
            continue
        meta, body = _split_frontmatter(md)
        if str(meta.get("status", "")).lower() == "deprecated":
            continue
        stem = Path(path).name[:-3]                      # filename without .md
        m = re.search(id_regex, path)
        ref = m.group(0) if m else stem
        category = _category_from_path(path) or meta.get("title", ref)
        title = str(meta.get("title") or ref)
        # Prepend the human title so the vector carries the weakness/test name.
        body = f"# {title}\n{body.strip()}"
        chunks += _split_markdown(body, source, category, ref=ref)
        kept += 1
    print(f"  {source}: {kept} file(s) chunked from {raw_base.split('/')[3]}")
    return chunks


def _maswe_chunks(cache_dir: Path) -> list[Chunk]:
    """OWASP MASWE weaknesses (the playbook's 'what can go wrong')."""
    paths = [p for p in _github_tree(MASWE_REPO, MASWE_BRANCH)
             if p.startswith("weaknesses/") and re.search(r"MASWE-\d+\.md$", p)]
    return _owasp_note_chunks(paths, MASWE_RAW, cache_dir / "maswe",
                              "maswe", r"MASWE-\d+")


def _mastg_chunks(cache_dir: Path) -> list[Chunk]:
    """OWASP MASTG V2 Android test procedures (the playbook's 'how to confirm')."""
    paths = [p for p in _github_tree(MASTG_REPO, MASTG_BRANCH)
             if p.startswith(MASTG_TESTS_PREFIX) and re.search(r"MASTG-TEST-\d+\.md$", p)]
    return _owasp_note_chunks(paths, MASTG_RAW, cache_dir / "mastg",
                              "mastg", r"MASTG-TEST-\d+")


def gather_chunks(cache_dir: Path) -> list[Chunk]:
    """Collect all knowledge chunks from every source."""
    course = _course_chunks()             # optional local playbook notes (empty by default)
    local_rules = _local_rulebook_chunks()  # optional local rulebook (empty by default)
    maswe = _maswe_chunks(cache_dir)
    mastg = _mastg_chunks(cache_dir)
    masvs = _masvs_chunks(cache_dir)
    n_controls = sum(1 for c in masvs if c.ref.rsplit("-", 1)[-1].isdigit())
    extra = f", {len(local_rules)} local-rulebook" if local_rules else ""
    print(f"  gathered {len(course)} local + {len(maswe)} MASWE + {len(mastg)} MASTG "
          f"+ {len(masvs)} MASVS chunk(s){extra} ({n_controls} MASVS control-level)")
    return course + local_rules + maswe + mastg + masvs
