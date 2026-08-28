"""The agent's toolbox — what Claude can *do* during Step 3.

Every tool is confined to one analysis workspace (the decompiled trees for a
single APK). Paths are resolved and checked so the model cannot read outside it.
Tool schemas are plain JSON (used with the manual agentic loop in agent.py).
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

_MAX_READ = 60_000        # per-file char cap returned to the model
_MAX_GREP_HITS = 60
_MAX_STRINGS = 400
# resource-id noise + our own pipeline artifacts (never let the agent read the answers)
_ARTIFACTS = {"extraction.json", "ai_report.json", "agent_report.json"}
_SKIP_NAMES = {"R.java"} | _ARTIFACTS
_TEXT_EXT = {".java", ".xml", ".smali", ".kt", ".txt", ".json", ".properties"}

# JSON schemas advertised to the model.
TOOL_SCHEMAS = [
    {
        "name": "list_dir",
        "description": "List files and subdirectories at a path inside the decompiled APK "
                       "workspace. Use to navigate. Path is relative to the workspace root "
                       "(e.g. 'jadx/sources/com/example/app', 'apktool/res/xml').",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "read_file",
        "description": "Read a text file (Java, smali, XML resource, strings.xml, etc.) from "
                       "the workspace. Path relative to workspace root. Large files are truncated.",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "grep",
        "description": "Regex-search all decompiled text files (Java/smali/resources) for a "
                       "pattern. Returns matching file:line snippets. Use for hunting secrets, "
                       "crypto calls, URLs, exported components, etc.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Python regex, case-insensitive."},
                "subdir": {"type": "string", "description": "Optional path to limit the search."},
            },
            "required": ["pattern"],
            "additionalProperties": False,
        },
    },
    {
        "name": "strings_in_lib",
        "description": "Run `strings` on a native .so library and return printable strings, "
                       "optionally filtered by a substring. Path relative to workspace root "
                       "(e.g. 'apktool/lib/arm64-v8a/libcommsapp.so').",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "contains": {"type": "string", "description": "Optional case-insensitive filter."},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "search_knowledge",
        "description": "Search the security knowledge base (OWASP MASVS controls + the "
                       "analyst's OWASP Mobile Top 10 course notes) by meaning. Use it to ground "
                       "a finding in a real standard: pass a natural-language description of the "
                       "issue (e.g. 'hardcoded AES key in native library', 'cleartext HTTP "
                       "traffic allowed') and get back the most relevant control/notes with their "
                       "citation labels. Cite what you retrieve in the finding's `standards`.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Description of the security issue to look up."},
                "source": {
                    "type": "string",
                    "enum": ["masvs", "course"],
                    "description": "Optional: restrict to MASVS controls or course notes only.",
                },
            },
            "required": ["query"],
            "additionalProperties": False,
        },
    },
]


class Toolbox:
    """Executes tool calls against one workspace, safely."""

    def __init__(self, workspace: str):
        self.root = Path(workspace).resolve()
        self._kb = None            # lazily-loaded KnowledgeBase (Step 4 RAG)
        self._kb_tried = False

    def run(self, name: str, tool_input: dict) -> str:
        try:
            fn = getattr(self, f"_{name}", None)
            if fn is None:
                return f"Error: unknown tool '{name}'"
            return fn(**tool_input)
        except Exception as e:  # tools must never crash the loop
            return f"Error running {name}: {e}"

    # --- path safety ---
    def _resolve(self, path: str) -> Path:
        p = (self.root / path).resolve()
        if self.root not in p.parents and p != self.root:
            raise ValueError(f"path escapes workspace: {path}")
        return p

    # --- tools ---
    def _list_dir(self, path: str) -> str:
        d = self._resolve(path)
        if not d.exists():
            return f"(no such path: {path})"
        if d.is_file():
            return f"{path} is a file, not a directory."
        entries = sorted(
            (e for e in d.iterdir() if e.name not in _ARTIFACTS),
            key=lambda x: (x.is_file(), x.name),
        )
        lines = [f"{'d' if e.is_dir() else 'f'}  {e.name}" for e in entries[:300]]
        return "\n".join(lines) or "(empty)"

    def _read_file(self, path: str) -> str:
        f = self._resolve(path)
        if f.name in _ARTIFACTS:
            return f"(access denied: {path} is a pipeline artifact)"
        if not f.is_file():
            return f"(no such file: {path})"
        text = f.read_text(errors="replace")
        if len(text) > _MAX_READ:
            return text[:_MAX_READ] + f"\n\n[truncated at {_MAX_READ} chars of {len(text)}]"
        return text

    def _grep(self, pattern: str, subdir: str = "") -> str:
        base = self._resolve(subdir) if subdir else self.root
        rx = re.compile(pattern, re.IGNORECASE)
        hits: list[str] = []
        for f in base.rglob("*"):
            if not f.is_file() or f.suffix not in _TEXT_EXT or f.name in _SKIP_NAMES:
                continue
            try:
                for i, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
                    if rx.search(line):
                        rel = f.relative_to(self.root)
                        hits.append(f"{rel}:{i}: {line.strip()[:200]}")
                        if len(hits) >= _MAX_GREP_HITS:
                            hits.append(f"[stopped at {_MAX_GREP_HITS} hits]")
                            return "\n".join(hits)
            except Exception:
                continue
        return "\n".join(hits) if hits else f"(no matches for /{pattern}/)"

    def _strings_in_lib(self, path: str, contains: str = "") -> str:
        f = self._resolve(path)
        if not f.is_file():
            return f"(no such file: {path})"
        out = subprocess.run(["strings", str(f)], capture_output=True, text=True, timeout=60).stdout
        lines = out.splitlines()
        if contains:
            low = contains.lower()
            lines = [ln for ln in lines if low in ln.lower()]
        if len(lines) > _MAX_STRINGS:
            lines = lines[:_MAX_STRINGS] + [f"[truncated at {_MAX_STRINGS} of {len(lines)} strings]"]
        return "\n".join(lines) or "(no strings matched)"

    def _load_kb(self):
        """Load the RAG index once; None if it hasn't been built yet."""
        if self._kb_tried:
            return self._kb
        self._kb_tried = True
        try:
            from ..knowledge.store import KnowledgeBase
            if KnowledgeBase.exists():
                self._kb = KnowledgeBase.load()
        except Exception:
            self._kb = None
        return self._kb

    def _search_knowledge(self, query: str, source: str = "") -> str:
        kb = self._load_kb()
        if kb is None:
            return ("(knowledge base not available — build it with "
                    "`python3 run.py --build-kb`. Proceed using your own knowledge and "
                    "leave the finding's `standards` empty.)")
        hits = kb.search(query, k=4, source=source or None)
        if not hits:
            return f"(no knowledge matched '{query}')"
        return "\n\n---\n\n".join(h.as_context() for h in hits)
