# Playbook — optional local methodology notes

The RAG knowledge base is built entirely from **public OWASP standards**, fetched
at build time:

- **Rulebook — OWASP MASVS** (the controls to *cite*).
- **Playbook — OWASP MASWE + MASTG** (weaknesses + Android test procedures: *how
  to find and confirm* an issue).

**This folder is optional.** It ships empty; anything you drop here is embedded
*in addition to* the OWASP playbook, so you can ground the agent in your own
static-analysis notes too. Leave it empty and the base is 100% OWASP-sourced.

## How to add notes

Put any Markdown (`.md`) files in this folder — any subfolder structure is fine —
then build the index:

```bash
python3 run.py --build-kb
```

Every `.md` here (except this `README.md`) is embedded and becomes searchable by
the agent's `search_knowledge` tool. Each file is cited by its path relative to
this folder, e.g. `playbook/crypto/aes-misuse.md` → cited as `Course:crypto/aes-misuse`.

**Tidy label shortcut:** a file named `M<n>_Title.md` (any folder) is cited as
`Course:M<n>` — handy if you organise notes by OWASP Mobile Top 10 category
(e.g. `M10_Insufficient_Cryptography.md` → `Course:M10`).

## Where the notes live (configurable)

By default the build reads this repo-local `playbook/` directory. To keep your
notes elsewhere (outside the repo, a shared drive, etc.), set an environment
variable in your `.env`:

```bash
APK_ANALYST_PLAYBOOK_DIR=~/path/to/your/notes
```

`~` is expanded; an absolute path works too. When set, this folder is ignored.

## No playbook? That's fine

If this folder is empty (and `APK_ANALYST_PLAYBOOK_DIR` is unset), `--build-kb`
still succeeds and builds a **MASVS-only** index. The agent runs normally;
findings cite MASVS controls but not a methodology playbook.
