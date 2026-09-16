# Rulebook — optional local standards to cite

The **rulebook** is the "what standard did this violate" half of the knowledge
base. By default it is **OWASP MASVS**, fetched automatically from OWASP's public
repo at build time — you don't need to add anything.

**This folder is optional.** Drop your own standard/control files here to have the
agent cite *them too* (alongside MASVS) — e.g. an internal secure-coding standard,
a client's requirements, or a compliance mapping.

## How to add your own

Put any Markdown (`.md`) files in this folder — any subfolder structure is fine —
then rebuild the index:

```bash
python3 run.py --build-kb
```

Each file is cited by its **filename** (without `.md`), so name files after your
control ids:

```
rulebook/ACME-CRYPTO-1.md   ->  cited as  ACME-CRYPTO-1
rulebook/PCI-DSS-6.5.3.md   ->  cited as  PCI-DSS-6.5.3
```

Inside each file, write the control statement and rationale in plain Markdown —
headings split it into focused, searchable chunks.

## Keep notes elsewhere (configurable)

To read the rulebook from a folder outside the repo, set an env var in `.env`:

```bash
APK_ANALYST_RULEBOOK_DIR=~/path/to/your/standards
```

`~` is expanded; an absolute path works too. When set, this folder is ignored.

> The same idea applies to the **playbook** (how to find/confirm) — see
> [`../playbook/README.md`](../playbook/README.md).
