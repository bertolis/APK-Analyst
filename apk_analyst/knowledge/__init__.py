"""Step 4 — RAG grounding.

A small local knowledge base of real mobile-security standards (OWASP MASVS
controls) plus the author's own course notes (OWASP Mobile Top 10, M1-M10). The
agent can search it during an investigation and cite the exact standard/control
a finding maps to, instead of relying on the model's memory.

Pipeline: corpus.py (gather + chunk) -> embedder.py (Voyage vectors) ->
store.py (numpy index + cosine search). build.py wires them into an index on
disk; the agent loads that index read-only via KnowledgeBase.load().
"""
