"""RAG prompt templates for cybersecurity grounded generation."""

SYSTEM_PROMPT = """You are a cybersecurity research assistant. Your role is to answer
questions using ONLY the provided evidence from cybersecurity knowledge bases (NVD, MITRE CWE, MITRE CAPEC, MITRE ATT&CK).

CRITICAL RULES:
1. Only use the supplied evidence to answer the question.
2. Do NOT invent, fabricate, or hallucinate cybersecurity IDs (CVE, CWE, CAPEC, ATT&CK technique IDs).
3. Do NOT invent relationships between entities that are not in the evidence.
4. Do NOT invent data sources or references.
5. Do NOT fabricate vulnerabilities or attack patterns.
6. Clearly distinguish between evidence-based facts and any analytical inference.
7. Cite evidence by referencing entity IDs (e.g., CVE-2024-1234, CWE-79).
8. If the evidence is insufficient to fully answer the question, explicitly state:
   "The available evidence is insufficient to fully answer this question."
9. If no relevant evidence was found, state:
   "No matching vulnerability record or sufficient supporting evidence was found in the current knowledge base."
10. Never claim that the system can detect every unknown vulnerability.
11. Label any analytical reasoning clearly as INFERENCE, not FACT.
"""

RAG_PROMPT_TEMPLATE = """Based on the following cybersecurity evidence, answer the user's question.

=== RETRIEVED EVIDENCE ===
{evidence_text}

=== USER QUESTION ===
{question}

=== INSTRUCTIONS ===
- Base your answer strictly on the evidence above.
- Cite specific entity IDs when referencing evidence.
- If evidence is insufficient, say so explicitly.
- Distinguish between FACT (directly from evidence) and INFERENCE (your reasoning).
- Do not fabricate any cybersecurity identifiers or relationships.

Answer:"""


def format_evidence_for_prompt(evidence: list[dict]) -> str:
    """Format evidence items into a prompt-ready text block."""
    if not evidence:
        return "No evidence was retrieved for this question."

    parts: list[str] = []
    for i, e in enumerate(evidence, 1):
        eid = e.get("id", "unknown")
        etype = e.get("entity_type", "")
        name = e.get("name", "")
        desc = (e.get("description", "") or "")[:800]
        source = e.get("source", "")
        score = e.get("relevance_score", 0)
        method = e.get("retrieval_method", "")

        entry = f"[Evidence {i}] {etype} {eid}"
        if name and name != eid:
            entry += f" — {name}"
        entry += f"\nSource: {source} | Relevance: {score:.3f} | Method: {method}"
        if desc:
            entry += f"\nDescription: {desc}"

        # Include relationship info if present
        rel_type = e.get("relationship_type", "")
        if rel_type:
            entry += f"\nRelationship: {rel_type}"

        parts.append(entry)

    return "\n\n".join(parts)


def build_rag_prompt(question: str, evidence: list[dict]) -> tuple[str, str]:
    """Build the system prompt and user prompt for RAG."""
    evidence_text = format_evidence_for_prompt(evidence)
    user_prompt = RAG_PROMPT_TEMPLATE.format(
        evidence_text=evidence_text,
        question=question,
    )
    return SYSTEM_PROMPT, user_prompt
