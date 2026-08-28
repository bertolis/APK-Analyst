"""Structured output schema — what a finding *is*.

The whole point of Step 2: force the model's analysis into a consistent,
machine-usable shape (severity / OWASP-M / CWE / location / evidence), mapped
to the course playbook, instead of free-form prose. This Pydantic model is
handed to `client.messages.parse(output_format=...)`.
"""
from __future__ import annotations

from enum import Enum
from typing import List

from pydantic import BaseModel, Field


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Confidence(str, Enum):
    firm = "firm"          # evidence directly shown
    likely = "likely"      # strong signal, not fully confirmed
    tentative = "tentative"  # worth a human look


class OwaspMobile(str, Enum):
    m1_credentials = "M1: Improper Credential Usage"
    m2_supply_chain = "M2: Inadequate Supply Chain Security"
    m3_auth = "M3: Insecure Authentication/Authorization"
    m4_validation = "M4: Insufficient Input/Output Validation"
    m5_communication = "M5: Insecure Communication"
    m6_privacy = "M6: Inadequate Privacy Controls"
    m7_binary = "M7: Insufficient Binary Protections"
    m8_misconfig = "M8: Security Misconfiguration"
    m9_storage = "M9: Insecure Data Storage"
    m10_crypto = "M10: Insufficient Cryptography"


class Finding(BaseModel):
    title: str = Field(description="Short, specific name for the issue.")
    severity: Severity
    confidence: Confidence
    owasp_mobile: OwaspMobile = Field(description="Best-matching OWASP Mobile Top 10 (2024) category.")
    cwe: str = Field(description="CWE id like 'CWE-798', or 'N/A' if none fits.")
    location: str = Field(description="File / class / component the finding sits in, as specific as the evidence allows.")
    evidence: str = Field(description="The concrete code/manifest snippet or fact that supports this. Quote it.")
    exploit_path: str = Field(description="How an attacker reaches and abuses this, concretely.")
    recommendation: str = Field(description="What the developer should change.")
    standards: List[str] = Field(
        default_factory=list,
        description="Citations retrieved from the knowledge base that this finding maps to, "
                    "e.g. 'MASVS-CRYPTO-1', 'Course:M10'. Empty if none was retrieved. "
                    "Only cite standards you actually looked up via search_knowledge.",
    )


class AnalysisReport(BaseModel):
    summary: str = Field(description="2-3 sentence overall security posture of the app.")
    findings: List[Finding]
