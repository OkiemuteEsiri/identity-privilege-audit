from __future__ import annotations

import hashlib
from typing import Iterable, List

from models import Identity, PrivilegeFinding

SEVERITY_WEIGHT = {"low": 20, "medium": 45, "high": 70, "critical": 90}


def _finding(identity: Identity, title: str, severity: str, rationale: str, remediation: str, techniques: list[str]) -> PrivilegeFinding:
    digest = hashlib.sha256(f"{identity.identity_id}:{title}".encode()).hexdigest()[:12]
    return PrivilegeFinding(
        finding_id=f"IP-{digest}",
        identity_id=identity.identity_id,
        title=title,
        severity=severity,
        score=SEVERITY_WEIGHT[severity],
        rationale=rationale,
        remediation=remediation,
        attack_techniques=techniques,
    )


def audit_identity(identity: Identity) -> List[PrivilegeFinding]:
    findings: list[PrivilegeFinding] = []
    if not identity.enabled:
        return findings

    if identity.privileged and not identity.mfa_enabled and not identity.break_glass:
        findings.append(_finding(identity, "Privileged identity without MFA", "critical",
            "A standing or assigned privileged identity is enabled without MFA protection.",
            "Require phishing-resistant MFA and validate Conditional Access coverage.", ["T1078"]))

    if identity.standing_admin and not identity.break_glass:
        findings.append(_finding(identity, "Standing administrative privilege", "high",
            "Persistent privileged access increases the window for misuse or account compromise.",
            "Replace standing access with time-bound eligible elevation and approval where feasible.", ["T1078", "T1098"]))

    if identity.last_sign_in_days is not None and identity.last_sign_in_days >= 90 and identity.privileged:
        findings.append(_finding(identity, "Dormant privileged identity", "high",
            f"Privileged identity has not signed in for {identity.last_sign_in_days} days.",
            "Confirm business need, disable or remove privilege, and document an owner-approved exception if retained.", ["T1078"]))

    if not identity.owner:
        findings.append(_finding(identity, "Missing identity owner", "medium",
            "No accountable owner is recorded for the identity.",
            "Assign a business or technical owner and establish periodic attestation.", []))

    if identity.service_account and identity.credential_age_days is not None and identity.credential_age_days > 180:
        findings.append(_finding(identity, "Aged service-account credential", "high",
            f"Service-account credential age is {identity.credential_age_days} days.",
            "Rotate the credential, prefer managed identity or workload federation, and verify dependent services.", ["T1078"]))

    if identity.service_account and identity.privileged:
        findings.append(_finding(identity, "Privileged service account", "high",
            "A non-human identity holds elevated privileges, increasing blast radius if its credential is exposed.",
            "Reduce privileges to task-specific permissions and migrate to managed identity where possible.", ["T1078", "T1098"]))

    return findings


def audit_identities(identities: Iterable[Identity]) -> List[PrivilegeFinding]:
    findings: list[PrivilegeFinding] = []
    for identity in identities:
        findings.extend(audit_identity(identity))
    return sorted(findings, key=lambda item: (-item.score, item.identity_id, item.title))


def posture_score(findings: Iterable[PrivilegeFinding]) -> int:
    penalties = sum(f.score for f in findings)
    return max(0, 100 - min(100, round(penalties / 5)))
