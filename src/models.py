from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class Identity:
    identity_id: str
    display_name: str
    identity_type: str
    enabled: bool
    mfa_enabled: bool
    privileged: bool
    last_sign_in_days: Optional[int]
    owner: Optional[str]
    roles: List[str] = field(default_factory=list)
    group_memberships: List[str] = field(default_factory=list)
    standing_admin: bool = False
    break_glass: bool = False
    service_account: bool = False
    credential_age_days: Optional[int] = None


@dataclass(frozen=True)
class PrivilegeFinding:
    finding_id: str
    identity_id: str
    title: str
    severity: str
    score: int
    rationale: str
    remediation: str
    attack_techniques: List[str] = field(default_factory=list)
