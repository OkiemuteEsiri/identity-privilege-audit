import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from audit import audit_identity, audit_identities, posture_score
from models import Identity


def make_identity(**overrides):
    base = dict(
        identity_id="id-1",
        display_name="Synthetic Identity",
        identity_type="user",
        enabled=True,
        mfa_enabled=True,
        privileged=False,
        last_sign_in_days=1,
        owner="Security",
        roles=[],
        group_memberships=[],
        standing_admin=False,
        break_glass=False,
        service_account=False,
        credential_age_days=10,
    )
    base.update(overrides)
    return Identity(**base)


def test_privileged_without_mfa_is_critical():
    findings = audit_identity(make_identity(privileged=True, mfa_enabled=False))
    assert any(f.title == "Privileged identity without MFA" and f.severity == "critical" for f in findings)


def test_break_glass_exempts_mfa_and_standing_admin_controls():
    findings = audit_identity(make_identity(privileged=True, mfa_enabled=False, standing_admin=True, break_glass=True))
    assert not any(f.title in {"Privileged identity without MFA", "Standing administrative privilege"} for f in findings)


def test_dormant_privileged_identity_detected():
    findings = audit_identity(make_identity(privileged=True, last_sign_in_days=120))
    assert any(f.title == "Dormant privileged identity" for f in findings)


def test_missing_owner_detected():
    findings = audit_identity(make_identity(owner=None))
    assert any(f.title == "Missing identity owner" for f in findings)


def test_aged_privileged_service_account_generates_multiple_findings():
    findings = audit_identity(make_identity(service_account=True, privileged=True, credential_age_days=365))
    titles = {f.title for f in findings}
    assert "Aged service-account credential" in titles
    assert "Privileged service account" in titles


def test_disabled_identity_is_not_reported():
    assert audit_identity(make_identity(enabled=False, privileged=True, mfa_enabled=False, owner=None)) == []


def test_findings_are_sorted_by_score():
    findings = audit_identities([
        make_identity(identity_id="a", owner=None),
        make_identity(identity_id="b", privileged=True, mfa_enabled=False),
    ])
    assert findings[0].score >= findings[-1].score


def test_posture_score_degrades_with_findings():
    low = posture_score([])
    high_risk = posture_score(audit_identity(make_identity(privileged=True, mfa_enabled=False, standing_admin=True)))
    assert low == 100
    assert high_risk < low
