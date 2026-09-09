# Identity Privilege Audit

A defensive identity-security engineering project for assessing privileged-access posture, identifying excessive or weakly protected privilege, prioritizing remediation, and validating that identity risk has actually been reduced.

This repository uses **synthetic identity data only**. It does not connect to production Active Directory, Microsoft Entra ID, PAM/PIM platforms, credential stores, or employer/client environments.

## Problem statement

Privileged identities concentrate organizational risk. A directory can appear healthy while still containing standing administrators, dormant privileged users, weak MFA coverage, unmanaged service accounts, stale credentials, and identities with no accountable owner. These conditions expand blast radius and create opportunities for abuse of valid accounts.

This project demonstrates how to turn normalized identity evidence into deterministic, explainable security findings and remediation priorities.

## Capabilities

- Canonical identity and privilege data model
- Detection of privileged identities without MFA
- Standing-administrator review
- Dormant privileged-identity detection
- Identity ownership governance checks
- Service-account credential-age review
- Privileged non-human identity detection
- Severity-weighted posture scoring
- Deterministic finding identifiers
- JSON CLI reporting
- Synthetic test inventory
- Unit-test coverage
- Remediation and revalidation methodology
- GitHub Actions CI and smoke assessment

## Architecture

```text
Synthetic identity inventory
          |
          v
Canonical Identity model
          |
          v
Privilege audit controls
          |
          +--> MFA / standing privilege
          +--> dormancy / ownership
          +--> service-account hygiene
          |
          v
Severity + posture scoring
          |
          v
JSON findings / remediation workflow
```

See [`docs/architecture.md`](docs/architecture.md) for component boundaries and production extension points.

## Repository structure

```text
.github/workflows/ci.yml       CI unit tests + smoke assessment
data/synthetic_identities.json Synthetic identity inventory
docs/architecture.md          Technical architecture
docs/methodology.md           Review and revalidation methodology
reports/example-assessment.md Example executive-style report
src/models.py                 Canonical models
src/audit.py                  Audit controls and scoring
src/cli.py                    Batch CLI
tests/test_audit.py           Unit tests
```

## Usage

Requires Python 3.10+ and no third-party runtime dependencies.

```bash
python src/cli.py data/synthetic_identities.json
```

Run the test suite:

```bash
python -m unittest discover -s tests -p 'test_*.py'
```

## Risk model

Findings are deliberately explainable rather than opaque. Current controls classify weaknesses as Medium, High, or Critical and map them to a bounded posture score. Severity indicates control weakness and potential blast radius; it is **not evidence that compromise occurred**.

Example high-priority conditions include:

- Privileged interactive identity without MFA
- Persistent standing administrative access
- Dormant privileged identity
- Privileged service account with excessive permissions
- Stale service-account credentials
- Missing accountable identity owner

## MITRE ATT&CK context

| Technique | Relevance |
|---|---|
| T1078 — Valid Accounts | Weakly protected or excessive privilege can increase impact if a legitimate identity is compromised or misused. |
| T1098 — Account Manipulation | Persistent or excessive administrative assignments can create durable privileged access paths. |

ATT&CK is used for defensive context only. The repository does not automate credential theft, account abuse, persistence, or exploitation.

## Remediation workflow

1. Validate identity, role, and owner data.
2. Confirm business need for each privileged assignment.
3. Remove obsolete or excessive privilege.
4. Replace standing administration with eligible/time-bound elevation where feasible.
5. Enforce phishing-resistant MFA for privileged interactive identities.
6. Rotate aged non-human credentials and prefer managed/workload identities.
7. Re-run the audit against refreshed evidence.
8. Close findings only when changed-state evidence is available.

See [`docs/methodology.md`](docs/methodology.md) for exception handling and revalidation guidance.

## Design decisions

- **Evidence before inference:** missing metadata is reported as governance debt, not compromise.
- **Deterministic findings:** stable finding IDs support remediation tracking and revalidation.
- **Disabled identities:** currently excluded from active-control findings to avoid overstating present exposure.
- **Break-glass accounts:** explicit exception logic prevents normal MFA/standing-admin controls from being misapplied; production governance should still separately monitor emergency identities.
- **No live directory integration:** collection and authorization concerns are intentionally separated from the assessment engine.

## Limitations

This lab does not yet model nested group expansion, entitlement-management workflows, Conditional Access evaluation, access-package governance, PIM activation history, risky sign-ins, session controls, workload federation, or credential exposure telemetry. Production implementations would also require authoritative HR, directory, PAM/PIM, sign-in, and change-management data.

## Skills demonstrated

- Identity security engineering
- Active Directory / Entra ID security concepts
- Privileged-access governance
- Security control design
- Risk prioritization
- Python security automation
- Defensive ATT&CK mapping
- Unit testing
- CI/CD security engineering
- Remediation validation
- Executive security reporting

## Roadmap

- Nested group and transitive privilege analysis
- Role criticality catalogue
- PIM/PAM eligibility and activation review
- Conditional Access coverage correlation
- Service-principal and workload-identity permissions
- Access-review attestation evidence
- Historical privilege drift and trend metrics
- Graph-based toxic privilege combinations

## Safety

All identities, roles, owners, and findings in this repository are synthetic. The project contains no real credentials, client data, production targeting, offensive payloads, or credential-abuse automation.
