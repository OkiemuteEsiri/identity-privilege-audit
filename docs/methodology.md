# Methodology

## Review scope

The lab evaluates identity and privilege posture from normalized inventory records. It is designed for defensive security engineering, identity governance, and vulnerability/exposure reduction workflows.

## Control families

- Privileged identities without MFA
- Standing administrative privilege
- Dormant privileged identities
- Missing accountable ownership
- Aged service-account credentials
- Privileged non-human identities

## Risk interpretation

Severity reflects control weakness and potential blast radius, not confirmed compromise. ATT&CK references provide adversary-context mapping only.

## MITRE ATT&CK context

- **T1078 — Valid Accounts:** stolen or abused privileged identities can enable authorized-looking access.
- **T1098 — Account Manipulation:** persistent or excessive privilege can increase opportunities for account/role abuse.

## Remediation workflow

1. Validate identity and role ownership.
2. Confirm whether privilege is required for current duties.
3. Remove obsolete or excessive role assignments.
4. Replace standing administration with time-bound eligible access where supported.
5. Enforce phishing-resistant MFA for privileged interactive identities.
6. Rotate aged service credentials and prefer managed/workload identities.
7. Re-run the assessment against refreshed evidence.
8. Document approved exceptions with owner, reason, compensating controls, and expiry date.

## Revalidation evidence

A finding is considered remediated only after refreshed inventory demonstrates the control change. Ticket closure alone is not sufficient evidence.

## Limitations

The lab does not model every directory feature, nested-group path, conditional-access condition, entitlement-management workflow, or privileged access management platform. A production review would enrich these controls with authoritative directory, HR, PAM/PIM, sign-in, and change-management data.
