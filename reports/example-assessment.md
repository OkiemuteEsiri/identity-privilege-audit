# Example Identity Privilege Assessment

> Synthetic demonstration only. No production identities or employer/client data are used.

## Executive summary

The sample inventory contains four identities. The audit highlights three high-value governance themes: privileged interactive access without MFA, persistent administrative privilege, and elevated non-human identities with stale credentials. A separate dormant privileged identity demonstrates lifecycle risk.

## Prioritized findings

| Priority | Identity | Finding | Severity | Validation target |
|---|---|---|---|---|
| P0 | `usr-admin-001` | Privileged identity without MFA | Critical | MFA enforcement visible in refreshed identity evidence |
| P1 | `usr-admin-001` | Standing administrative privilege | High | Standing role removed or converted to eligible/time-bound elevation |
| P1 | `svc-reporting-001` | Aged service-account credential | High | Credential rotated or workload identity implemented |
| P1 | `svc-reporting-001` | Privileged service account | High | Permissions reduced to task-specific scope |
| P1 | `usr-dormant-001` | Dormant privileged identity | High | Privilege removed, account disabled, or exception approved |
| P2 | `svc-reporting-001` | Missing identity owner | Medium | Accountable owner recorded and attestation scheduled |

## Remediation sequence

1. Protect privileged interactive access with phishing-resistant MFA.
2. Reduce persistent Tier-0/administrative access using just-in-time or eligible elevation.
3. Review dormant privileged identities for deprovisioning.
4. Reduce service-account privileges and rotate aged credentials.
5. Assign accountable ownership to all non-human identities.
6. Re-run the assessment and retain evidence of the changed state.

## Residual risk

Identity risk is not eliminated by remediation of these controls alone. Production programs should also evaluate nested group membership, privileged access workflows, Conditional Access coverage, risky sign-ins, workload identity permissions, credential exposure, and periodic access reviews.
