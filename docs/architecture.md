# Architecture

## Objective

Provide an explainable, testable identity-governance assessment pipeline using synthetic identity data only.

## Components

1. **Input inventory** — normalized identity records in JSON.
2. **Canonical model** — `Identity` and `PrivilegeFinding` dataclasses.
3. **Audit engine** — deterministic controls for privilege, MFA, dormancy, ownership, and service-account hygiene.
4. **Scoring layer** — severity-weighted findings and bounded posture score.
5. **CLI** — repeatable batch execution against a supplied inventory.
6. **Tests** — control-level and scoring behavior validation.
7. **CI** — unit tests and a synthetic smoke run on every change.

## Trust boundaries

This project does not connect to Active Directory, Microsoft Entra ID, production directories, credential stores, or live APIs. All examples are synthetic. A production implementation would place collection adapters outside the assessment core and would require explicit authorization, least-privilege read access, secret management, data-retention controls, and audit logging.

## Design principles

- Separate evidence from interpretation.
- Preserve deterministic finding identifiers.
- Do not treat missing metadata as proof of compromise.
- Prefer remediations that reduce standing privilege and credential exposure.
- Keep break-glass treatment explicit rather than silently suppressing all governance requirements.
