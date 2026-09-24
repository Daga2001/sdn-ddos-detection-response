# ADR 0001: Keep Ryu for the first baseline

## Decision

Retain Ryu and the proposal’s controller terminology for the first repository release. Pin a legacy Python 3.9 environment and document the maintenance risk.

## Rationale

The student proposal and current implementation both use Ryu. Changing controller frameworks during repository curation would make experimental comparisons harder to interpret. A future OS-Ken migration is a separate, reviewable change.

## Consequences

The setup is more constrained and must remain isolated. The compatibility environment must be recorded with dependency versions and manual smoke-test evidence.
