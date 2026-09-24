# ADR 0002: Use OpenFlow 1.3 as the implemented baseline

The current Ryu app and topology explicitly use OpenFlow 1.3. The proposal contains an OpenFlow 1.0 reference, so the first release treats code behavior as authoritative and records the discrepancy for academic reconciliation rather than silently changing protocol versions.
