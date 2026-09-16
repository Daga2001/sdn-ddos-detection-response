# Security and responsible use

This project is for authorized, isolated academic experimentation. It is not a production DDoS defense and must not be used to test systems without written authorization.

The experiment launcher accepts only private IPv4 addresses in `SDN_ALLOWED_TARGET_CIDRS`, requires `--confirm-isolated-lab`, caps traffic at 1,000 packets/second and 300 seconds, and uses no shell interpolation. Keep the controller’s `SDN_MITIGATION_ENABLED=false` unless a test plan explicitly enables it.

Do not report secrets, private keys, database passwords, public proxy lists, raw attack logs, or packet captures in issues. If a vulnerability affects the repository, contact the maintainers privately and include reproducible steps that remain inside the lab.
