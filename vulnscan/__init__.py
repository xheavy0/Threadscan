"""vulnscan: a standalone AI vulnerability scanner.

Host side (this package, PyYAML only): parse the target config, split the target
into components, build images, run one sandboxed agent per component, re-run every
candidate's reproducer itself (the verification gate) and write the report.

Container side: ``agent_runner.py`` (Claude Agent SDK) and ``gateway.py`` (stdlib)
are copied into containers and never imported by the host at scan time.
"""

__version__ = "0.1.0"
