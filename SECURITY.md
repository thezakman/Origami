# Security Policy

## Authorized use only

Origami is an **offensive security tool** built for authorized engagements:
penetration tests with written scope, bug-bounty programs that permit active
testing, CTF competitions, and assets you own or operate.

Scanning systems you are not explicitly authorized to test may be **illegal**
(e.g. the U.S. Computer Fraud and Abuse Act, the UK Computer Misuse Act, and
equivalents worldwide) and is against the spirit of this project. You are solely
responsible for ensuring you have permission before pointing Origami at any
target. The authors accept no liability for misuse — see the Apache-2.0
`LICENSE` (provided "AS IS", without warranty).

The tool itself encodes this posture: it honors `--exclude` safety rails, the
cache-poisoning fold only detects the primitive (it never writes a poisoned
response to a cache key real users hit), and active modules are opt-in.

## Reporting a vulnerability in Origami

If you find a security issue **in Origami itself** (e.g. a way the tool could be
turned against its operator, an injection in report generation, a dependency
risk), please report it privately rather than opening a public issue:

- Email: **thezakman@ctf-br.org**
- Include: affected version (`origami --version`), a description, and steps to
  reproduce.

You can expect an acknowledgement within a reasonable timeframe. Please give a
chance to ship a fix before any public disclosure.

## Supported versions

Security fixes target the latest released version. Always run the most recent
version (`git pull` / `pip install -U origami-scanner`).
