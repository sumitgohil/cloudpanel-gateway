# Security policy

## Supported versions

Security fixes are applied to the latest release on `main`. Older releases may
receive guidance but are not guaranteed to receive patches.

## Reporting a vulnerability

Please do **not** open a public GitHub issue for suspected vulnerabilities.
Report privately to the repository owner through GitHub's private security
advisory flow, including:

- affected version and CloudPanel/Ubuntu version;
- impact and reproduction steps;
- proof of concept with all secrets, tokens, domains, IPs, and customer data
  removed; and
- any suggested mitigation.

We will acknowledge a valid report within seven days, assess it, and coordinate
a fix and disclosure timeline with the reporter. Do not access data, disrupt
services, or exceed the minimum testing needed to demonstrate the issue.

## Scope

Relevant issues include authentication or token handling, helper or Nginx
commit socket access, command injection, path traversal, privilege separation,
artifact handling, audit redaction, release signing, and unsafe installation
behavior.
