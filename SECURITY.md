# Security Policy

## Supported Versions

Security fixes are released for the latest minor version only. Upgrade to it before reporting.

| Version | Supported |
| --- | --- |
| 0.4.x | Yes |
| < 0.4 | No |

## Reporting A Vulnerability

Do not open a public issue, discussion or pull request for a vulnerability.

Report it privately through
[GitHub's private vulnerability reporting](https://github.com/VelodeLabs/Velode-Identity-Connector/security/advisories/new)
(**Security > Report a vulnerability**). Include the affected version, how to reproduce it and the impact you
expect. If the issue lies in Velode Identity rather than in this connector, report it here as well and we will route it.

We aim to acknowledge reports within five working days, keep you informed while we fix them, and credit you in the
published advisory unless you prefer otherwise. Please give us a reasonable time to release a fix before disclosing.

## Scope

In scope: the code in this repository, its published package and the HTTP endpoints it adds to an application
(`/velode-identity/**`).

Out of scope: weaknesses that require an attacker to already control the application's database, server or
configuration, and findings in applications that ignore the [security guide](docs/security.md), such as running
without HTTPS or trusting forwarded headers from any client.

## How The Connector Is Protected

[docs/security.md](docs/security.md) describes what the connector keeps secret, the protections of its sign-in
endpoints and what the application remains responsible for.
