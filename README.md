# Velode Identity Connector

[![CI](https://github.com/velodelabs/Velode-Identity-Connector/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/velodelabs/Velode-Identity-Connector/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Spring Boot starter that connects an application's backend to Velode Identity.
The connector generates and renews its connection key; a global administrator approves the application in Identity.
Identity authenticates users and controls application access; the application owns roles and permissions.

- No credentials to copy or configure: set two addresses and approve the application in the Identity panel.
- Sign-in through Identity's page, or on the application's own page with its own design.
- Key rotation and reconnection shared safely between replicas.

Requires Java 21 and Spring Boot 3.5 or 4.x with a servlet stack.

## Guides

- [Connect an application](docs/connect-application.md)
- [Advanced usage](docs/advanced-usage.md)
- [Security guide](docs/security.md)
- [Identity protocol](docs/identity-protocol.md)
- [Changelog](CHANGELOG.md)

## Develop And Release

Use Java 21 and the included Maven wrapper.
See the [development and release guide](docs/development.md) and [how to contribute](CONTRIBUTING.md).

## Security

Report vulnerabilities privately as described in the [security policy](SECURITY.md).

## License

[Apache License 2.0](LICENSE)
