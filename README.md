# Velode Identity Connector

Spring Boot starter that connects an application's backend to
[Velode Identity](https://github.com/VelodeLabs/Velode-Identity).
The connector generates and renews its connection key; a global administrator approves the application in Identity.
Identity authenticates users and controls application access; the application owns roles and permissions.

## Guides

- [Connect an application](docs/connect-application.md)
- [Advanced usage](docs/advanced-usage.md)
- [Identity contracts](https://github.com/VelodeLabs/Velode-Identity/blob/master/docs/contracts.md#application-and-administration-boundaries)

## Develop And Release

Use Java 21 and the included Maven wrapper.
See the [development and release guide](docs/development.md) for verification and publishing.
