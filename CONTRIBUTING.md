# Contributing

Thanks for helping improve the Velode Identity Connector. Report vulnerabilities privately as described in the
[security policy](SECURITY.md), never in a public issue.

## Branches

- `master` holds released code. It only receives pull requests from `develop`.
- `develop` collects the work for the next release.
- Work happens on a short-lived branch from `develop`, named for its purpose: `feature/…`, `fix/…`, `docs/…`,
  `test/…` or `chore/…`. Open the pull request against `develop`.

## Pull Requests

- Keep each pull request to one change, with tests for behavior it adds or fixes.
- Run `./mvnw verify` (`./mvnw.cmd verify` on Windows) before pushing. It needs Java 21.
- CI must pass: the build and tests, the secret scan and the dependency scan.
- Match the surrounding code: package-private classes, records for values, and comments that explain why rather than
  what. Tests drive the connector against a stand-in for Identity; see `VelodeIdentityTest`.
- Update the guides in `docs/` when behavior that applications see changes.

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).
