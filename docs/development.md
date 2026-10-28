# Development And Release

## Verify

```powershell
./mvnw.cmd verify
```

## Scan

CI scans every push and pull request. To run the same scans locally with Docker:

```bash
docker run --rm -v "$PWD:/repo" ghcr.io/gitleaks/gitleaks:v8.30.1 git /repo --redact
./mvnw org.cyclonedx:cyclonedx-maven-plugin:2.9.1:makeBom -DoutputFormat=json -DoutputName=bom -DincludeTestScope=true
docker run --rm -v "$PWD/target:/sbom:ro" ghcr.io/google/osv-scanner:v2.2.4 scan source -L /sbom/bom.json
```

## Dependencies

Dependabot only raises alerts for vulnerable dependencies; it opens no pull requests. Update dependencies by hand on a
branch from `develop`, keeping the Spring Boot parent on the oldest supported line (patch releases only). The weekly
`Security` workflow also fails when a new advisory affects a dependency.

## Branches

Work on a branch from `develop` and open a pull request against it; see [contributing](../CONTRIBUTING.md).
`master` only receives pull requests from `develop` and always holds released code.

## Release

1. On a branch from `develop`, set the new version in `pom.xml` and in the
   [connection guide](connect-application.md), and merge it to `develop`.
2. Open a pull request from `develop` to `master` and merge it once CI passes.
3. Push a matching tag from `master`, such as `v0.4.1`.

The `Publish` workflow refuses a tag that differs from the `pom.xml` version, then publishes the jar, sources and
Javadoc to Maven Central (signed) and to GitHub Packages. Published versions are immutable; release a new one instead
of replacing it.

### Maven Central

The `maven-central` environment only accepts release tags and holds:

| Secret | Value |
| --- | --- |
| `CENTRAL_USERNAME`, `CENTRAL_TOKEN` | A user token from central.sonatype.com for the verified `com.velode` namespace |
| `GPG_PRIVATE_KEY`, `GPG_PASSPHRASE` | The armored signing key and its passphrase |

The signing key is `0FA015BF13775E582A58C41EDC3A6A2D31C6A2F1` (Velode Labs, RSA 4096), published on
`keyserver.ubuntu.com` and `keys.openpgp.org`. It expires in October 2029: extend it with `gpg --quick-set-expire`,
publish it again and update `GPG_PRIVATE_KEY`. If the token or key leaks, revoke it and replace the secrets.

To check a release build locally without publishing, give the build any signing key through `MAVEN_GPG_KEY` and
`MAVEN_GPG_PASSPHRASE`, and a `central` server in `~/.m2/settings.xml`:

```bash
./mvnw -P release,central deploy -DskipPublishing=true
```
