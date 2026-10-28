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

## Branches

Work on a branch from `develop` and open a pull request against it; see [contributing](../CONTRIBUTING.md).
`master` only receives pull requests from `develop` and always holds released code.

## Release

1. On a branch from `develop`, set the new version in `pom.xml` and in the
   [connection guide](connect-application.md), and merge it to `develop`.
2. Open a pull request from `develop` to `master` and merge it once CI passes.
3. Push a matching tag from `master`, such as `v0.4.0`.

The `Publish` workflow refuses a tag that differs from the `pom.xml` version and deploys the starter to GitHub
Packages. Published versions are immutable; release a new one instead of replacing it.
