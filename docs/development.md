# Development And Release

## Verify

```powershell
./mvnw.cmd verify
```

## Release

To release, set the new version in `pom.xml`, merge it to `master`, then push a matching tag such as `v0.2.0`.
The `Publish` workflow refuses a tag that differs from the `pom.xml` version and deploys the starter to GitHub
Packages. Published versions are immutable; release a new one instead of replacing it.
