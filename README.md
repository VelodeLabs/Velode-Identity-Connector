# Velode Identity Connector

Spring Boot starter that connects an application's backend to
[Velode Identity](https://github.com/VelodeLabs/Velode-Identity). There are no API keys to create, copy or rotate:
the connector generates and renews its own key, and a global administrator approves the application once in the
organization panel. Identity's
[contracts](https://github.com/VelodeLabs/Velode-Identity/blob/master/docs/contracts.md#application-and-administration-boundaries)
own the protocol; change it there first.

## Install

The starter is published to GitHub Packages. Add the repository and the dependency to the application
(Java 21, Spring Boot 3.5 or 4.x, servlet web):

```xml
<repositories>
    <repository>
        <id>github-velode</id>
        <url>https://maven.pkg.github.com/VelodeLabs/Velode-Identity-Connector</url>
    </repository>
</repositories>

<dependency>
    <groupId>com.velode</groupId>
    <artifactId>identity-spring-boot-starter</artifactId>
    <version>0.1.0</version>
</dependency>
```

GitHub Packages requires authentication to download. Each developer machine and CI declares the server once in
`~/.m2/settings.xml` with a token that has `read:packages` and read access to this repository; keep it out of git.

```xml
<servers>
    <server>
        <id>github-velode</id>
        <username>GITHUB_USERNAME</username>
        <password>${env.GITHUB_PACKAGES_TOKEN}</password>
    </server>
</servers>
```

Set two values, neither of them secret:

```properties
# Copied from "Connect app" in the organization panel.
velode.identity.url=https://iam.velode.io/o/{organizationId}
# Public HTTPS origin of this application.
velode.identity.app-url=https://lista.velode.io
```

`velode.identity.name` overrides the name suggested to the administrator (default `spring.application.name`) and
`velode.identity.key-rotation` how often the key is replaced (default `30d`).

## Connect

Start the application. Its log shows `Waiting for a Velode Identity administrator to approve this application.
Code: 4F7-A92`, and the organization panel shows the request with the same code. Approve it and choose who may
sign in. The connector notices within ten seconds; nothing is restarted or pasted.

The connector keeps its connection in the application's own storage so every replica shares it: a
`velode_identity_connection` table it creates when the application has a `JdbcTemplate`. Declare a `ConnectionStore`
bean to keep it elsewhere. A custom store must implement atomic `create` and `compareAndSet(expected, updated)`;
a missing or changed expected value returns false. The previous unconditional `save` contract is removed.

Update all replicas together after adapting custom stores. Older connector versions can overwrite newer connection
state. The stored format is unchanged.

If an administrator disconnects the application, or its storage is lost, the connector asks to connect again and the
panel shows the request as a reconnection of the same application.

## Use

Link to `/velode-identity/login?returnTo=/some/path` to sign a user in and `/velode-identity/logout` to sign out.
The connector handles the callback and keeps the session token in an `HttpOnly`, `Secure` cookie.

```java
@GetMapping("/me")
ResponseEntity<String> me(HttpServletRequest request) {
    return velodeIdentity.currentUser(request)
        .map(user -> ResponseEntity.ok(user.email()))
        .orElseGet(() -> ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
}
```

`VelodeIdentity` also offers `loginUrl`, `exchange` and `verify` for applications that manage the browser flow
themselves. Identity only says who the user is and that they may enter the application; own the user's data with
`userId` and decide roles and permissions in the application. Until the connection is approved, sign-in answers
`503` and no user is returned.

## Develop And Release

```powershell
./mvnw.cmd verify
```

To release, set the new version in `pom.xml`, merge it to `master`, then push a matching tag such as `v0.2.0`.
The `Publish` workflow refuses a tag that differs from the `pom.xml` version and deploys the starter to GitHub
Packages. Published versions are immutable; release a new one instead of replacing it.
