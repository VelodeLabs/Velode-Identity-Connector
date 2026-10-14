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
    <version>0.3.0</version>
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

The application's origin must be HTTPS on one of the organization's application domains, and its backend must
reach the organization address over HTTPS. An application that uses Spring Security permits `/velode-identity/**`.

## Connect

Start the application. Its log shows `Waiting for a Velode Identity administrator to approve this application.
Code: 4F7-A92`, and the organization panel shows the request with the same code. Approve it and choose who may
sign in. The connector notices within ten seconds; nothing is restarted or pasted.

The connector keeps its connection in the application's own storage so every replica shares it: a
`velode_identity_connection` table it creates when the application has a `JdbcTemplate`. Declare a `ConnectionStore`
bean to keep it elsewhere. A custom store must implement atomic `create` and `compareAndSet(expected, updated)`;
a missing or changed expected value returns false. The previous unconditional `save` contract is removed.

Update Identity first, then update all connector replicas together after adapting custom stores. Older connector versions can overwrite newer connection
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

`currentUser` and `verify` ask Identity on every call, so call them once per request. Signing out clears the
application's cookie only; the user's Identity session continues, and signing in again returns without a prompt.

## Your Own Sign-In Page

An application can show email sign-in on its own page, with its own design, instead of linking to Identity's page.
Identity still decides every step; the page only collects what the user types and sends it to the connector, which
is the only thing that talks to Identity. Requires Identity with the `login-flow` protocol.

| Request | Body | Success |
| --- | --- | --- |
| `GET /velode-identity/flow/options` | — | `{"turnstileSiteKey", "turnstileAction"}` when Turnstile is required, else `{}` |
| `POST /velode-identity/flow/start` | `{"email", "turnstileToken"?}` | `{"next":"EMAIL_CODE"}` |
| `POST /velode-identity/flow/resend` | `{"turnstileToken"?}` | `{"next":"EMAIL_CODE"}` |
| `POST /velode-identity/flow/code` | `{"code"}` | `{"next":"TOTP"}` or `{"next":"DONE"}` |
| `POST /velode-identity/flow/totp` | `{"code"}` | `{"next":"DONE"}` |

```js
async function step(name, body) {
  const response = await fetch(`/velode-identity/flow/${name}`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body)
  });
  return response.json(); // {"next": ...} or {"error": ...}
}
await step("start", { email });             // always EMAIL_CODE, so it never reveals whether an account exists
const { next } = await step("code", { code }); // TOTP asks for the authenticator code next; DONE is signed in
```

The flow lives in an `HttpOnly` cookie that page scripts never see; `DONE` sets the same session cookie as the
redirect sign-in, after Identity confirms the session it issued. Requests must be JSON. Failures answer
`{"error": CODE}`: `INVALID_CODE` (wrong, used or expired code: ask again or restart), `TURNSTILE_REJECTED`,
`LOCKED`, `RATE_LIMITED`, `ACCESS_DENIED` (the account may not enter this application), `NO_FLOW` (start first) and
`NOT_CONNECTED` or `IDENTITY_UNAVAILABLE`. With Spring Security, permit `/velode-identity/**` and either exclude
`/velode-identity/flow/**` from CSRF or send the CSRF header with these requests.

When `options` names a site key, render Cloudflare Turnstile with that key and action and send its token with
`start` and `resend`; the application's host must be in the widget's hostnames. Identity applies its limits and
lockouts to the browser's address: behind a proxy, set `server.forward-headers-strategy` so `getRemoteAddr()` is the
browser's. Codes for these sign-ins name the application and have no magic link. OAuth providers still use the
redirect sign-in, and sign-ins on an application's own page are not shared with other applications.
`VelodeIdentity` offers the same steps as `loginOptions`, `startLogin`, `resendLoginCode`, `submitLoginCode` and
`submitAuthenticatorCode` for applications that keep the flow themselves.

## Develop And Release

```powershell
./mvnw.cmd verify
```

To release, set the new version in `pom.xml`, merge it to `master`, then push a matching tag such as `v0.2.0`.
The `Publish` workflow refuses a tag that differs from the `pom.xml` version and deploys the starter to GitHub
Packages. Published versions are immutable; release a new one instead of replacing it.
