# Advanced Usage

## Connection Storage

The connector keeps its connection in the application's own storage so every replica shares it: a
`velode_identity_connection` table it creates when the application has a `JdbcTemplate`. Declare a `ConnectionStore`
bean to keep it elsewhere. A custom store must implement atomic `create` and `compareAndSet(expected, updated)`;
a missing or changed expected value returns false. The previous unconditional `save` contract is removed.

Update Identity first, then update all connector replicas together after adapting custom stores. Older connector versions can overwrite newer connection
state. The stored format is unchanged.

If an administrator disconnects the application, or its storage is lost, the connector asks to connect again and the
panel shows the request as a reconnection of the same application.

## Installing From GitHub Packages

Every release is also published to GitHub Packages. Add the repository under `<repositories>`:

```xml
<repository>
    <id>github-velode</id>
    <url>https://maven.pkg.github.com/VelodeLabs/Velode-Identity-Connector</url>
</repository>
```

and its credentials under `<servers>` in `~/.m2/settings.xml`, on developer machines and CI:

```xml
<server>
    <id>github-velode</id>
    <username>GITHUB_USERNAME</username>
    <password>${env.GITHUB_PACKAGES_TOKEN}</password>
</server>
```

`GITHUB_PACKAGES_TOKEN` is a GitHub personal access token (classic) with the `read:packages` scope, which GitHub
Packages requires even for public packages. Keep it out of git.

## Configuration

`velode.identity.name` overrides the name suggested to the administrator (default `spring.application.name`) and
`velode.identity.key-rotation` how often the key is replaced (default `30d`).

## Browser Flows

`VelodeIdentity` also offers `loginUrl`, `exchange` and `verify` for applications that manage the browser flow
themselves. `currentUser` and `verify` ask Identity on every call, so call them once per request. Every method that
asks Identity throws `IdentityUnavailableException` when Identity cannot be reached; the connector's own sign-in
addresses answer `503` in that case.

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
redirect sign-in, after Identity confirms the session it issued. Requests must be JSON and come from the page's own
origin: a `POST` whose `Origin` differs from `velode.identity.app-url`, or whose `Sec-Fetch-Site` is not
`same-origin`, answers `403` `{"error":"CROSS_ORIGIN"}`. Serve the page from that origin. Failures answer
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
