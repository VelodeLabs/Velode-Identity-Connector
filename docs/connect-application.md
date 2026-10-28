# Connect An Application

This guide connects a Java 21, Spring Boot 3.5 or 4.x servlet application to Velode Identity.
The application needs a public HTTPS origin and must reach Identity over HTTPS.

## 1. Prepare The Organization

A global administrator opens the organization's panel in Identity, confirms it is active, and adds the app's
domain under **Settings > General > Application domains**. The organization needs working authentication and
a user who can sign in. Global and organization sign-ins are separate.

Open **Connect app** and copy the organization address for step 3.

## 2. Add The Connector

The connector is published to Maven Central. Add it under `<dependencies>` in the application's `pom.xml`:

```xml
<dependency>
    <groupId>com.velode</groupId>
    <artifactId>identity-spring-boot-starter</artifactId>
    <version>0.4.1</version>
</dependency>
```

Releases are signed with the Velode Labs key `0FA0 15BF 1377 5E58 2A58 C41E DC3A 6A2D 31C6 A2F1`, published on
`keyserver.ubuntu.com` and `keys.openpgp.org`. The same versions are also on GitHub Packages, which needs a token
even for public packages; see [installing from GitHub Packages](advanced-usage.md#installing-from-github-packages).

## 3. Configure The Application

Set these in the application's `application.properties`, using the address copied from Identity:

```properties
velode.identity.url=https://identity.example.com/o/ORGANIZATION_ID
velode.identity.app-url=https://app.example.com
```

The app URL is an origin, without a path, on an allowed application domain.
Both addresses must use `https`, because the connection key and users' session tokens travel to them; the
connector refuses to start otherwise. Plain `http` is accepted only for `localhost`, `127.0.0.1` and `[::1]`,
for local development.
Use the application's existing `JdbcTemplate` bean and database: the connector creates
`velode_identity_connection` there, so its account needs permission to create that table.
All replicas must share this storage. For another storage option, see [connection storage](advanced-usage.md#connection-storage).

## 4. Allow The Connector Routes

If the app uses Spring Security, permit `/velode-identity/**` in its existing authorization rules,
before broader matchers:

```java
.requestMatchers("/velode-identity/**", "/me").permitAll()
```

The example also permits `/me`, whose handler below checks the user itself. The connector does not populate
Spring Security's `SecurityContext`. Protect other application routes using the
verified user returned in step 6 and the app's own authorization rules.

## 5. Start And Approve

Start the application. Its log shows a waiting message with a code, such as `4F7-A92`.
In the organization's **Connect app** panel, compare that code and the app's origin, then approve.

Choose **All users of the organization**, or **Only the people I choose** and add the intended users to the app's
access list. The connector notices approval within ten seconds. No restart or manual connection key is needed.

## 6. Sign In And Read The User

Add a sign-in link to the application:

```html
<a href="/velode-identity/login?returnTo=/">Sign in</a>
```

Constructor-inject `com.velode.identity.connector.VelodeIdentity` into a Spring MVC controller.
For example, this handler returns the verified user or `401`:

```java
@GetMapping("/me")
ResponseEntity<VelodeIdentity.IdentityUser> me(HttpServletRequest request) {
    return identity.currentUser(request)
        .map(ResponseEntity::ok)
        .orElseGet(() -> ResponseEntity.status(401).build());
}
```

Here `identity` is the injected connector; use Spring MVC's `GetMapping`, Spring's `ResponseEntity` and
Jakarta's `HttpServletRequest`. Check the user once per request; each call verifies access with Identity.
Use `userId` to own application data and keep roles and permissions in the app.
When Identity cannot be reached, `currentUser` throws `IdentityUnavailableException`; answer `503` so the user can
try again, rather than treating them as signed out.

Test the sign-in link over HTTPS, then request `/me` in the same browser.
The connector handles the callback and keeps the session in an `HttpOnly`, `Secure` cookie.
Link to `/velode-identity/logout` to clear the app's cookie; the Identity session remains signed in.
Sign-out started by another site is refused with `403`, so other sites cannot sign users out.
Before approval, sign-in returns `503`.

For a custom email sign-in page, see [Your own sign-in page](advanced-usage.md#your-own-sign-in-page).
Before going to production, review the [security guide](security.md) and its checklist.
