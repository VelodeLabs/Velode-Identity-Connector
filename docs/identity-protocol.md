# Identity Protocol

The HTTP contract between the connector and Velode Identity. Applications do not call these addresses themselves;
the connector does. It is documented here for reviewers, for alternative clients and to explain what the connector
sends.

## Addresses

The organization address from the Identity panel, `https://identity.example.com/o/{organizationId}`, gives two bases:

| Base | Used by |
| --- | --- |
| `https://identity.example.com/o/{organizationId}` | The browser, for the sign-in page |
| `https://identity.example.com/api/organizations/{organizationId}` | The connector, for every call below |

## Requests And Answers

Every call is a `POST` with a JSON body and `Content-Type: application/json`, authenticated by the connection key:

```http
X-Server-Connection-Key: <connection key>
```

Every call except `/connection` also sends `appSlug`, the identifier Identity assigned when it approved the
application.

A success answers `200` with the result in `data`, or `204` without a body:

```json
{"success": true, "data": {"userId": "5b4084b4-8c5c-47a5-a1e2-9d1654a7338b", "email": "user@example.com"}}
```

A failure answers an error status with a code:

```json
{"status": 401, "error": "INVALID_CONNECTION_KEY", "message": "Invalid server connection key"}
```

`401 INVALID_CONNECTION_KEY` means Identity refused the key itself. The connector then reloads the stored connection,
since another replica may have replaced the key, and asks to be approved again if the key is still refused.

## Connection

| Call | Body | Answer |
| --- | --- | --- |
| `/connection` | `origin`, `name`, `key` | `status`: `PENDING` with an approval `code`, or `CONNECTED` with `appSlug` |
| `/connection/rotate` | `newKey` | `204` once the new key replaces the one in the header |

The connector calls `/connection` with a new key every ten seconds until an administrator approves it, and replaces the
key with `/connection/rotate` when it is due. It stores the replacement before sending it, so a crash after Identity
accepts it does not lose the connection.

## Redirect Sign-In

1. The connector sends the browser to
   `{organization address}/login?appSlug={appSlug}&returnTo={app-url}/velode-identity/callback&state={state}`.
2. Identity signs the user in and returns to the callback with `velode_identity_code` and `velode_identity_state`.
3. The connector checks the state and trades the code:

| Call | Body | Answer |
| --- | --- | --- |
| `/session/exchange` | `code` | `userId`, `email`, `sessionToken`, `expiresAt` (ISO-8601) |
| `/verify` | `token` | `userId`, `email` while the session is valid and the user may enter the application |

## Sign-In On The Application's Own Page

| Call | Body | Answer |
| --- | --- | --- |
| `/login-flow/options` | — | `turnstileSiteKey` and `turnstileAction` when Turnstile is required |
| `/login-flow/start` | `email`, `clientAddress`, `turnstileToken`? | `next: EMAIL_CODE`, `flowId`, `flowSecret` |
| `/login-flow/resend` | `flowId`, `flowSecret`, `clientAddress`, `turnstileToken`? | `next: EMAIL_CODE` |
| `/login-flow/email-code` | `flowId`, `flowSecret`, `code`, `clientAddress` | `next: TOTP`, or `next: DONE` with a session |
| `/login-flow/totp` | `flowId`, `flowSecret`, `code`, `clientAddress` | `next: DONE` with a session |

A session is `userId`, `email`, `sessionToken` and `expiresAt`, as in `/session/exchange`. `start` answers
`EMAIL_CODE` whether or not the address has an account. `clientAddress` is the browser's address, to which Identity
applies its limits. Error codes include `INVALID_CODE`, `TURNSTILE_REJECTED`, `VALIDATION_ERROR`, `ACCESS_DENIED`,
`LOCKED` and `RATE_LIMITED`.

Before handing a `DONE` session to the application, the connector calls `/verify` with its token and accepts it only
when Identity names the same user.
