# 0004: Accounts, login, bootstrap tokens and device keys

- **Status:** accepted. Invite-based sign-up is pending the oracle (see
  "Open").
- **Date:** 2026-11-23
- **Spec:** §2.2.1, §4.1–§4.7

## Decisions

### Who can create accounts (Joe, 2026-11-23)

**Admins and invitations only. There is no open self-registration.**
`POST /api/auth/register` answers `403 registration_closed`, an extension
code paired with its status. Accounts are created through
`Accounts::create_account`, which the admin API will call (with admin
authentication and an audit log), and by invitation once the protocol for
presenting an invite is settled.

### Passwords (§4.1.4)

- **Hashing:** Argon2id with 64 MiB memory, 3 passes and 4 lanes, and a
  16-byte random salt, stored as a PHC string.
- **Length:** 8 to 1 024 bytes. The upper bound limits how much hashing work
  an attacker can request.
- **Throttling:** hashes run on the blocking pool behind a semaphore, at most
  4 at once (each holds 64 MiB), so a burst queues instead of exhausting
  memory.
- **No timing leak:** an unknown or impossible handle is verified against a
  dummy hash and gets byte-identical `401` bodies, so neither the response
  nor its timing reveals whether an account exists (§4.1.2).
- **Test builds:** `[profile.dev.package.argon2]` builds the hashing crates
  optimized, so tests use the real parameters at a tolerable speed.

### Abuse resistance (§4.1.5)

- **Per source address:** a token bucket of 10 at once, then 20 per minute,
  on login and device-key registration.
- **Choosing the address:** it comes from `CLIENT_IP_HEADER` (first entry)
  when that's configured, otherwise the TCP peer. Set the header only behind
  a proxy that overwrites it; otherwise clients choose their own key.
  - **Check on the first deploy:** what jkbase's proxy sends.
- **Per handle:** 5 free failures, then a lockout of 60 s that doubles per
  further failure, up to 1 h. A success clears it. During a lockout even the
  right password gets `429`, without hashing anything.
  - **Trade-off:** someone can deliberately lock a victim out for up to an
    hour. The spec suggests this behaviour, and it's the usual trade against
    online guessing.
- **Bounded memory:** both trackers are bounded, and they fail closed when
  full.

### Bootstrap tokens (§4.2)

- **Format:** `bt_` + 256 random bits, base64url. A token is valid for 300 s,
  bound to its handle, accepted only by `POST /api/auth/device-keys`, and
  presented as `Authorization: Bearer`.
- **Kept in memory, by SHA-256:** a restart forgets them and the user logs in
  again. Persisting them would add risk for no gain.
- **Consumed only by a successful registration:** a request rejected for a
  bad key, algorithm or name leaves the token usable, as §4.2 requires.
- **Ordering:** registration is serialized. The steps are re-check token,
  insert key, consume token. If consuming fails because the account was
  disabled meanwhile, the inserted key is revoked.

### Device keys (§4.3, §4.7)

- **Ids and payload:** `dk_` + 128 random bits. The public key must decode
  to a valid Ed25519 point. `algorithm` may be omitted, otherwise it must be
  `"Ed25519"`. `device_name` is limited to 200 characters.
- **Cap:** at most 20 active keys per account; one more gets `409 conflict`.
  Registration is serialized, so the cap is exact.
- **Revocation:** one conditional update. The key leaves the keys endpoint
  at once, the in-process key cache is cleared, and a `Revocation` is
  broadcast so the WebSocket layer can close sessions with `4003` (§4.7.1).
- **Keys endpoint:** `GET /.well-known/ofscp/users/{handle}/keys` serves
  `cache_until` = now + 5 min, plus a matching `Cache-Control` header.
  Unknown, invalid or disabled handles get `404`.
- **Local-account endpoints:** list and revoke refuse remote actors and
  provider signatures with `403` (security requirement 1).
- **No relation field in the schema:** keys are stored by `handle`. At the
  pinned commit, rhypedb can't link an object inside `create`, contrary to
  its docs, and linking afterwards would be a second, non-atomic statement.

### Disabling an account

The steps run in this order:
1. Set the status to `disabled`, so logins fail and keys stop verifying.
2. Drop outstanding bootstrap tokens.
3. Revoke every key.
4. Clear the key cache.
5. Broadcast the revocation.

### Key resolution

`ProviderKeys` resolves this provider's actors from the store, through a
60 s positive cache that revocation clears. A `fresh` lookup always reads the
store. Everything else goes to a remote resolver. Until remote resolution
with the §8 outbound rules lands, `NoRemoteKeys` refuses every remote signer.

## Open

**How a client presents an invite at sign-up.** The registration schema
forbids extra fields, so this has gone to the oracle. The proposal: a
discovery field `authentication.registration` (`open` / `invite` /
`closed`), an optional `inviteToken`, and a `403 registration_invite_required`.
Until it's settled, registration stays closed.

## Not here yet

- **Admin API:** admin sign-in and the admin API that calls `create_account`
  and `disable_account` come with the next PR.
- **Password recovery (§4.1.3):** it needs an email channel. It's a SHOULD,
  and it's not planned until there's one.
- **Discovery and CORS:** the discovery document (§3.1) and CORS (§3.4) are a
  separate PR.
