# 0004: Accounts, login, bootstrap tokens and device keys

- **Status:** accepted.
- **Date:** 2026-11-23
- **Spec:** §2.2.1, §4.1–§4.7; registration modes and account invites from
  lost-conn/ofscp#18 (merged)

## Decisions

### Who can create accounts (Joe, 2026-11-23)

**Admins and invitations only. There is no open self-registration.**

- **Mode:** `REGISTRATION` is `invite` (the default) or `closed`. `open` is
  refused at startup. Discovery will advertise it as
  `authentication.registration` (§3.1) when the discovery document lands.
- **Admins** create accounts directly through `Accounts::create_account`,
  which the admin API calls, with admin authentication and an audit log
  (0005).
- **Invites** (§4.1.1): `Accounts::create_invite` issues `ai_` + 256 random
  bits, valid 7 days by default (at most 30), optionally pinned to a handle,
  shared as `https://{DOMAIN}/register?invite={token}`. Only the token's
  SHA-256 is stored (`RegistrationInvite`), and tokens are never logged. A
  pinned handle must be a valid registration handle and not already taken
  when the invite is issued. Request logs record the path only, never the
  query string.
- **`POST /api/auth/register`** checks, in the spec's order:
  1. Closed mode → `403 registration_closed`, invite or not.
  2. No invite, or one that is unknown, expired, used, or pinned to another
     handle → `403 invite_required`. The body is identical in every case.
  3. Invalid handle or password → `400`. Handle taken → `409`.
  4. Hash, then claim the invite and create the account. Both run under one
     in-process lock: the claim is a `@unique` `InviteClaim` row, and only
     its creator marks the invite used (decision 0012; a conditional update
     on `used == false` alone is not atomic in rhypedb). A claim whose
     account can't be created is released. The invite therefore stays usable after a
     failed registration, and of two registrations with one invite exactly
     one succeeds. After an ambiguous storage error the invite is released
     only if the account is confirmed absent.
  5. `201` with a bootstrap token.
- **Display name:** starts as the handle; the registration request carries
  none.
- **`recoveryEmail`** is accepted and ignored: there's no email channel yet
  (see "Not here yet").
- **Single instance:** the lock assumes one server process, as the replay
  store already does.

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
  on registration, login and device-key registration.
- **Choosing the address:** it comes from the **last** entry of
  `CLIENT_IP_HEADER` (the one the trusted proxy appended) when that's
  configured, otherwise the TCP peer. IPv6 addresses are grouped by /64, so
  one subscriber can't mint fresh keys from its own prefix. `ip:port` forms
  are accepted. If the header is missing, or isn't an address, that's logged
  as an error: a missing header falls back to the TCP peer, and an
  unparsable one is used as the key verbatim, rather than putting every
  client in one bucket. Set the header only when every request passes
  through that proxy.
  - **Check on the first deploy:** what jkbase's proxy sends.
- **Per handle:** a login attempt for a valid handle is admitted only while
  the handle isn't locked. It counts as a failure *before* the password is
  checked, and a success clears the count. So concurrent guesses can't all
  get in ahead of the first recorded failure.
  - **The lock:** the 5th admitted attempt also sets a 60 s lock, which
    applies if that attempt fails. Each later admitted attempt doubles it,
    up to 1 h.
  - **Refusals:** refused attempts never extend a lock. Once a lock lapses,
    exactly one attempt is let through again.
  - **During a lockout:** even the right password gets `429`, without any
    hashing.
  - **Faults don't count:** if the database fails, or hashing is saturated,
    before the password is checked, the attempt is refunded.
  - **Invalid handles aren't tracked:** they can't exist, and tracking them
    would let anyone fill the table.
  - **Trade-off:** anyone can keep an account locked by guessing once per
    lapse, for up to an hour at a time. The spec suggests this behaviour,
    and it's the usual trade against online guessing.
- **Bounded memory:** both trackers are bounded, and they fail closed when
  full.
- **Bounded hashing queue:** a request waits at most 5 s for a hashing slot,
  then gets `503` with `Retry-After`, so a flood can't queue without limit.
- **Body limit:** the three unauthenticated auth endpoints accept at most
  16 KiB (`413` beyond).

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
  A valid handle without an active account (unknown or disabled) gets `200`
  with no keys, the same as Forumall, so this public endpoint can't be used
  to enumerate accounts. An invalid handle gets `404`.
- **Local-account endpoints:** list and revoke refuse remote actors and
  provider signatures with `403` (security requirement 1).
- **No relation field in the schema:** keys are stored by `handle`. At the
  pinned commit, rhypedb can't link an object inside `create`, contrary to
  its docs, and linking afterwards would be a second, non-atomic statement.

### Disabling an account

The steps run in this order:
1. Set the status to `disabled`, so logins fail and keys stop verifying.
2. Drop outstanding bootstrap tokens.
3. Clear the key cache.
4. Broadcast the revocation.
5. Revoke every key.

The status change is what takes effect, so the in-process steps run as soon
as it's stored. Only the bulk revocation can fail afterwards: if it does,
the keys stay marked active but can't verify, and running the disable again
finishes it.

A lookup that read a key just before an invalidation can't put it back in
the cache: every invalidation bumps an epoch, and a lookup caches its result
only if the epoch is unchanged.

If the key store is unreachable, verification answers `503` (retry), not
`401`.

### Key resolution

`ProviderKeys` resolves this provider's actors from the store, through a
60 s positive cache that revocation clears. A `fresh` lookup always reads the
store. Everything else goes to the remote resolver, which fetches keys under
the §8 outbound rules (docs/decisions/0006).

## Not here yet

- **Web sign-up page:** the invite link's `/register` page (served with
  `Referrer-Policy: no-referrer`) is a client concern; it isn't served yet.
- **Password recovery (§4.1.3):** it needs an email channel. It's a SHOULD,
  and it's not planned until there's one.
- **Discovery and CORS:** the discovery document (§3.1) and CORS (§3.4) are a
  separate PR.
