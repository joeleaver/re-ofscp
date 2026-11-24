# 0005: Admin identity, sessions and the admin API

- **Status:** accepted.
- **Date:** 2026-11-23
- **Spec:** none. Admin accounts are this server's own design (CLAUDE.md,
  "Admins have their own sign-ins"). They are not OFSCP actors, are never
  federated, and never sign OFSCP requests.

## Decisions

### Identity

- **Separate type:** admins are `Admin` rows in `schema.rhype`, not a flag on
  `User`. An admin needs no OFSCP account, and an OFSCP signature never
  authenticates an admin request: the admin routes are merged into the router
  *after* the signing layer.
- **Usernames:** `^[a-z0-9][a-z0-9_.-]{2,63}$`. A separate namespace from
  handles.
- **Passwords:** Argon2id through the same `Passwords` hasher as accounts
  (0004): the same parameters, length bounds, semaphore and dummy-hash timing
  defence.
- **Roles:** `owner` > `operator` > `read_only`.
  - `read_only` lists accounts, invites and the audit log.
  - `operator` also creates and disables accounts, and issues and revokes
    invites.
  - `owner` also manages admins (create, change role, disable, reset TOTP).
- **Status:** `active` or `disabled`. **Disabling is final**: a disabled
  admin cannot be re-enabled or have their role changed; create a new admin
  instead. That keeps "this username was disabled" a permanent fact in the
  audit trail.
- **Always an active owner:** the last active owner can be neither demoted
  nor disabled (409).
- **Cap:** at most 200 admins, active or disabled, so the admin list is one
  bounded read (rhypedb has no sort or paging cursor).

### Enabling the admin API

- **`ADMIN_SECRET_KEY`** (32 bytes, base64) seals TOTP secrets. Without it the
  whole admin API answers 404 with a detail saying it is off: there is no
  second factor without the key, and no admin access without a second factor.
- **`ADMIN_SETUP_TOKEN`** (at least 32 characters) is only needed for the
  first-admin bootstrap. Both are jkbase secrets.

### First admin

- `POST /api/admin/setup` with the setup token creates one `owner`, created
  by `"setup"`, and only while **no admin exists at all** (409 afterwards,
  even with the right token). The token is compared through SHA-256 digests
  in constant time. Remove the secret once setup is done.
- The new owner signs in with the password alone and gets a restricted
  session that can only enroll TOTP (below).

### Second factor: TOTP (RFC 6238)

- SHA-1, 6 digits, 30-second steps, one step of skew either way. These are
  the parameters every authenticator app supports.
- **Every sign-in needs a code** once enrolled. Each step is accepted at most
  once: the login does a conditional update `totp_last_step < step`, so even
  concurrent sign-ins can't reuse a code. Reset keeps the last used step, so
  old codes stay dead.
- **Sealed at rest:** secrets are encrypted with XChaCha20-Poly1305 under
  `ADMIN_SECRET_KEY`, with the username as associated data (a sealed secret
  copied to another row doesn't open). Format `v1:` + base64(nonce ‖
  ciphertext).
- **Enrollment:** `totp/enroll` stores a pending secret and returns it with an
  `otpauth://` URI; `totp/confirm` with a valid code promotes it, records the
  step, and ends the admin's other sessions. Wrong codes count toward the
  lockout.
- **Recovery:** an owner resets another admin's TOTP, which ends that admin's
  sessions; they enroll again at their next sign-in. **Owners can't reset
  their own** (otherwise a stolen password plus a live session would be
  enough to replace the factor). A sole owner who loses their authenticator
  needs database intervention, so **run with at least two owners**.
- WebAuthn was considered and deferred: it needs a browser ceremony in the
  admin UI. TOTP works from day one with any client.

### Restricted sessions

A session is restricted while its admin has no TOTP or must change a password
another admin chose. It may only read `session`, enroll and confirm TOTP,
change the password, and log out; everything else is 403 and audited as a
`restricted` denial. New admins are created with `passwordChangeRequired`.

### Sessions

- **Token:** `as_` + 256 random bits; only its SHA-256 is stored
  (`AdminSession`).
- **Cookie:** `__Secure-re-ofscp-admin=…; Path=/api/admin; Max-Age=43200;
  HttpOnly; Secure; SameSite=Strict`. CLAUDE.md suggested scoping it to both
  `/api/admin` and `/admin`, but a cookie has one path, and the `/admin` UI is
  static and needs no credential, so it is scoped to the API alone.
- **Ambiguous cookies:** two different values for the cookie name (a cookie
  planted for a parent domain by a sibling host) are refused with 401 rather
  than guessed between.
- **Lifetime:** at most 12 hours from sign-in, and ended after 30 minutes
  without a request. Activity is recorded at most once a minute. A
  background task purges dead sessions every minute.
- **Ended early** by logout (that session), a password change or TOTP
  confirmation (every *other* session of that admin), and by disabling or a
  TOTP reset (every session of that admin).
- **Credential epoch:** deleting the other sessions alone isn't enough: a
  sign-in that read the admin before the change but stored its session
  after the deletion (its password check takes ~100 ms) would survive,
  and a password-only session would then count as a full one once TOTP is
  enrolled. So `Admin.credential_epoch` is bumped, by a conditional update
  on its old value, whenever TOTP is confirmed or reset or the password
  changes. Each session stores the epoch it was opened under, and a session
  whose epoch differs from its admin's is dead. The session that made the
  change is re-stamped with the new epoch.

### CSRF and origin

- **Token:** base64url(SHA-256(`"re-ofscp admin csrf v1\0"` ‖ session
  token)), returned in the session info and required in `X-CSRF-Token` on
  every mutation. Derived, so nothing more is stored, and the page can't read
  the HttpOnly cookie it comes from.
- **Origin:** on every admin request, an `Origin` header, when present, must
  be `https://{DOMAIN}`, and `Sec-Fetch-Site`, when present, must be
  `same-origin`. This also covers `setup` and `login`, which have no session
  yet.
- A CSRF failure with a valid session is audited as a `csrf` denial naming
  the admin.

### Abuse resistance

- **Per source address:** a token bucket of 5 at once, then 10 per minute, on
  setup and login, keyed the same way as account login (0004:
  `CLIENT_IP_HEADER`, IPv6 by /64).
- **Per username and source:** the same `FailureBackoff` as accounts, keyed
  by (username, source): 5 failures free, then 60 s doubling up to an hour
  (429 with `Retry-After`). Wrong passwords and wrong or reused codes count.
  Keying by source too means nobody can lock an admin out of the console
  from elsewhere, which a per-username lock would allow (five failures
  would lock every owner for as long as the attacker keeps going).
- **Distributed guessing:** an attacker with many addresses gets five
  guesses per address. For an enrolled admin each guess must be the
  password *and* a current code together (one 401 for both), so that's
  hopeless. An admin who hasn't enrolled yet has only a password between an
  attacker and a restricted session (from which they could enroll their
  own TOTP), so those admins also have a lock per username alone: 10
  failures across every source, then 60 s doubling up to an hour. It
  tracks real admins only, so its table never fills; the trade-off is
  that someone can lock a not-yet-enrolled admin out, and so learn that the
  username exists and hasn't enrolled. Enroll promptly.
- **Never fails closed for everyone:** the (username, source) table holds
  10 000 entries and its keys can be invented. When it's full of locked
  keys, a new key is admitted untracked rather than refused, so filling it
  can't lock real admins out; the TOTP code and the per-username lock still
  stand.
- **Inside a session:** wrong codes at TOTP confirmation and wrong current
  passwords at a password change count towards a third per-username lock
  (5 free, then 60 s doubling), which only that session's holder can reach.
- **No enumeration:** an unknown username, a wrong password and a wrong code
  all get the same 401 body, an unknown username still runs a dummy hash,
  and a real admin's failure is audited in the background, so it takes no
  longer to answer.

### Audit log

- **Every admin action** is recorded in `AdminAudit`: time, admin, action,
  target, outcome, source address and a short detail. The routes and their
  action names are in `src/admin/routes/mod.rs`.
- **Fail closed:** a `pending` entry is written before the action and
  finished after it (`ok` or `failed`). If the log can't be written, the
  action is refused with 503; that includes setup, whose entry is written
  before the owner is created. If a sign-in's audit write fails after its
  session was created, the session is deleted and the sign-in fails.
- **Denials are recorded** (role, CSRF, restricted session). Failed and
  locked-out logins are recorded only for usernames that exist, so the log
  can't be flooded with invented names. Those entries are written in the
  background (they record a refusal, not an action), so a failure to write
  one is logged rather than changing the answer.
- **Never secrets:** invite entries record the invite id (its token hash),
  never the token. Passwords, codes and hashes never appear; a database
  error is summarised as "server error" because its text can echo a query.
- **Reads aren't audited.** The log answers "who changed what".
- **Retention:** kept indefinitely. The listing is a time window (default the
  last day, at most 31 days, optionally one admin) and answers 400 past
  5 000 entries, asking for a narrower window.
- Each entry is also emitted as a structured `tracing` event with target
  `audit`, so it reaches the log pipeline even if the database is later lost.

### The admin API over accounts and invites

- **Accounts:** create (`Accounts::create_account`, so the same handle rules
  and reserved `guest_` prefix apply), get, disable, and a substring search
  on handles (`q`, at most 64 bytes), at most 100 results with a `truncated`
  flag. No sorting beyond what we do in memory: rhypedb has no sort.
- **Invites:** create (optionally pinned to a handle, with a TTL), list the
  usable ones, and revoke by id. The token is shown once, at creation, with
  its `/register?invite=` link. **Outstanding invites are capped at 1 000**
  so the list is one bounded read. Revoking expires the invite; revoking a
  used one is 409, an unknown one 404.

### Single instance

The setup, admin-roster and invite-issue locks are in-process, like the
replay store (0001). Running more than one server instance needs them moved
into the database first.

## Not here yet

- **Admin web UI:** `admin-web` still needs the sign-in, enrollment and
  management screens on top of this API.
- **WebAuthn:** see above.
- **Audit export / retention policy:** add when an operator needs one.
