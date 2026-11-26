# 0008: Profiles, privacy settings, presence and membership listing

- **Status:** accepted
- **Date:** 2026-11-26
- **Spec:** §5.1 (UserProfile, UserAccount), §6.1–§6.6 (user privacy
  endpoints), §7.5 (presence), §2.2 (`{userRef}`); schemas
  `user-profile.json`, `user-account.json`, `user-public-profile-response.json`,
  `privacy-settings.json`, `presence.json`, `user-groups-response.json`

## Context

The provider had accounts and device keys, but nothing for peers or
clients to read about a user. §6 defines a shared visibility policy and
four surfaces that use it: the profile, presence, group memberships and
contacts. Groups (§5.3), media (§5.8), contacts (§6.7) and WebSockets
(§7) do not exist here yet, so this work has to stand on its own while
leaving each of those a place to plug in.

## Decisions

### Endpoints

| Route | Who | Answer |
| --- | --- | --- |
| `GET /api/me` | local signer | `UserAccount` (`settings` is `{}`) |
| `PATCH /api/me/profile` | local signer | the updated `UserProfile` |
| `PUT /api/me/presence` | local signer | the caller's own `Presence` |
| `GET`/`PUT /api/me/privacy` | local signer | the full `PrivacySettings` |
| `GET /api/users/{userRef}/profile` | anyone | `UserProfile`, filtered |
| `GET /api/users/{userRef}/presence` | anyone | `Presence`, filtered |
| `GET /api/users/{userRef}/groups` | anyone | `UserGroupsResponse`, filtered |

- **Unsigned reads are an anonymous viewer** (Joe's decision, relayed
  by the OFSCP oracle on 2026-11-26; spec clarification PR to follow). The
  three `/api/users/{userRef}/…` reads accept unsigned requests; an
  anonymous viewer satisfies only `public` and never matches `allowList`
  or `denyList`. Otherwise `public` and `authenticated` would mean the
  same thing. A request that carries signature headers which fail §4.5 is
  still `401`, never downgraded to anonymous. `/api/me/*` needs a
  signature (`401` without one).
- **`/api/me/*` refuses remote signers with `403`** (security
  requirement 1): a remote `bob@b.com` is never the local `bob`.
- **Every unresolvable `{userRef}` gets one `404`**, with the same body:
  a malformed reference, a user on another provider, an unknown handle,
  a non-canonical spelling (`Alice`), or a disabled account. A caller
  cannot tell them apart. `{userRef}` accepts the three §2.2 forms (bare
  handle, `handle@domain`, the object URI), percent-decoded once; the
  actor and URI forms resolve locally only when their authority is ours.

### The visibility policy (§6.1), `src/privacy/`

One function, `Policy::admits(subject, viewer, relationships)`, is the
only place a tier is interpreted. Every surface calls it. The order:

1. **The subject always sees their own data**, even under `nobody` or
   when listed in their own `denyList`.
2. **`denyList` beats everything else.**
3. **`allowList` admits**, whatever the tier.
4. **The tier:** `public` admits any viewer; `authenticated` any *user*;
   `sharedGroups` a user who shares a group with the subject; `contacts`
   a user who is a contact; `nobody` no one.

The lists hold actors, so they match only user viewers. A **provider
signer** (§8.1) satisfies only `public`. Every comparison is on the full
canonical `(handle, domain)` actor.

**A viewer the policy refuses gets `200` with emptiness, never `403`**:

- the profile answers the `UserProfile` of §5.1.1 (id, handle, domain,
  display name, avatar, `updatedAt`, `metadata`) without the profile
  extras, today only `bio`. The `UserProfile` is shown whatever
  `profileVisibility` is: §6.1 and §6.2 apply the setting to "profile
  extras (e.g. bio)", and a peer needs the base to render a message
  author;
- presence answers `{"availability":"offline","metadata":[]}`, the same
  bytes as a user who really is offline (§7.5);
- groups answer `{"groups":[],"metadata":[]}`.

So a viewer cannot tell refusal from absence.

### Settings

- **Defaults** (no row stored), as Forumall's: presence `sharedGroups`,
  profile `public`, membership `authenticated`, empty lists, no metadata.
- **`PUT /api/me/privacy` is a partial update**: an absent field is left
  unchanged, `[]` clears a list, `null` is refused. The first save creates
  the row; a concurrent first save that loses the unique-handle race
  retries as an update, so both changes land (tested).
- **List entries** must be actors. They are canonicalized per §2.2
  (`jane@A.COM` → `jane@a.com`, a default port dropped), duplicates are
  dropped, and each list holds at most 500 entries. An actor that would
  end up on both lists, checked against the stored list the request leaves
  in place, is refused with `400`.

### Profiles

- **`PATCH /api/me/profile`**: absent fields are unchanged. `displayName`
  is trimmed, 1–100 characters, no control characters, and cannot be
  removed. `bio` is at most 2000 characters, line breaks and tabs only;
  `""` removes it. `metadata` replaces the list. `updatedAt` is the time of
  the last change, falling back to the account's creation.
- **Avatars wait for media.** §5.1.1 says an avatar SHOULD be a media URL
  this provider serves (§5.8, `POST /api/media`), and no media exists yet.
  Every avatar URL is refused with `400` and a detail that says why;
  `avatar: null` (remove) is accepted. When media lands, accept URLs of
  media the caller uploaded here, and nothing else: a profile must not
  point other users' clients at arbitrary hosts (security requirement 8).
- **Metadata** (every surface): at most 32 entries, 16 KiB serialized;
  `schema` must be an absolute `https` URI, `version` non-empty, and
  `data` present (it may be `null`).

### Presence (§7.5) without WebSockets

- The stored state is the explicit availability (`online`, `away`,
  `dnd`) and `status` (at most 200 characters, one line). `PUT` is a full
  replace: an absent `status` clears it. `offline` is refused with `400`:
  §7.5 makes it derived, not settable (the schema's allowing it is a bug
  the oracle is fixing).
- The reported availability is the stored one **only while the subject
  has a live connection**, and `offline` otherwise. Liveness is the
  `Liveness` seam; until WebSockets exist its implementation is
  `NoConnections`, so today every user reads `offline` (with their status,
  to permitted viewers). `lastSeen` is stored but nothing sets it until
  connections exist.

### Seams, not stubs

`src/privacy/seams.rs` defines three traits, each with an honest
implementation for a provider that has none of the thing:

| Trait | Used by | Today |
| --- | --- | --- |
| `GroupMemberships` (`share_a_group`, `groups_visible_to`) | the `sharedGroups` tier, `GET …/groups` | `NoGroupsHosted`: no groups exist here, so false / empty |
| `Contacts` (`are_contacts`) | the `contacts` tier | `NoContacts` |
| `Liveness` (`is_connected`) | presence | `NoConnections` |

`AppStateBuilder` takes each (`group_memberships`, `contacts`,
`liveness`), so the groups, contacts and WebSocket work each swap in a
real implementation with one line. `groups_visible_to` owns the
group-side filtering (a private group is listed only to its members), so
the listing never discloses a group the viewer could not read (security
requirement 5). Only groups this provider hosts can be known; a remote
group's membership is never claimed.

**Contacts (§6.7) are a follow-up**: its own endpoints, the federated
accept rule (security requirement 4) and DM consent belong together.

### Storage and migration

- `User` gains `avatar`, `bio`, `profile_metadata` and
  `profile_updated_at`. New types `PrivacySettings` and `Presence` are
  keyed by `handle @unique`. All additive: rhypedb reads an absent field
  as `null`, which means "none" (and `updatedAt` falls back to
  `created_at`), so existing accounts need no data migration.
- Metadata and actor lists are stored as JSON text in `String` fields.
  They are only ever read and written whole with the row and never
  queried into, so a JSON column is the right shape; the server validates
  before writing and treats unparsable stored JSON as a database error.

## Settled with the OFSCP oracle (2026-11-26)

The oracle agreed with every decision above, and Joe decided the three it
could not: unsigned reads are anonymous, `PUT /api/me/privacy` is partial,
and `PUT /api/me/presence` is a full replace (like `presence.set`). It is
fixing `presence-update-request.json`, which wrongly allows `offline`, in
one §6 clarification spec PR; cite it here once open.
