# 0008: The federation allow/deny policy

- **Status:** accepted
- **Date:** 2026-11-26

## Context

Spec §8 *Authorization* lets a provider refuse to federate with other
providers. lost-conn/ofscp#20 (merged) settled the details this change
builds on:

- §4.5 step 6: when federation policy denies the signer's provider, the
  answer is `403 forbidden`.
- §4.6 "No fetch is allowed": a denied provider's keys are not fetched, and
  the request gets `403` *even if a cached key would match*. (An outbound
  rule refusing the fetch, such as a private address, gets `401`; that is
  decision 0006 and is unchanged.)
- §8: no outbound request of any kind goes to a denied provider.
- §7.1: a WebSocket authenticated as an actor whose provider *becomes*
  denied closes at once with `4001`.

The spec does not say how a policy is expressed. That part is this
provider's design.

## Decision

### Policy shape

- **A mode and two lists.** The mode is `open` (the default), `allowlist`
  or `denylist`. The allowlist and the denylist are both always stored, and
  the mode picks which one is in force: `open` uses neither, `allowlist`
  permits only providers on the allowlist, `denylist` permits everyone
  except providers on the denylist. Switching modes never loses rules, so
  an operator can prepare an allowlist before switching to it.
- **Two rule scopes.**
  - `authority`: one exact canonical provider authority (§2.4: lowercase
    host, default port 443 dropped), e.g. `peer.example:8443`.
  - `domain`: that DNS name and every name under it, on any port, e.g.
    `evil.example` covers `evil.example`, `chat.evil.example` and
    `evil.example:8443`. Domain rules never match IP-literal hosts. Use an
    authority rule for those.
- **Registrable grouping is not used.** The ICANN-only registrable grouping
  in `registrable.rs` (decisions 0006 and 0007) is for rate-limit quotas,
  where the risk is an attacker spreading load over many names. A policy
  rule is an operator's explicit choice, and grouping would widen it
  silently. For example, denying `bad.github.io` must not deny every
  `github.io` site. A rule covers exactly what it names, and a domain rule
  covers its subdomains.
- **Refused rules.**
  - A domain rule that *is* an ICANN public suffix (`com`, `co.uk`) is
    refused, because it would cover everyone under that suffix. A
    private-section suffix (`github.io`) is one operator's namespace and is
    allowed.
  - A single-label or numeric-last-label domain is refused, and so is a
    domain with a port.
  - An authority rule naming this provider is refused, since the policy
    never applies to it (below).
- **Limits.** At most 1000 rules per list. A note is at most 200 bytes.
- **Rule ids** are `fr_` plus 32 hex characters from the SHA-256 of
  `list\nscope\nvalue`. The same rule always has the same id, so the
  schema's `@unique` refuses duplicates even when two admins race.

### Where it applies

- **Never to this provider's own authority.** Local signers are not
  federation. An empty allowlist cuts off every remote provider, but this
  provider's own accounts keep working.
- **Verifier (§4.5).** The check sits at the start of step 6, after the
  replay *check* (step 4) and the digest (step 5), and before any key is
  resolved, cached or fetched. So a replayed request still gets `401` and
  a bad digest still gets `400`. A denied signer gets `403 forbidden`
  without its signature ever being checked, and its nonce is never
  recorded. It applies to actor and provider signers alike. The signer's
  provider is the actor's domain, or the `X-OFSCP-Provider` authority.
- **Remote key resolver.** It decides before consulting its cache, so a
  denied provider is neither fetched nor answered from cache. That gives
  `KeyError::Denied`, which the verifier turns into `403`.
- **Outbound client.** Every request is checked at `target()`, before the
  operator's `OUTBOUND_ALLOW_HOSTS` exemption (denial wins over it), and
  checked again when a reserved request is sent, so a request reserved
  before a denial is not sent after it. This one choke point covers keys,
  discovery and every later outbound feature (webhooks, push, DM
  forwarding).
- **Unsigned public endpoints** (discovery, user keys, health) are still
  answered for anyone. The policy is about whom this provider federates
  with. It is not a network block, which belongs at the edge.

### Until the policy is loaded

At startup the stored policy is read before serving. If rhypedb is
unreachable, a background task retries every 2 s. Until it loads, the
policy is *unknown* and federation fails closed but temporarily:

- remote signers get `503` with `Retry-After: 5`;
- nothing is sent outbound;
- the admin API answers `503` for the policy.

It is never treated as "denied", because a `403` would wrongly tell peers
they are blocked. And it is never treated as "open", because an allowlist
provider would then federate with anyone after every restart.

### Storage and ownership

- `schema.rhype` gains `FederationSetting` (one row, `name = "federation"`:
  `mode`, `updated_by`, `updated_at`) and `FederationRule` (`rule_id`
  `@unique`, `list`, `scope`, `value`, `note`, `created_by`,
  `created_at`). Both types are new, so no migration is needed. With no
  setting row, the mode is `open`.
- The policy in force is an in-memory snapshot behind a `tokio::sync::watch`
  channel (`federation::FederationPolicy`), read lock-free on the hot
  paths. Every change is written to rhypedb first, then installed in
  memory, under one mutex. A failed write changes nothing.
- As with the replay ledger (decision 0001), one process owns the policy.
  A second process writing the same database would not be seen until its
  next restart.

### Admin API and roles

| Route | Role | Audit action |
|---|---|---|
| `GET /api/admin/federation` | read_only | `federation.get` (only refusals are logged) |
| `PUT /api/admin/federation/mode` | **owner** | `federation.mode` (target: the new mode; detail: `was <old>`) |
| `POST /api/admin/federation/rules` | operator | `federation.rule_add` (target: `list scope value`; detail: the note) |
| `DELETE /api/admin/federation/rules/{id}` | operator | `federation.rule_remove` (detail: what was removed) |

Adding or removing a rule is incident response, so operators may do it.
Switching to `allowlist` cuts federation with everyone not listed, so only
an owner may change the mode. The console asks for confirmation and spells
out the effect, including "the allowlist is empty".

Errors: an invalid rule is `400`; a duplicate rule or a full list is `409`;
an unknown id is `404`; a policy not yet loaded is `503`.

### §7.1 WebSocket close `4001`: the seam

This provider has no WebSocket endpoint yet. When it does, the connection
task for a remote actor will call `FederationPolicy::decide` at
authentication. It will then select on
`FederationPolicy::watch().until_denied(actor_domain)` beside its socket,
and close with `4001` when that resolves. `until_denied` resolves at once
if the provider is already denied, or at the first policy change that
denies it. It ignores the unknown state. It never resolves once the policy
is dropped (shutdown). It is tested in `federation::tests`.

## Questions put to the OFSCP oracle

These were asked on 2026-11-26. No answer had arrived when this change
merged. The defaults above are the conservative readings, and this section
gets updated with whatever the oracle answers:

1. Are a denied provider's *unsigned* requests to public endpoints still
   answered? (Default: yes. Signed requests from a denied signer get `403`
   on every route.)
2. Is rule granularity left to the provider? (Default: exact authority, or
   domain plus subdomains, with no registrable grouping.)
3. Does the `403` belong at the start of step 6, after the replay check
   and the digest? (Default: yes. That is the step #20 names, and it keeps
   the nonce unrecorded.)

## Consequences

- A denied provider gets `403` on every signed request, and this provider
  never contacts it, whatever stored state (follows, DMs, cached keys)
  names it.
- An outage of rhypedb at startup delays federation, but not local
  service, until the policy loads.
- Rules cannot express "everything under a registrable domain except one
  name". A denylist entry plus a later allowlist is not a combination this
  design supports. Operators use the mode that fits.
