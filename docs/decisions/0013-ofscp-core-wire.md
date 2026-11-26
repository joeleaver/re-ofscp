# 0013: The REST wire types in `ofscp-core::wire`

- **Status:** accepted
- **Date:** 2026-11-26
- **Builds on:** 0011 (the `ofscp-core` crate), 0015 (ids, strict
  identifiers, `jiff`)

## Context

Pull request 2 of the port described in 0015 brings Postrinch's REST wire
types into `ofscp-core`. Three sets of definitions already existed:
`ofscp_core::auth` and `ofscp_core::discovery` (from 0011),
`re_ofscp_types::profile` (decision 0009), and Postrinch's `wire`. Each
type must have one definition, readable by a client and servable by this
provider.

## Decision

- **One module, `ofscp_core::wire`,** holds the REST payloads of the whole
  spec, split by area (auth, guest, discovery, directory, profile, privacy,
  contact, group, membership, my groups, media, message, dm, follow,
  notify, delivery, problem). `ofscp_core::auth` and `ofscp_core::discovery` are now
  re-export paths, and so is `re_ofscp_types::profile`, so existing code
  compiles at its old imports. The names already used in this repository
  won where two definitions met (`DeviceKeyCreated`, `PublicKey`,
  `DiscoveryDocument`, `Authentication`, `ProviderPublicKey`,
  `PrivacyUpdate`, `UserGroups`, `GroupEntry`); Postrinch's semantics won
  where they were more permissive to read (every discovery capability is
  optional, `RegistrationMode` is open).
- **Conventions.**
  - Unknown fields are ignored everywhere (§2.3). The `deny_unknown_fields`
    on the login and registration requests is gone.
  - Enumerations a provider *answers* are open (`open_enum!`: an `Other`
    variant keeps an unknown value). Their equality and hash compare the
    wire string, so a hand-built `Other("private")` equals `Private`
    (`is_known` tells them apart from a truly unknown value).
  - Enumerations only a client *sends*, with values the spec fixes, are
    closed, so a provider refuses a bad value while decoding:
    `SetAvailability` (no `offline`, §7.5) and `Visibility`. Their answers
    use the open `Availability` and `VisibilityPolicy`; `From` converts.
  - Enumerations shared by an object and its create/update requests
    (`Tier`, `JoinPolicy`, `ChannelType`) stay open: a provider must refuse
    an `Other` value itself.
  - Optional fields are skipped when `None`. `metadata` and `attachments`
    read as empty when absent. A present `null` is refused where it means
    nothing, and means "clear" only in a `Patch<T>` field.
  - Identifiers deserialize strictly. No wire field opts into
    `actor::lenient`; `PrivacyUpdate`'s lists stay strings because this
    provider converts them itself (0009, §2.2), with its own bounds and
    messages.
  - Every timestamp is `jiff::Timestamp`. The server keeps unix seconds
    (`time`) and converts in one place, `timefmt::timestamp` and
    `timefmt::parse_timestamp`; rhypedb's RFC 3339 strings decode straight
    into `Timestamp` in the row types.
  - Objects that are signed or extended keep unknown fields verbatim
    (`MetadataObject::extra`, `Delivery::extra`, `PushData::extra`), since
    a JCS signature covers every field.
- **Review findings on Postrinch's crate, fixed in the port.** `Invite`'s
  `Debug` hides its bearer `token` (as passwords and bootstrap tokens
  are). `ProblemDetails` decodes from `{"status": 503}` alone (`type`
  defaults to `about:blank`, `title` is optional, RFC 7807). The
  invite-redeem (`InviteRedeemResponse`) and guest-create
  (`GuestCreateResponse`, with the spec's mixed `key_id` / `groupId`
  casing) answers exist. `Message.content` is optional, so a tombstone
  (§7.1) and a page holding one decode. An extra permission entry that is
  not a list of roles is dropped rather than failing the group or channel.
- **Content, media and membership** (lost-conn/ofscp#24, spec
  `187acb9`).
  - Messages, message creates and DM creates carry `mentions` (strict
    actors); messages and creates carry the article fields `title`,
    `summary` and `cover`.
  - `MessageUpdate` is the spec's partial edit: `content`, `attachments`,
    `tags` and `mentions` replace when present and refuse `null`; the
    article fields are `Patch`es, so `null` removes them. It is not
    refused at decode when empty: `is_empty` and `has_only_article_fields`
    give the provider the two `400` checks of §7.1, since the second needs
    the stored message's type.
  - `Attachment` gains `expiresAt` and a `thumbnail`, typed `Thumbnail`
    (an attachment without a thumbnail of its own); a nested thumbnail is
    refused at decode, as the schema's `not` says.
  - `Group.membership` (`Membership`) is the caller's own, authoritative
    membership. `GroupPointer`, `GroupPointerRequest` and
    `GroupPointersResponse` are the home provider's group list (§5.7, *My
    groups*); a pointer's `group` is a strict `ObjectUri`.
  - `Patch` and the `some` helper moved from `profile` to `common`, now
    that messages use them too.
  - The WebSocket samples of #24 (`groups.updated`, the article
    `message.update`) are WebSocket frames, which `wire` does not hold;
    the roundtrip test skips `ws-*` samples.
- **The `errorCode` registry** (§7.3, lost-conn/ofscp#17) is
  `wire::ErrorCode`, with `REGISTRY` and the fixed `status()` of each
  code. The server writes its problem bodies as `wire::ProblemDetails`,
  and a test keeps its own registry (which adds titles, descriptions and
  extension codes) equal to the core's.
- **Conformance.** `crates/ofscp-core/tests/roundtrip.rs` decodes every
  REST sample of the spec (all but `ws-*` and `call-*`, which are
  WebSocket payloads) and re-encodes it to the same JSON; both `*.invalid`
  samples are refused; and a listing test fails when the spec gains a
  sample no type covers.

## Consequences

- Breaking changes for outside users of `ofscp-core`: the auth and
  discovery types gained typed fields (`Timestamp`, `Actor`, `Authority`,
  `KeyAlgorithm`), and every discovery capability is an `Option`.
- The server's presence store holds a `SetAvailability`, and the profile
  answers name the `domain` as an `Authority`.
- Pull request #18 (groups and channels) defines its own group and channel
  types in `re-ofscp-types`; it should move onto these when it rebases.
