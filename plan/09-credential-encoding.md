# Credential JSON encoding

`fido-token register` prints a credential as JSON for the caller to store. Today
`credential_id` comes out as an array of decimal bytes:

```json
{
  "rp_id": "fidostorers.local",
  "credential_id": [161, 178, 195, 212, 96, 22, 8, 79],
  "device_hint": "YubiKey 5 NFC"
}
```

It should be a hex string:

```json
{
  "rp_id": "fidostorers.local",
  "credential_id": "a1b2c3d46016084f",
  "device_hint": "YubiKey 5 NFC"
}
```

A real credential ID is 32-64 bytes, so the array form runs to several hundred
characters across many lines, cannot be compared by eye, and does not match how the
same value is written everywhere else in the project — `fidostorers info` prints hex,
`fido-token derive --credential` reports hex, and the exit-code table and manual
testing guide all talk in hex.

## The constraint: this type is also the vault format

`fido_token::Credential` is serialized twice:

- to **JSON**, by `fido-token register` and `selftest`, and read back by
  `--credential`;
- by **postcard**, as part of `CredentialEntry` inside every vault header
  ([03-vault-format-and-crypto.md](03-vault-format-and-crypto.md)).

Serde attributes are per-type, not per-format. Putting `serialize_with = "hex"` on the
field would therefore change the on-disk vault layout as well: `credential_id` would
become a length-prefixed *string* of 2n hex characters instead of n raw bytes, which
is both twice the size and a breaking format change requiring `FORMAT_VERSION` 2 and a
migration path for existing vaults.

That is not what this change is for. Settled in
[07-open-decisions.md](07-open-decisions.md) #17: **the hex encoding applies to the
CLI's JSON only, and the vault format does not change.**

## Design

A dedicated JSON representation in the `fido-token` CLI, converted at the boundary:

```rust
/// How a credential is written to and read from JSON by this CLI. Deliberately
/// separate from `fido_token::Credential`, whose serde impl also defines the vault
/// header's on-disk layout (plan/03) and must not move.
#[derive(Serialize, Deserialize)]
struct CredentialJson {
    rp_id: String,
    /// Lowercase hex, no separators, no `0x` prefix.
    credential_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_hint: Option<String>,
}

impl From<&Credential> for CredentialJson { ... }
impl TryFrom<CredentialJson> for Credential { ... }  // hex decode can fail
```

`register` and `selftest` print `CredentialJson`; `load_credential` parses it and
converts. The library type, and therefore the vault header, is untouched.

### Reading the old form

Credential files already exist — the M1 manual testing procedure has readers saving
`cred.json` and reusing it after a replug
([../docs/M1-MANUAL-TESTING.md](../docs/M1-MANUAL-TESTING.md) test 4). Silently
failing on those would be a poor trade for a cosmetic improvement.

`load_credential` therefore accepts **either** form on read — a JSON string is hex, a
JSON array is raw bytes — and always writes the hex form. The array branch is a
compatibility shim: mark it with a comment saying so, and it can be deleted once no
one has an old `cred.json` worth keeping.

### Validation

Hex parsing is the one new failure mode, and it is reached from a user-supplied file,
so it must fail clearly rather than panic:

- odd number of characters -> "credential_id must have an even number of hex digits"
- non-hex character -> name the character and its offset
- empty string -> "credential_id must not be empty"
- absurd length -> reject above the same `MAX_CREDENTIAL_ID_LEN` (1024 bytes) the
  vault header parser already enforces, so the two agree

The existing `from_hex`/`to_hex` helpers in the two binaries do this work already and
are duplicated between them; folding them into a small shared helper in `fido-token`'s
library — where `Credential` lives — removes the duplication and gives one place for
these messages.

## Scope

Small and self-contained. No library API change, no format change, no migration.

- `crates/fido-token/src/bin/fido-token.rs` — `CredentialJson`, conversions, both
  print sites, `load_credential`.
- `crates/fido-token/src/lib.rs` — shared hex encode/decode helpers.
- `crates/fidostorers/src/bin/fidostorers.rs` — use the shared helpers instead of its
  own copies.
- [../docs/M1-MANUAL-TESTING.md](../docs/M1-MANUAL-TESTING.md) — the sample output in
  test 2 and 4 shows the array form and needs updating.

## Testing

- Round trip: `Credential` -> `CredentialJson` -> JSON -> back, byte-identical.
- The emitted JSON contains a hex *string*, asserted against a fixed expected value so
  a future serde change cannot silently alter the format.
- An old array-form document still loads, and produces the same `Credential`.
- Each malformed-hex case above produces its specific error, not a panic.
- **A vault header written before and after this change is byte-identical** — the
  regression that would matter most, and the cheapest to guard against.
