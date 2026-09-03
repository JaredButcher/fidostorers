//! Standalone CLI for `fido-token`. Useful on its own for debugging/inspecting
//! keys, and dogfoods the library API. See plan/01-crate-fido-token.md.
//!
//! Logging is the point of this binary as much as the operations are: every
//! subcommand runs the same code paths the library exposes, with `-v` turning on
//! the full CTAP2 trace from the `authenticator` crate underneath. See
//! docs/M1-MANUAL-TESTING.md.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use fido_token::{
    Credential, DeriveOptions, PinProvider, RegisterOptions, TokenError, DEFAULT_RP_ID,
};
use serde::{Deserialize, Serialize};

/// Exit codes, so scripts (and crate 2's CLI) can distinguish outcomes without
/// parsing messages. See plan/01-crate-fido-token.md.
mod exit {
    pub const USAGE: i32 = 2;
    pub const NO_DEVICE: i32 = 3;
    pub const TIMEOUT: i32 = 4;
    pub const NOT_ALLOWED: i32 = 5;
    pub const UNKNOWN_CREDENTIAL: i32 = 6;
    pub const HMAC_SECRET_UNSUPPORTED: i32 = 7;
    pub const PIN: i32 = 8;
    pub const DEVICE_ACCESS: i32 = 9;
    pub const TRANSPORT: i32 = 10;
    /// A self-test ran to completion but the key failed a property it must hold.
    pub const SELFTEST_FAILED: i32 = 11;
}

#[derive(Parser)]
#[command(
    name = "fido-token",
    version,
    about = "Talk to FIDO2/U2F security keys",
    long_about = "Talk to FIDO2/U2F security keys.\n\n\
                  Set RUST_LOG for fine-grained control (e.g. RUST_LOG=authenticator=trace), \
                  or use -v/-vv for a quick increase in verbosity."
)]
struct Cli {
    #[command(flatten)]
    verbosity: Verbosity,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Args, Clone, Copy)]
struct Verbosity {
    /// Increase logging (-v = debug, -vv = trace, including the full CTAP2
    /// exchange). Overridden by RUST_LOG when that is set.
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Suppress all logging below errors.
    #[arg(short, long, global = true, conflicts_with = "verbose")]
    quiet: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Enumerate connected authenticators and their capabilities.
    List,

    /// Create a credential and print it as JSON to stdout.
    Register {
        /// Relying-party id to register under. Not a real domain; this is local-only.
        #[arg(long, default_value = DEFAULT_RP_ID)]
        rp_id: String,
        /// Label shown on authenticators with a display; not sensitive.
        #[arg(long, default_value = "fidostorers")]
        name: String,
        /// Require PIN/biometric verification, not just a touch.
        #[arg(long)]
        require_uv: bool,
        /// Seconds to wait for the user to touch a key.
        #[arg(long, default_value_t = 30)]
        timeout: u64,
        /// Fail instead of prompting if the authenticator asks for a PIN.
        #[arg(long)]
        no_pin: bool,
    },

    /// Derive the hmac-secret output for a credential + salt and print it as hex.
    Derive {
        /// Path to a JSON-encoded credential, as printed by `register`.
        #[arg(long)]
        credential: PathBuf,
        /// 32-byte salt, hex-encoded (64 hex characters).
        #[arg(long)]
        salt: String,
        /// Require PIN/biometric verification, not just a touch.
        #[arg(long)]
        require_uv: bool,
        /// Seconds to wait for the user to touch a key.
        #[arg(long, default_value_t = 30)]
        timeout: u64,
        /// Fail instead of prompting if the authenticator asks for a PIN.
        #[arg(long)]
        no_pin: bool,
    },

    /// Register a credential, then derive from it repeatedly to prove the
    /// hmac-secret extension works and is deterministic on this machine.
    ///
    /// This is the milestone-1 acceptance check from plan/06-roadmap.md, packaged as
    /// one command so it can be run identically on Linux and Windows. It needs
    /// several touches of the key.
    Selftest {
        /// Relying-party id to register under. Not a real domain; this is local-only.
        #[arg(long, default_value = DEFAULT_RP_ID)]
        rp_id: String,
        /// Require PIN/biometric verification, not just a touch.
        #[arg(long)]
        require_uv: bool,
        /// Seconds to wait for each touch.
        #[arg(long, default_value_t = 30)]
        timeout: u64,
        /// Fail instead of prompting if the authenticator asks for a PIN.
        #[arg(long)]
        no_pin: bool,
        /// Reuse an existing credential instead of registering a new one. Lets the
        /// test confirm that a secret survives a replug or a reboot.
        #[arg(long)]
        credential: Option<PathBuf>,
    },
}

fn main() {
    let cli = Cli::parse();
    init_logging(cli.verbosity);

    match run(cli.command) {
        Ok(()) => {}
        Err(err) => {
            eprintln!("error: {err:#}");
            std::process::exit(exit_code(&err));
        }
    }
}

/// Debug builds default to `debug` level so a developer running the binary gets a
/// usable trace without having to know about RUST_LOG; release builds stay quiet.
/// An explicit RUST_LOG always wins.
fn init_logging(verbosity: Verbosity) {
    let default = if verbosity.quiet {
        "error"
    } else {
        match verbosity.verbose {
            0 if cfg!(debug_assertions) => "debug",
            0 => "warn",
            1 => "debug",
            _ => "trace",
        }
    };

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default))
        .format_timestamp_millis()
        // The default format already prints the target, which shows whether a line
        // came from this crate or from the CTAP stack underneath — most of the value
        // when debugging. Adding the module path too would just repeat it.
        .init();

    log::debug!(
        "fido-token {} on {} ({} build)",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        build_kind()
    );
}

fn run(command: Commands) -> Result<()> {
    match command {
        Commands::List => list(),
        Commands::Register {
            rp_id,
            name,
            require_uv,
            timeout,
            no_pin,
        } => {
            let credential = fido_token::register(&RegisterOptions {
                rp_id,
                user_name: name,
                require_uv,
                timeout: Duration::from_secs(timeout),
                pin_provider: pin_provider(no_pin),
            })?;
            print_credential(&credential)?;
            Ok(())
        }
        Commands::Derive {
            credential,
            salt,
            require_uv,
            timeout,
            no_pin,
        } => {
            let credential = load_credential(&credential)?;
            let salt = parse_salt(&salt)?;
            let secret = fido_token::derive_secret(
                &credential,
                &salt,
                &DeriveOptions {
                    require_uv,
                    timeout: Duration::from_secs(timeout),
                    pin_provider: pin_provider(no_pin),
                },
            )?;
            println!("{}", to_hex(&*secret));
            Ok(())
        }
        Commands::Selftest {
            rp_id,
            require_uv,
            timeout,
            no_pin,
            credential,
        } => selftest(rp_id, require_uv, timeout, no_pin, credential),
    }
}

fn list() -> Result<()> {
    let devices = fido_token::list_devices()?;
    if devices.is_empty() {
        eprintln!("no FIDO authenticators found");
        return Ok(());
    }
    for device in devices {
        println!(
            "{}\t{}\t{}\tvid:pid={}\themac-secret={}\tclientPIN={}",
            device.path,
            device.manufacturer.as_deref().unwrap_or("(unknown)"),
            device.product.as_deref().unwrap_or("(unknown)"),
            match (device.vendor_id, device.product_id) {
                (Some(vid), Some(pid)) => format!("{vid:04x}:{pid:04x}"),
                _ => "(unknown)".to_string(),
            },
            describe_capability(device.supports_hmac_secret),
            describe_capability(device.supports_client_pin),
        );
    }
    // Enumeration is deliberately passive and never opens the device for I/O, so
    // capabilities are not probed. Say so rather than letting "unknown" read as a
    // missing feature.
    eprintln!(
        "\nnote: capabilities are not probed during enumeration (that would require \
         opening the device for I/O, which a non-elevated Windows process cannot do). \
         Run `fido-token selftest` to find out what a key actually supports."
    );
    Ok(())
}

fn describe_capability(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unprobed",
    }
}

fn selftest(
    rp_id: String,
    require_uv: bool,
    timeout: u64,
    no_pin: bool,
    credential_path: Option<PathBuf>,
) -> Result<()> {
    let timeout = Duration::from_secs(timeout);
    let derive_opts = DeriveOptions {
        require_uv,
        timeout,
        pin_provider: pin_provider(no_pin),
    };

    println!("fido-token self-test ({} build)", build_kind());
    println!("platform: {}", std::env::consts::OS);
    println!();

    let devices = fido_token::list_devices().unwrap_or_default();
    println!(
        "step 0/4: enumerate — found {} FIDO device(s)",
        devices.len()
    );
    for device in &devices {
        println!(
            "  {} {}",
            device.path,
            device.product.as_deref().unwrap_or("")
        );
    }
    println!();

    let credential = match credential_path {
        Some(path) => {
            let credential = load_credential(&path)?;
            println!("step 1/4: reusing credential from {}", path.display());
            credential
        }
        None => {
            println!("step 1/4: register — touch your key when it blinks");
            let credential = fido_token::register(&RegisterOptions {
                rp_id: rp_id.clone(),
                user_name: "fido-token-selftest".to_string(),
                require_uv,
                timeout,
                pin_provider: pin_provider(no_pin),
            })?;
            println!(
                "  registered, credential id is {} bytes",
                credential.credential_id.len()
            );
            credential
        }
    };
    println!();

    let salt_a = [0x11u8; 32];
    let salt_b = [0x22u8; 32];

    println!("step 2/4: derive with salt A — touch your key");
    let first = fido_token::derive_secret(&credential, &salt_a, &derive_opts)?;
    println!("  fingerprint {}", fido_token::fingerprint(&*first));
    println!();

    println!("step 3/4: derive with salt A again — touch your key");
    let second = fido_token::derive_secret(&credential, &salt_a, &derive_opts)?;
    println!("  fingerprint {}", fido_token::fingerprint(&*second));
    println!();

    println!("step 4/4: derive with salt B — touch your key");
    let third = fido_token::derive_secret(&credential, &salt_b, &derive_opts)?;
    println!("  fingerprint {}", fido_token::fingerprint(&*third));
    println!();

    // These two properties are what the whole project rests on: same inputs must
    // give the same key, different inputs must not.
    let deterministic = *first == *second;
    let salt_separated = *first != *third;

    println!(
        "determinism  (salt A twice -> same secret):      {}",
        verdict(deterministic)
    );
    println!(
        "salt binding (salt A vs B  -> different secret): {}",
        verdict(salt_separated)
    );
    println!();

    if deterministic && salt_separated {
        println!("PASS — hmac-secret works as required on this platform.");
        println!();
        println!("Save this credential to re-test after a replug or reboot:");
        println!("{}", serde_json::to_string(&credential)?);
        Ok(())
    } else {
        eprintln!(
            "FAIL — this key/platform does not satisfy the assumptions in plan/00-overview.md."
        );
        std::process::exit(exit::SELFTEST_FAILED);
    }
}

/// Debug builds log far more than release builds, so self-test output says which
/// one produced it.
fn build_kind() -> &'static str {
    if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    }
}

fn verdict(ok: bool) -> &'static str {
    if ok {
        "PASS"
    } else {
        "FAIL"
    }
}

/// Build the PIN provider used by every subcommand.
fn pin_provider(no_pin: bool) -> Option<PinProvider> {
    if no_pin {
        log::debug!("--no-pin: PIN prompts disabled");
        return None;
    }
    fido_token::terminal_pin_provider()
}

/// How a credential is written to and read from JSON by this CLI.
///
/// Deliberately separate from [`Credential`], whose serde impl also defines the vault
/// header's on-disk layout (plan/03) and therefore must not move. Serde attributes
/// are per-type rather than per-format, so encoding `credential_id` as hex on the
/// library type would silently change the vault format too. See
/// plan/09-credential-encoding.md and plan/07 #17.
#[derive(Serialize, Deserialize)]
struct CredentialJson {
    rp_id: String,
    /// Lowercase hex, no separators, no `0x` prefix.
    credential_id: CredentialIdJson,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_hint: Option<String>,
}

/// Accepts either spelling on the way in, and only ever writes the hex one.
///
/// The array form is what this CLI emitted before M7. Credential files already exist
/// on disk — docs/M1-MANUAL-TESTING.md has readers saving `cred.json` and reusing it
/// after a replug — and silently breaking them for a cosmetic change would be a poor
/// trade. Delete the `Bytes` variant once no such file is worth keeping.
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum CredentialIdJson {
    Hex(String),
    Bytes(Vec<u8>),
}

impl From<&Credential> for CredentialJson {
    fn from(credential: &Credential) -> Self {
        Self {
            rp_id: credential.rp_id.clone(),
            credential_id: CredentialIdJson::Hex(fido_token::to_hex(&credential.credential_id)),
            device_hint: credential.device_hint.clone(),
        }
    }
}

impl TryFrom<CredentialJson> for Credential {
    type Error = anyhow::Error;

    fn try_from(json: CredentialJson) -> Result<Self> {
        let credential_id = match json.credential_id {
            CredentialIdJson::Hex(text) => {
                fido_token::from_hex(&text).context("credential_id is not valid hex")?
            }
            CredentialIdJson::Bytes(bytes) => bytes,
        };
        if credential_id.is_empty() {
            anyhow::bail!("credential_id must not be empty");
        }
        // Agree with the bound the vault header parser enforces, so a credential this
        // CLI accepts can always be enrolled.
        if credential_id.len() > MAX_CREDENTIAL_ID_LEN {
            anyhow::bail!(
                "credential_id is {} bytes, over the {MAX_CREDENTIAL_ID_LEN}-byte limit",
                credential_id.len()
            );
        }
        Ok(Credential {
            rp_id: json.rp_id,
            credential_id,
            device_hint: json.device_hint,
        })
    }
}

/// Matches `MAX_CREDENTIAL_ID_LEN` in the vault header parser (plan/03).
const MAX_CREDENTIAL_ID_LEN: usize = 1024;

fn print_credential(credential: &Credential) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&CredentialJson::from(credential))?
    );
    Ok(())
}

fn load_credential(path: &PathBuf) -> Result<Credential> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading credential file {}", path.display()))?;
    let json: CredentialJson = serde_json::from_str(&raw).context("parsing credential JSON")?;
    json.try_into()
}

/// Map a failure onto a stable exit code. Anything that isn't a `TokenError`
/// (bad arguments, unreadable files) is ordinary usage failure.
fn exit_code(err: &anyhow::Error) -> i32 {
    let Some(token_error) = err.downcast_ref::<TokenError>() else {
        return exit::USAGE;
    };
    match token_error {
        TokenError::NoDevice => exit::NO_DEVICE,
        TokenError::Timeout => exit::TIMEOUT,
        TokenError::NotAllowed => exit::NOT_ALLOWED,
        TokenError::UnknownCredential => exit::UNKNOWN_CREDENTIAL,
        TokenError::HmacSecretUnsupported => exit::HMAC_SECRET_UNSUPPORTED,
        TokenError::PinRequired(_) | TokenError::PinBlocked(_) => exit::PIN,
        TokenError::DeviceAccess(_) => exit::DEVICE_ACCESS,
        TokenError::Transport(_)
        | TokenError::BackendUnavailable
        | TokenError::NotImplemented(_) => exit::TRANSPORT,
    }
}

fn parse_salt(input: &str) -> Result<[u8; 32]> {
    let bytes = from_hex(input).context("salt must be 64 hex characters (32 bytes)")?;
    let salt: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("salt must be exactly 32 bytes (64 hex characters)"))?;
    Ok(salt)
}

/// Thin wrappers so this binary's errors stay `anyhow`. The encoding itself lives in
/// the library beside `Credential`, so both binaries and the JSON DTO agree.
fn from_hex(input: &str) -> Result<Vec<u8>> {
    Ok(fido_token::from_hex(input)?)
}

fn to_hex(bytes: &[u8]) -> String {
    fido_token::to_hex(bytes)
}

#[cfg(test)]
mod tests {
    use super::{Credential, CredentialJson};

    fn sample() -> Credential {
        Credential {
            rp_id: "fidostorers.local".to_string(),
            credential_id: vec![0xA1, 0xB2, 0xC3, 0xD4, 0x60, 0x16, 0x08, 0x4F],
            device_hint: Some("YubiKey 5 NFC".to_string()),
        }
    }

    #[test]
    fn credential_json_round_trips() {
        let original = sample();
        let text = serde_json::to_string(&CredentialJson::from(&original)).unwrap();
        let parsed: CredentialJson = serde_json::from_str(&text).unwrap();
        assert_eq!(Credential::try_from(parsed).unwrap(), original);
    }

    #[test]
    fn credential_id_is_emitted_as_a_hex_string() {
        // Pinned against a literal so a future serde change cannot quietly alter the
        // format that users' saved credential files depend on.
        let text = serde_json::to_string(&CredentialJson::from(&sample())).unwrap();
        assert!(
            text.contains(r#""credential_id":"a1b2c3d46016084f""#),
            "{text}"
        );
        assert!(
            !text.contains('['),
            "the byte-array form is still being written: {text}"
        );
    }

    #[test]
    fn the_old_byte_array_form_still_loads() {
        // A cred.json saved before M7 must keep working; see plan/09.
        let old = r#"{
            "rp_id": "fidostorers.local",
            "credential_id": [161, 178, 195, 212, 96, 22, 8, 79],
            "device_hint": "YubiKey 5 NFC"
        }"#;
        let parsed: CredentialJson = serde_json::from_str(old).unwrap();
        assert_eq!(Credential::try_from(parsed).unwrap(), sample());
    }

    #[test]
    fn a_missing_device_hint_round_trips_as_absent() {
        let mut credential = sample();
        credential.device_hint = None;
        let text = serde_json::to_string(&CredentialJson::from(&credential)).unwrap();
        assert!(!text.contains("device_hint"), "{text}");
        let parsed: CredentialJson = serde_json::from_str(&text).unwrap();
        assert_eq!(Credential::try_from(parsed).unwrap(), credential);
    }

    #[test]
    fn malformed_credential_ids_are_rejected_with_a_reason() {
        let cases = [
            (r#"{"rp_id":"x","credential_id":"abc"}"#, "even number"),
            (
                r#"{"rp_id":"x","credential_id":"abzz"}"#,
                "invalid hex digit",
            ),
            (r#"{"rp_id":"x","credential_id":""}"#, "found nothing"),
        ];
        for (json, expected) in cases {
            let parsed: CredentialJson = serde_json::from_str(json).unwrap();
            let err = Credential::try_from(parsed).unwrap_err();
            let text = format!("{err:#}");
            assert!(text.contains(expected), "{json} -> {text}");
        }
    }

    #[test]
    fn an_oversized_credential_id_is_rejected() {
        // Agrees with the vault header's own cap, so anything this CLI accepts can
        // actually be enrolled.
        let json = format!(
            r#"{{"rp_id":"x","credential_id":"{}"}}"#,
            "ab".repeat(super::MAX_CREDENTIAL_ID_LEN + 1)
        );
        let parsed: CredentialJson = serde_json::from_str(&json).unwrap();
        assert!(Credential::try_from(parsed).is_err());
    }

    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn version_flags_report_the_crate_version() {
        for flag in ["--version", "-V"] {
            // `unwrap_err` would require `Cli: Debug`; match instead so the
            // production type keeps its current derives.
            let err = match Cli::try_parse_from(["fido-token", flag]) {
                Ok(_) => panic!("{flag} should short-circuit parsing, not produce a command"),
                Err(err) => err,
            };
            assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
            assert!(
                err.to_string().contains(env!("CARGO_PKG_VERSION")),
                "{flag} output {:?} should contain the crate version",
                err.to_string()
            );
        }
    }

    #[test]
    fn parses_list() {
        let cli = Cli::try_parse_from(["fido-token", "list"]).unwrap();
        assert!(matches!(cli.command, Commands::List));
    }

    #[test]
    fn parses_register_with_defaults() {
        let cli = Cli::try_parse_from(["fido-token", "register"]).unwrap();
        match cli.command {
            Commands::Register {
                rp_id,
                name,
                require_uv,
                timeout,
                no_pin,
            } => {
                assert_eq!(rp_id, DEFAULT_RP_ID);
                assert_eq!(name, "fidostorers");
                assert!(!require_uv);
                assert_eq!(timeout, 30);
                assert!(!no_pin);
            }
            _ => panic!("expected Register"),
        }
    }

    #[test]
    fn parses_derive_with_require_uv() {
        let cli = Cli::try_parse_from([
            "fido-token",
            "derive",
            "--credential",
            "cred.json",
            "--salt",
            "00".repeat(32).as_str(),
            "--require-uv",
        ])
        .unwrap();
        match cli.command {
            Commands::Derive {
                credential,
                salt,
                require_uv,
                ..
            } => {
                assert_eq!(credential, PathBuf::from("cred.json"));
                assert_eq!(salt.len(), 64);
                assert!(require_uv);
            }
            _ => panic!("expected Derive"),
        }
    }

    #[test]
    fn derive_requires_a_credential_and_salt() {
        assert!(Cli::try_parse_from(["fido-token", "derive"]).is_err());
        assert!(Cli::try_parse_from(["fido-token", "derive", "--credential", "c.json"]).is_err());
    }

    #[test]
    fn verbosity_flags_are_global_and_countable() {
        let cli = Cli::try_parse_from(["fido-token", "list", "-vv"]).unwrap();
        assert_eq!(cli.verbosity.verbose, 2);
        let cli = Cli::try_parse_from(["fido-token", "-v", "list"]).unwrap();
        assert_eq!(cli.verbosity.verbose, 1);
    }

    #[test]
    fn quiet_and_verbose_are_mutually_exclusive() {
        assert!(Cli::try_parse_from(["fido-token", "list", "-q", "-v"]).is_err());
    }

    #[test]
    fn selftest_can_reuse_a_saved_credential() {
        let cli =
            Cli::try_parse_from(["fido-token", "selftest", "--credential", "cred.json"]).unwrap();
        match cli.command {
            Commands::Selftest { credential, .. } => {
                assert_eq!(credential, Some(PathBuf::from("cred.json")));
            }
            _ => panic!("expected Selftest"),
        }
    }

    #[test]
    fn hex_round_trip() {
        let bytes = [0u8, 1, 255, 16];
        let hex = to_hex(&bytes);
        assert_eq!(from_hex(&hex).unwrap(), bytes);
    }

    #[test]
    fn odd_length_hex_is_rejected() {
        assert!(from_hex("abc").is_err());
    }

    #[test]
    fn salt_must_be_exactly_32_bytes() {
        assert!(parse_salt(&"00".repeat(32)).is_ok());
        assert!(parse_salt(&"00".repeat(31)).is_err());
        assert!(parse_salt(&"00".repeat(33)).is_err());
        assert!(parse_salt("zz".repeat(32).as_str()).is_err());
    }

    #[test]
    fn token_errors_get_distinct_exit_codes() {
        let cases = [
            (TokenError::NoDevice, exit::NO_DEVICE),
            (TokenError::Timeout, exit::TIMEOUT),
            (TokenError::NotAllowed, exit::NOT_ALLOWED),
            (TokenError::UnknownCredential, exit::UNKNOWN_CREDENTIAL),
            (
                TokenError::HmacSecretUnsupported,
                exit::HMAC_SECRET_UNSUPPORTED,
            ),
            (TokenError::PinRequired("x"), exit::PIN),
            (TokenError::DeviceAccess("x".into()), exit::DEVICE_ACCESS),
            (TokenError::Transport("x".into()), exit::TRANSPORT),
        ];
        for (err, expected) in cases {
            assert_eq!(exit_code(&anyhow::Error::from(err)), expected);
        }
    }

    #[test]
    fn non_token_errors_are_usage_failures() {
        let err = anyhow::anyhow!("bad argument");
        assert_eq!(exit_code(&err), exit::USAGE);
    }

    #[test]
    fn capability_display_distinguishes_unprobed_from_absent() {
        assert_eq!(describe_capability(Some(true)), "yes");
        assert_eq!(describe_capability(Some(false)), "no");
        assert_eq!(describe_capability(None), "unprobed");
    }
}
