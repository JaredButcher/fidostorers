//! `fidostorers` CLI. See plan/02-crate-fidostorers.md.
//!
//! `init`, `lock`, `unlock`, and `info` are wired end to end for file mode (M2).
//! `enroll`/`revoke` (M5), directory mode (M3), and kv mode (M4) still bottom out in
//! `NotImplemented` — see plan/06-roadmap.md.
//!
//! This binary is where the two halves meet: it asks `fido-token` for an
//! `hmac-secret` output, runs it through `fidostorers::kek_from_secret`, and hands
//! the resulting KEK to `Vault`. The library never talks to hardware itself
//! (plan/02-crate-fidostorers.md), so this orchestration lives here and only here.

use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use fidostorers::{Enrollment, Mode, Vault};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

const DEFAULT_RP_ID: &str = "fidostorers.local";
const DEFAULT_TIMEOUT_SECS: u64 = 30;

#[derive(Parser)]
#[command(
    name = "fidostorers",
    version,
    about = "Encrypt files, directories, and key/value secrets using a FIDO2 security key"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new vault, enrolled with one security key.
    Init {
        vault: PathBuf,
        #[arg(long, value_name = "file|dir|kv")]
        mode: Mode,
        #[arg(long, default_value = DEFAULT_RP_ID)]
        rp_id: String,
        #[arg(long)]
        require_uv: bool,
    },
    /// Add another security key that can unlock an existing vault.
    Enroll { vault: PathBuf },
    /// Remove a security key's ability to unlock an existing vault.
    Revoke {
        vault: PathBuf,
        /// Hex-encoded credential ID, as shown by `fidostorers info`.
        #[arg(long)]
        credential: String,
    },
    /// (mode = file | dir) Encrypt `input` into the vault.
    Lock {
        vault: PathBuf,
        input: PathBuf,
        #[arg(long)]
        require_uv: bool,
    },
    /// (mode = file | dir) Decrypt the vault into `output`.
    Unlock {
        vault: PathBuf,
        output: PathBuf,
        #[arg(long)]
        require_uv: bool,
    },
    /// (mode = kv) Manage individual encrypted key/value entries.
    Kv {
        #[command(subcommand)]
        command: KvCommands,
    },
    /// Show a vault's mode, format version, and enrolled credentials. Does not
    /// require touching a security key.
    Info { vault: PathBuf },
}

#[derive(Subcommand)]
enum KvCommands {
    Set {
        vault: PathBuf,
        name: String,
        #[command(flatten)]
        source: KvValueSource,
    },
    Get {
        vault: PathBuf,
        name: String,
    },
    Rm {
        vault: PathBuf,
        name: String,
    },
    Ls {
        vault: PathBuf,
    },
}

#[derive(Args)]
struct KvValueSource {
    #[arg(long, conflicts_with_all = ["stdin", "file"])]
    value: Option<String>,
    #[arg(long, conflicts_with_all = ["value", "file"])]
    stdin: bool,
    #[arg(long, conflicts_with_all = ["value", "stdin"])]
    file: Option<PathBuf>,
}

impl KvValueSource {
    fn resolve(self) -> Result<Vec<u8>> {
        match (self.value, self.stdin, self.file) {
            (Some(v), false, None) => Ok(v.into_bytes()),
            (None, true, None) => {
                let mut buf = Vec::new();
                std::io::stdin()
                    .read_to_end(&mut buf)
                    .context("reading value from stdin")?;
                Ok(buf)
            }
            (None, false, Some(path)) => {
                std::fs::read(&path).with_context(|| format!("reading value file {path:?}"))
            }
            (None, false, None) => {
                bail!("specify exactly one of --value, --stdin, or --file")
            }
            _ => unreachable!("clap's conflicts_with rules out every other combination"),
        }
    }
}

fn register_credential(rp_id: String, require_uv: bool) -> Result<fido_token::Credential> {
    Ok(fido_token::register(&fido_token::RegisterOptions {
        rp_id,
        user_name: "fidostorers".to_string(),
        require_uv,
        timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        pin_provider: fido_token::terminal_pin_provider(),
    })?)
}

/// Derive one credential's KEK: touch the key, get `hmac-secret(credential, salt)`,
/// then HKDF it into a key-encryption key. This is the whole hardware seam.
fn derive_kek(
    credential: &fido_token::Credential,
    salt: &[u8; 32],
    require_uv: bool,
) -> Result<Zeroizing<[u8; 32]>, fido_token::TokenError> {
    let secret = fido_token::derive_secret(
        credential,
        salt,
        &fido_token::DeriveOptions {
            require_uv,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            pin_provider: fido_token::terminal_pin_provider(),
        },
    )?;
    Ok(fidostorers::kek_from_secret(&secret))
}

/// Touch an enrolled key and recover the vault's data key.
///
/// Tries each enrolled credential in turn, because we cannot know in advance which
/// of a vault's keys is the one plugged in. A key that does not hold a given
/// credential says so without consuming the operation, so moving on to the next
/// entry is the correct response rather than an error.
fn unlock_vault(vault: &Vault, require_uv: bool) -> Result<Zeroizing<[u8; 32]>> {
    let entries = vault.credentials();
    let mut last_err = None;

    for entry in entries {
        if entries.len() > 1 {
            eprintln!("trying enrolled key {:?}...", entry.label);
        }
        match derive_kek(&entry.credential, &entry.salt, require_uv) {
            Ok(kek) => return Ok(vault.unlock_with(&entry.credential.credential_id, kek)?),
            Err(fido_token::TokenError::UnknownCredential) => {
                last_err = Some(fido_token::TokenError::UnknownCredential);
                continue;
            }
            Err(err) => return Err(err.into()),
        }
    }

    match last_err {
        Some(err) => Err(anyhow::Error::from(err).context(
            "none of this vault's enrolled keys are connected (or the wrong key was touched)",
        )),
        None => bail!("vault has no enrolled credentials"),
    }
}

/// `lock`/`unlock` only know file mode today. Directory mode is M3 and kv mode M4,
/// so say which milestone rather than a bare "unsupported".
fn not_yet_supported(mode: Mode) -> anyhow::Error {
    let milestone = match mode {
        Mode::Dir => "M3",
        Mode::Kv => "M4",
        Mode::File => unreachable!("file mode is implemented"),
    };
    anyhow::anyhow!(
        "this is a {mode} vault; {mode} mode lands in {milestone}, see plan/06-roadmap.md"
    )
}

fn run() -> Result<()> {
    match Cli::parse().command {
        Commands::Init {
            vault,
            mode,
            rp_id,
            require_uv,
        } => {
            if vault.exists() {
                bail!("{vault:?} already exists; refusing to overwrite it");
            }
            let credential = register_credential(rp_id, require_uv)?;

            // The salt is drawn fresh per enrollment and stored in the header. It is
            // not secret; its job is to separate this vault from any other using the
            // same physical key (plan/03-vault-format-and-crypto.md).
            let mut salt = [0u8; 32];
            OsRng.fill_bytes(&mut salt);
            let kek = derive_kek(&credential, &salt, require_uv)?;

            Vault::create(
                &vault,
                mode,
                &Enrollment {
                    credential,
                    label: "primary".to_string(),
                    salt,
                    kek,
                },
            )?;
            println!("created {mode} vault at {vault:?}");
            println!(
                "WARNING: this vault can only be opened by that security key. Enroll a \
                 second key you keep somewhere safe, or losing this one destroys the data."
            );
        }
        Commands::Enroll { vault } => {
            let _ = Vault::open(&vault)?;
            bail!("enrollment lands in M5, see plan/06-roadmap.md");
        }
        Commands::Revoke { vault, credential } => {
            let credential_id = from_hex(&credential).context("--credential must be hex")?;
            let vault = Vault::open(&vault)?;
            // Revoking rewrites the header, so `header_mac` has to be recomputed under
            // a key derived from the data key (plan/03-vault-format-and-crypto.md).
            // That means unlocking with a surviving credential first; wiring up that
            // touch is M5, same as enrollment.
            let _ = (&vault, &credential_id);
            bail!("revocation lands in M5, see plan/06-roadmap.md");
        }
        Commands::Lock {
            vault: path,
            input,
            require_uv,
        } => {
            let mut vault = Vault::open(&path)?;
            match vault.mode() {
                Mode::File => {
                    let data_key = unlock_vault(&vault, require_uv)?;
                    vault.seal_file(&data_key, &input)?;
                    println!("locked {input:?} into {path:?}");
                }
                mode => return Err(not_yet_supported(mode)),
            }
        }
        Commands::Unlock {
            vault: path,
            output,
            require_uv,
        } => {
            let vault = Vault::open(&path)?;
            match vault.mode() {
                Mode::File => {
                    let data_key = unlock_vault(&vault, require_uv)?;
                    vault.open_file(&data_key, &output)?;
                    println!("unlocked {path:?} into {output:?}");
                }
                mode => return Err(not_yet_supported(mode)),
            }
        }
        Commands::Kv { command } => match command {
            KvCommands::Set {
                vault,
                name,
                source,
            } => {
                let value = source.resolve()?;
                let _ = (Vault::open(&vault)?, name, value);
                bail!("kv support lands in M4, see plan/06-roadmap.md");
            }
            KvCommands::Get { vault, name } => {
                let _ = (Vault::open(&vault)?, name);
                bail!("kv support lands in M4, see plan/06-roadmap.md");
            }
            KvCommands::Rm { vault, name } => {
                let _ = (Vault::open(&vault)?, name);
                bail!("kv support lands in M4, see plan/06-roadmap.md");
            }
            KvCommands::Ls { vault } => {
                let _ = Vault::open(&vault)?;
                bail!("kv support lands in M4, see plan/06-roadmap.md");
            }
        },
        Commands::Info { vault } => {
            let vault = Vault::open(&vault)?;
            // header_mac can only be checked with the data key, which needs a touch.
            // `info` deliberately requires none, so everything below is unverified
            // and must be labelled as such (plan/04-security-and-threat-model.md).
            println!("UNAUTHENTICATED: shown without touching a key, so none of it is");
            println!("verified. Decide nothing security-relevant from this output.");
            println!();
            println!("mode: {}", vault.mode());
            println!("rp id: {}", vault.rp_id());
            println!("format version: {}", vault.format_version());
            println!("enrolled credentials:");
            for entry in vault.credentials() {
                println!(
                    "  {} ({})",
                    entry.label,
                    to_hex(&entry.credential.credential_id)
                );
            }
        }
    }
    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

fn from_hex(input: &str) -> Result<Vec<u8>> {
    if input.len() % 2 != 0 {
        bail!("hex string must have an even number of characters");
    }
    (0..input.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&input[i..i + 2], 16)
                .with_context(|| format!("invalid hex byte at offset {i}"))
        })
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
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
            let err = match Cli::try_parse_from(["fidostorers", flag]) {
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
    fn parses_init_with_defaults() {
        let cli =
            Cli::try_parse_from(["fidostorers", "init", "myvault.fido", "--mode", "file"]).unwrap();
        match cli.command {
            Commands::Init {
                vault,
                mode,
                rp_id,
                require_uv,
            } => {
                assert_eq!(vault, PathBuf::from("myvault.fido"));
                assert_eq!(mode, Mode::File);
                assert_eq!(rp_id, DEFAULT_RP_ID);
                assert!(!require_uv);
            }
            _ => panic!("expected Init"),
        }
    }

    #[test]
    fn rejects_invalid_mode() {
        let result = Cli::try_parse_from(["fidostorers", "init", "v.fido", "--mode", "bogus"]);
        assert!(result.is_err());
    }

    #[test]
    fn parses_kv_set_with_value() {
        let cli =
            Cli::try_parse_from(["fidostorers", "kv", "set", "v.fido", "name", "--value", "x"])
                .unwrap();
        match cli.command {
            Commands::Kv {
                command: KvCommands::Set { name, source, .. },
            } => {
                assert_eq!(name, "name");
                assert_eq!(source.resolve().unwrap(), b"x".to_vec());
            }
            _ => panic!("expected Kv Set"),
        }
    }

    #[test]
    fn kv_set_rejects_conflicting_sources() {
        let result = Cli::try_parse_from([
            "fidostorers",
            "kv",
            "set",
            "v.fido",
            "name",
            "--value",
            "x",
            "--stdin",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn kv_value_source_requires_one_option() {
        let source = KvValueSource {
            value: None,
            stdin: false,
            file: None,
        };
        assert!(source.resolve().is_err());
    }

    #[test]
    fn parses_revoke() {
        let cli =
            Cli::try_parse_from(["fidostorers", "revoke", "v.fido", "--credential", "aabbcc"])
                .unwrap();
        match cli.command {
            Commands::Revoke { vault, credential } => {
                assert_eq!(vault, PathBuf::from("v.fido"));
                assert_eq!(credential, "aabbcc");
            }
            _ => panic!("expected Revoke"),
        }
    }

    #[test]
    fn hex_round_trip() {
        let bytes = [0u8, 1, 255, 16];
        assert_eq!(from_hex(&to_hex(&bytes)).unwrap(), bytes);
    }
}
