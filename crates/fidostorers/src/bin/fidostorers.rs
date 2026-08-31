//! `fidostorers` CLI. See plan/02-crate-fidostorers.md.
//!
//! Every subcommand's argument parsing and dispatch plumbing is real; the bodies
//! bottom out in `NotImplemented` errors today because the hardware backend (M1)
//! and vault crypto (M2+) haven't landed yet — see plan/06-roadmap.md. Nothing here
//! should need to change shape once those land, only the stub bodies get replaced.

use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use fidostorers::{Mode, Vault};
use rand::RngCore;

const DEFAULT_RP_ID: &str = "fidostorers.local";
const DEFAULT_TIMEOUT_SECS: u64 = 30;

#[derive(Parser)]
#[command(
    name = "fidostorers",
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
    Lock { vault: PathBuf, input: PathBuf },
    /// (mode = file | dir) Decrypt the vault into `output`.
    Unlock { vault: PathBuf, output: PathBuf },
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
    })?)
}

fn run() -> Result<()> {
    match Cli::parse().command {
        Commands::Init {
            vault,
            mode,
            rp_id,
            require_uv,
        } => {
            let credential = register_credential(rp_id, require_uv)?;

            let mut salt = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut salt);
            let secret = fido_token::derive_secret(
                &credential,
                &salt,
                &fido_token::DeriveOptions {
                    require_uv,
                    timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
                },
            )?;

            Vault::create(&vault, mode, &credential, "primary", secret)?;
            println!("created {mode} vault at {vault:?}");
        }
        Commands::Enroll { vault } => {
            let _ = Vault::open(&vault)?;
            bail!("enrollment lands in M5, see plan/06-roadmap.md");
        }
        Commands::Revoke { vault, credential } => {
            let credential_id = from_hex(&credential).context("--credential must be hex")?;
            let mut vault = Vault::open(&vault)?;
            vault.revoke(&credential_id)?;
        }
        Commands::Lock { vault, input } => {
            let vault = Vault::open(&vault)?;
            let _ = input;
            bail!(
                "locking requires touching an enrolled key to obtain the data key; \
                 wiring that up is M2/M3 (mode = {}), see plan/06-roadmap.md",
                vault.mode()
            );
        }
        Commands::Unlock { vault, output } => {
            let vault = Vault::open(&vault)?;
            let _ = output;
            bail!(
                "unlocking requires touching an enrolled key; wiring that up is M2/M3 \
                 (mode = {}), see plan/06-roadmap.md",
                vault.mode()
            );
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
            println!("mode: {}", vault.mode());
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
