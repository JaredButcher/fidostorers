//! Standalone CLI for `fido-token`. Useful on its own for debugging/inspecting
//! keys, and dogfoods the library API. See plan/01-crate-fido-token.md.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use fido_token::{Credential, DeriveOptions, RegisterOptions};

#[derive(Parser)]
#[command(
    name = "fido-token",
    version,
    about = "Talk to FIDO2/U2F security keys"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Enumerate connected authenticators and their capabilities.
    List,
    /// Create a credential and print it as JSON to stdout.
    Register {
        #[arg(long)]
        rp_id: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        require_uv: bool,
        #[arg(long, default_value_t = 30)]
        timeout: u64,
    },
    /// Derive the hmac-secret output for a credential + salt and print it as hex.
    Derive {
        /// Path to a JSON-encoded credential, as printed by `register`.
        #[arg(long)]
        credential: PathBuf,
        /// 32-byte salt, hex-encoded (64 hex characters).
        #[arg(long)]
        salt: String,
        #[arg(long)]
        require_uv: bool,
        #[arg(long, default_value_t = 30)]
        timeout: u64,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Commands::List => {
            let devices = fido_token::list_devices()?;
            for device in devices {
                println!(
                    "{}\t{}\thmac-secret={}\tclientPIN={}",
                    device.path,
                    device.product.as_deref().unwrap_or("(unknown)"),
                    device.supports_hmac_secret,
                    device.supports_client_pin,
                );
            }
        }
        Commands::Register {
            rp_id,
            name,
            require_uv,
            timeout,
        } => {
            let credential = fido_token::register(&RegisterOptions {
                rp_id,
                user_name: name,
                require_uv,
                timeout: Duration::from_secs(timeout),
            })?;
            println!("{}", serde_json::to_string_pretty(&credential)?);
        }
        Commands::Derive {
            credential,
            salt,
            require_uv,
            timeout,
        } => {
            let credential: Credential = {
                let raw = std::fs::read_to_string(&credential)
                    .with_context(|| format!("reading credential file {credential:?}"))?;
                serde_json::from_str(&raw).context("parsing credential JSON")?
            };
            let salt = parse_salt(&salt)?;
            let secret = fido_token::derive_secret(
                &credential,
                &salt,
                &DeriveOptions {
                    require_uv,
                    timeout: Duration::from_secs(timeout),
                },
            )?;
            println!("{}", to_hex(&*secret));
        }
    }
    Ok(())
}

fn parse_salt(input: &str) -> Result<[u8; 32]> {
    let bytes = from_hex(input).context("salt must be 64 hex characters (32 bytes)")?;
    let salt: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("salt must be exactly 32 bytes (64 hex characters)"))?;
    Ok(salt)
}

fn from_hex(input: &str) -> Result<Vec<u8>> {
    if input.len() % 2 != 0 {
        anyhow::bail!("hex string must have an even number of characters");
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
        let cli = Cli::try_parse_from([
            "fido-token",
            "register",
            "--rp-id",
            "fidostorers.local",
            "--name",
            "primary",
        ])
        .unwrap();
        match cli.command {
            Commands::Register {
                rp_id,
                name,
                require_uv,
                timeout,
            } => {
                assert_eq!(rp_id, "fidostorers.local");
                assert_eq!(name, "primary");
                assert!(!require_uv);
                assert_eq!(timeout, 30);
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
    fn missing_required_arg_is_rejected() {
        let result = Cli::try_parse_from(["fido-token", "register", "--rp-id", "x"]);
        assert!(result.is_err());
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
}
