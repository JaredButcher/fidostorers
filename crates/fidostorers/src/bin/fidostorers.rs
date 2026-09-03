//! `fidostorers` CLI. See plan/02-crate-fidostorers.md.
//!
//! Every subcommand is wired end to end: all three modes (M2–M4) and multi-key
//! enrollment/revocation (M5). See plan/06-roadmap.md.
//!
//! This binary is where the two halves meet: it asks `fido-token` for an
//! `hmac-secret` output, runs it through `fidostorers::kek_from_secret`, and hands
//! the resulting KEK to `Vault`. The library never talks to hardware itself
//! (plan/02-crate-fidostorers.md), so this orchestration lives here and only here.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use fidostorers::{Enrollment, Mode, Vault};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

const DEFAULT_RP_ID: &str = "fidostorers.local";
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Generic failure.
const EXIT_ERROR: i32 = 1;
/// The vault was decrypted and extracted, but the tree on disk is **incomplete** —
/// typically a symlink that Windows would not let us create. Distinct from both
/// success and a hard error so a script can tell the difference, as plan/07 #8
/// requires.
const EXIT_INCOMPLETE_EXTRACTION: i32 = 20;

#[derive(Parser)]
#[command(
    name = "fidostorers",
    version,
    about = "Encrypt files, directories, and key/value secrets using a FIDO2 security key",
    long_about = "Encrypt files, directories, and key/value secrets using a FIDO2 security key.

A vault is unlocked by touching an enrolled security key -- there is no password and
no recovery path. If every enrolled key is lost, the data is gone permanently. Enroll
a second key with `fidostorers enroll` and keep it somewhere safe.",
    after_help = "\
EXAMPLES:
  # A single encrypted file
  fidostorers init secrets.fido --mode file
  fidostorers lock secrets.fido ./private.txt
  fidostorers unlock secrets.fido ./private.txt

  # A whole directory tree
  fidostorers init backup.fido --mode dir
  fidostorers lock backup.fido ./my-folder
  fidostorers unlock backup.fido ./restored

  # Many named secrets in one vault
  fidostorers init tokens.fido --mode kv
  fidostorers kv set tokens.fido github --stdin < token.txt
  fidostorers kv get tokens.fido github
  fidostorers kv ls tokens.fido

  # Add a backup key, then retire the old one
  fidostorers enroll tokens.fido --label \"backup in safe\"
  fidostorers info tokens.fido
  fidostorers revoke tokens.fido --credential <hex-id>

Every unlocking operation requires a live touch. `info` is the only command that
does not, and its output is therefore unauthenticated."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new vault, enrolled with one security key.
    ///
    /// Requires two touches: one to create a credential on the key, one to derive
    /// this vault's key-encryption key. The vault starts empty; use `lock` or
    /// `kv set` to put something in it.
    Init {
        /// Path for the new vault file. Refuses to overwrite an existing file.
        vault: PathBuf,
        /// What this vault will hold. Fixed for the vault's lifetime.
        #[arg(long, value_name = "file|dir|kv")]
        mode: Mode,
        /// Relying-party identifier bound into the credential. The default is fine
        /// unless you want vaults that deliberately cannot share credentials.
        #[arg(long, default_value = DEFAULT_RP_ID)]
        rp_id: String,
        /// Name for this factor, shown by `fidostorers info`.
        #[arg(long, default_value = "primary")]
        label: String,
        /// What kind of factor to enroll first.
        #[arg(long, value_name = "fido2|keyfile", default_value = "fido2")]
        auth: AuthKind,
        /// Keyfile for a keyfile factor. Required with `--auth keyfile`.
        #[arg(long, value_name = "PATH", required_if_eq("auth", "keyfile"))]
        keyfile: Option<PathBuf>,
        /// Read the password from stdin instead of prompting.
        #[arg(long)]
        password_stdin: bool,
        #[command(flatten)]
        argon2: Argon2Args,
        /// Require PIN or biometric verification, not just a touch.
        #[arg(long)]
        require_uv: bool,
    },
    /// Add another security key that can unlock an existing vault.
    ///
    /// Touch an already-enrolled key first, then the new one. Afterwards either key
    /// opens the vault. Do this before you need it: there is no way to add a key
    /// once every enrolled key is lost.
    Enroll {
        /// The vault to add a key to.
        vault: PathBuf,
        /// Name for the new factor, shown by `fidostorers info` (e.g. "backup in safe").
        #[arg(long, default_value = "backup")]
        label: String,
        /// What kind of factor to add.
        #[arg(long, value_name = "fido2|keyfile", default_value = "fido2")]
        auth: AuthKind,
        /// Keyfile for the new factor. Required with `--auth keyfile`.
        #[arg(long, value_name = "PATH", required_if_eq("auth", "keyfile"))]
        keyfile: Option<PathBuf>,
        /// Read the NEW factor's password from stdin instead of prompting. With
        /// `--unlock-password-stdin`, the unlocking password is read first.
        #[arg(long, requires = "keyfile")]
        password_stdin: bool,
        #[command(flatten)]
        argon2: Argon2Args,
        /// How to unlock the vault first, with a factor already enrolled.
        #[command(flatten)]
        unlock_with: UnlockAuthArgs,
    },
    /// Remove a security key's ability to unlock an existing vault.
    ///
    /// This edits THIS file only. The data key is unchanged, so anyone holding the
    /// revoked key and an older copy of the vault can still read it. If the revoked
    /// key may be in someone else's hands, create a new vault instead.
    Revoke {
        /// The vault to remove a key from.
        vault: PathBuf,
        /// Hex entry id, as shown by `fidostorers info`.
        #[arg(long, value_name = "HEX", conflicts_with = "credential")]
        id: Option<String>,
        /// Hex credential ID. Kept as an alias for `--id`; FIDO2 entries only.
        #[arg(long, value_name = "HEX")]
        credential: Option<String>,
        /// How to unlock the vault first, with a factor that is staying.
        #[command(flatten)]
        auth: UnlockAuthArgs,
    },
    /// Encrypt a file or directory into a vault (mode = file or dir).
    ///
    /// Replaces whatever the vault held before.
    Lock {
        /// The vault to write into.
        vault: PathBuf,
        /// The file (mode = file) or directory (mode = dir) to encrypt.
        input: PathBuf,
        #[command(flatten)]
        auth: AuthArgs,
    },
    /// Decrypt a vault back out to disk (mode = file or dir).
    ///
    /// Exits 20 if the tree was extracted but is incomplete -- see `lock`'s
    /// counterpart notes about Windows symlinks.
    Unlock {
        /// The vault to read.
        vault: PathBuf,
        /// Destination file (mode = file) or directory (mode = dir).
        output: PathBuf,
        #[command(flatten)]
        auth: AuthArgs,
    },
    /// Generate a keyfile for keyfile+password authentication.
    Keyfile {
        #[command(subcommand)]
        command: KeyfileCommands,
    },
    /// Manage individual encrypted key/value entries (mode = kv).
    Kv {
        #[command(subcommand)]
        command: KvCommands,
    },
    /// Show a vault's mode, format version, and enrolled credentials.
    ///
    /// The only command that needs no touch -- and therefore the only one whose
    /// output is unauthenticated, since checking the header's MAC requires the data
    /// key. Do not decide anything security-relevant from it.
    Info {
        /// The vault to describe.
        vault: PathBuf,
    },
}

#[derive(Subcommand)]
enum KeyfileCommands {
    /// Write 32 random bytes to a new file. Refuses to overwrite.
    ///
    /// A random binary keyfile is what you want: nothing will reformat it, and its
    /// 256 bits are what keep your password from being the only thing between an
    /// attacker and the vault.
    New {
        /// Where to write the keyfile. Keep it somewhere the vault is not.
        path: PathBuf,
    },
}

/// Which kind of factor to enroll.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum AuthKind {
    Fido2,
    Keyfile,
}

/// Argon2id cost for a new keyfile factor. Stored per entry, so raising these later
/// does not invalidate factors already enrolled.
#[derive(Args, Clone)]
struct Argon2Args {
    /// Memory cost in KiB.
    #[arg(long = "argon2-memory", value_name = "KIB", default_value_t = fidostorers::keyfile::DEFAULT_M_COST_KIB)]
    memory_kib: u32,
    /// Number of passes.
    #[arg(long = "argon2-time", value_name = "N", default_value_t = fidostorers::keyfile::DEFAULT_T_COST)]
    time: u32,
    /// Degree of parallelism.
    #[arg(long = "argon2-parallelism", value_name = "N", default_value_t = fidostorers::keyfile::DEFAULT_PARALLELISM)]
    parallelism: u32,
}

impl From<&Argon2Args> for fidostorers::KeyfileParams {
    fn from(args: &Argon2Args) -> Self {
        Self {
            m_cost_kib: args.memory_kib,
            t_cost: args.time,
            parallelism: args.parallelism,
        }
    }
}

#[derive(Subcommand)]
enum KvCommands {
    /// Store a value, replacing any existing entry of that name.
    Set {
        vault: PathBuf,
        /// Entry name. Any non-empty string up to 255 bytes.
        name: String,
        #[command(flatten)]
        source: KvValueSource,
        #[command(flatten)]
        auth: AuthArgs,
    },
    /// Write one entry's value to stdout, raw, with no trailing newline.
    Get {
        vault: PathBuf,
        /// Entry name, as shown by `kv ls`.
        name: String,
        #[command(flatten)]
        auth: AuthArgs,
    },
    /// Delete one entry. Errors if there is no such entry.
    Rm {
        vault: PathBuf,
        /// Entry name, as shown by `kv ls`.
        name: String,
        #[command(flatten)]
        auth: AuthArgs,
    },
    /// List entry names, one per line, sorted.
    Ls {
        vault: PathBuf,
        #[command(flatten)]
        auth: AuthArgs,
    },
}

#[derive(Args)]
struct KvValueSource {
    /// The value, given on the command line. Visible in your shell history and to
    /// other processes -- prefer --stdin or --file for anything sensitive.
    #[arg(long, conflicts_with_all = ["stdin", "file"])]
    value: Option<String>,
    /// Read the value from standard input.
    #[arg(long, conflicts_with_all = ["value", "file"])]
    stdin: bool,
    /// Read the value from a file.
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

/// How to authenticate: a security key, or a keyfile plus a password.
///
/// Flattened into every command that unlocks. `--keyfile` is what selects the keyfile
/// factor; without it, a security key is used.
#[derive(Args, Clone)]
struct AuthArgs {
    /// Unlock with a keyfile + password factor instead of a security key. The
    /// password is prompted for.
    #[arg(long, value_name = "PATH")]
    keyfile: Option<PathBuf>,
    /// Read the password from stdin instead of prompting (for scripting). Only
    /// meaningful with --keyfile.
    #[arg(long, requires = "keyfile")]
    password_stdin: bool,
    /// Try only this entry, by id from `fidostorers info`. Without it, every entry of
    /// the chosen kind is tried in turn.
    #[arg(long, value_name = "HEX")]
    id: Option<String>,
    /// Require PIN or biometric verification, not just a touch. Security keys only.
    #[arg(long)]
    require_uv: bool,
}

/// The same choice as [`AuthArgs`], spelled `--unlock-*`.
///
/// `enroll` needs to say two different things about keyfiles: which one unlocks the
/// vault now, and which one the new factor will use. One `--keyfile` cannot mean both,
/// so the unlocking half is prefixed.
#[derive(Args, Clone)]
struct UnlockAuthArgs {
    /// Unlock with a keyfile + password factor instead of a security key.
    #[arg(id = "unlock_keyfile", long = "unlock-keyfile", value_name = "PATH")]
    keyfile: Option<PathBuf>,
    /// Read the unlocking password from stdin instead of prompting.
    #[arg(
        id = "unlock_password_stdin",
        long = "unlock-password-stdin",
        requires = "unlock_keyfile"
    )]
    password_stdin: bool,
    /// Unlock with only this entry, by id from `fidostorers info`.
    #[arg(id = "unlock_id", long = "unlock-id", value_name = "HEX")]
    id: Option<String>,
    /// Require PIN or biometric verification when unlocking with a security key.
    #[arg(id = "unlock_require_uv", long = "unlock-require-uv")]
    require_uv: bool,
}

impl From<UnlockAuthArgs> for AuthArgs {
    fn from(args: UnlockAuthArgs) -> Self {
        AuthArgs {
            keyfile: args.keyfile,
            password_stdin: args.password_stdin,
            id: args.id,
            require_uv: args.require_uv,
        }
    }
}

/// Prompt for a password with no echo, or read one from stdin.
///
/// There is deliberately no `--password` flag: a password in `argv` lands in shell
/// history and is visible to every other process on the machine. Same reasoning as
/// `kv set --value`.
fn read_password(from_stdin: bool, confirm: bool) -> Result<Zeroizing<String>> {
    if from_stdin {
        let mut buffer = String::new();
        std::io::stdin()
            .read_line(&mut buffer)
            .context("reading the password from stdin")?;
        // A trailing newline is an artifact of the pipe, not part of the password.
        while buffer.ends_with('\n') || buffer.ends_with('\r') {
            buffer.pop();
        }
        return Ok(Zeroizing::new(buffer));
    }

    let password =
        Zeroizing::new(rpassword::prompt_password("Password: ").context("reading the password")?);
    if confirm {
        let again = Zeroizing::new(
            rpassword::prompt_password("Password (again): ").context("reading the password")?,
        );
        if *password != *again {
            bail!("the two passwords do not match");
        }
    }
    if password.is_empty() {
        bail!("password must not be empty");
    }
    Ok(password)
}

/// Warn about a keyfile that looks likely to change out from under the user. The
/// keyfile must stay byte-identical forever or the factor stops working, and the
/// usual culprits are files something else edits or normalizes.
fn warn_about_fragile_keyfile(path: &Path) {
    let Ok(metadata) = std::fs::metadata(path) else {
        return;
    };
    if metadata.len() > fidostorers::keyfile::LARGE_KEYFILE_WARN_BYTES {
        eprintln!(
            "warning: {} is large; it is re-read and re-hashed on every unlock.",
            path.display()
        );
    }
    let looks_like_text = std::fs::read(path)
        .ok()
        .is_some_and(|bytes| std::str::from_utf8(&bytes).is_ok());
    if looks_like_text {
        eprintln!(
            "warning: {} looks like a text file. An editor adding a trailing newline, or a\n\
             \x20        Windows/Linux copy translating line endings, would silently make this\n\
             \x20        vault unopenable through this factor. `fidostorers keyfile new` creates\n\
             \x20        a random binary keyfile instead.",
            path.display()
        );
    }
    let ancestors_look_synced = path.ancestors().any(|a| {
        a.file_name().is_some_and(|n| {
            let n = n.to_string_lossy().to_lowercase();
            n == ".git" || n == "dropbox" || n == "onedrive" || n.contains("google drive")
        }) || a.join(".git").is_dir()
    });
    if ancestors_look_synced {
        eprintln!(
            "warning: {} appears to be inside a git repository or a synced folder. Keep the\n\
             \x20        keyfile somewhere the vault file is not - a thief who takes both is\n\
             \x20        left with only your password.",
            path.display()
        );
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

/// Recover the vault's data key, by whichever factor the caller selected.
fn unlock_vault(vault: &Vault, auth: &AuthArgs) -> Result<Zeroizing<[u8; 32]>> {
    let wanted_id = match &auth.id {
        Some(hex) => Some(from_hex(hex).context("--id must be hex")?),
        None => None,
    };

    let candidates: Vec<&fidostorers::FactorEntry> = vault
        .credentials()
        .iter()
        .filter(|entry| {
            let kind_matches = match &entry.factor {
                fidostorers::Factor::Fido2(_) => auth.keyfile.is_none(),
                fidostorers::Factor::Keyfile(_) => auth.keyfile.is_some(),
            };
            let id_matches = match &wanted_id {
                Some(id) => {
                    entry.id == id[..]
                        || entry
                            .factor
                            .credential()
                            .is_some_and(|c| c.credential_id == *id)
                }
                None => true,
            };
            kind_matches && id_matches
        })
        .collect();

    if candidates.is_empty() {
        if auth.keyfile.is_some() {
            bail!("this vault has no keyfile factor enrolled that matches; `fidostorers info` lists them");
        }
        bail!(
            "this vault has no security key enrolled that matches; `fidostorers info` lists them"
        );
    }

    match &auth.keyfile {
        Some(path) => unlock_with_keyfile(vault, &candidates, path, auth.password_stdin),
        None => unlock_with_security_key(vault, &candidates, auth.require_uv),
    }
}

/// Tries each enrolled credential in turn, because we cannot know in advance which of
/// a vault's keys is the one plugged in. A key that does not hold a given credential
/// says so without consuming the operation, so moving on to the next entry is the
/// correct response rather than an error.
fn unlock_with_security_key(
    vault: &Vault,
    candidates: &[&fidostorers::FactorEntry],
    require_uv: bool,
) -> Result<Zeroizing<[u8; 32]>> {
    let mut last_err = None;
    for entry in candidates {
        let Some(credential) = entry.factor.credential() else {
            continue;
        };
        if candidates.len() > 1 {
            eprintln!("trying enrolled key {:?}...", entry.label);
        }
        match derive_kek(credential, &entry.salt, require_uv) {
            Ok(kek) => return Ok(vault.unlock_with(&entry.id, kek)?),
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
        None => bail!("vault has no enrolled security keys"),
    }
}

/// The keyfile is hashed once and reused across candidate entries; each entry still
/// needs its own Argon2 run, since each has its own salt.
fn unlock_with_keyfile(
    vault: &Vault,
    candidates: &[&fidostorers::FactorEntry],
    keyfile: &Path,
    password_stdin: bool,
) -> Result<Zeroizing<[u8; 32]>> {
    let hash = fidostorers::keyfile::hash_keyfile(keyfile)?;
    let password = read_password(password_stdin, false)?;

    let mut last_err = None;
    for entry in candidates {
        let fidostorers::Factor::Keyfile(params) = &entry.factor else {
            continue;
        };
        if candidates.len() > 1 {
            eprintln!("trying {:?}...", entry.label);
        }
        let kek =
            fidostorers::keyfile::derive_kek(&hash, password.as_bytes(), &entry.salt, params)?;
        match vault.unlock_with(&entry.id, kek) {
            Ok(data_key) => return Ok(data_key),
            Err(err @ fidostorers::VaultError::AuthenticationFailed) => {
                last_err = Some(err);
                continue;
            }
            Err(err) => return Err(err.into()),
        }
    }

    // Deliberately cannot say which input was wrong: storing a keyfile fingerprint to
    // tell them apart would let anyone holding the vault file test candidate keyfiles
    // offline without the password. See plan/10-keyfile-password-auth.md.
    match last_err {
        Some(err) => Err(anyhow::Error::from(err)
            .context("the keyfile or the password is wrong (there is no way to tell which)")),
        None => bail!("vault has no enrolled keyfile factors"),
    }
}

/// `lock`/`unlock` handle file and dir vaults; a kv vault is managed entry by entry
/// through the `kv` subcommand instead.
fn wrong_command_for_mode(mode: Mode) -> anyhow::Error {
    anyhow::anyhow!("this is a {mode} vault; use `fidostorers kv` to manage its entries")
}

/// Open a vault and confirm it is a kv vault before asking for a touch — telling
/// someone they used the wrong subcommand should not cost them a key press.
fn open_kv_vault(path: &Path) -> Result<Vault> {
    let vault = Vault::open(path)?;
    if vault.mode() != Mode::Kv {
        bail!(
            "this is a {} vault; `kv` only works on kv vaults (use `lock`/`unlock`)",
            vault.mode()
        );
    }
    Ok(vault)
}

/// Produce an `Enrollment` for whichever factor kind was chosen, doing the touching
/// or the prompting that kind requires. This is the only place the two factor types'
/// setup differs.
fn plural_factors(n: usize) -> String {
    if n == 1 {
        "1 factor".to_string()
    } else {
        format!("{n} factors")
    }
}

fn build_enrollment(
    rp_id: &str,
    label: String,
    kind: AuthKind,
    keyfile: Option<&Path>,
    password_stdin: bool,
    argon2: &Argon2Args,
    require_uv: bool,
) -> Result<Enrollment> {
    // The salt is drawn fresh per enrollment and stored in the header. It is not
    // secret; its job is to separate this vault from any other using the same
    // security key or keyfile (plan/03-vault-format-and-crypto.md).
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);

    match kind {
        AuthKind::Fido2 => {
            let credential = register_credential(rp_id.to_string(), require_uv)?;
            let kek = derive_kek(&credential, &salt, require_uv)?;
            Ok(Enrollment {
                factor: fidostorers::Factor::Fido2(credential),
                rp_id: rp_id.to_string(),
                label,
                salt,
                kek,
            })
        }
        AuthKind::Keyfile => {
            let path = keyfile.expect("clap requires --keyfile with --auth keyfile");
            let params = fidostorers::KeyfileParams::from(argon2);
            let hash = fidostorers::keyfile::hash_keyfile(path)?;
            warn_about_fragile_keyfile(path);

            let password = read_password(password_stdin, !password_stdin)?;
            let kek = fidostorers::keyfile::derive_kek(&hash, password.as_bytes(), &salt, &params)?;
            Ok(Enrollment {
                factor: fidostorers::Factor::Keyfile(params),
                rp_id: rp_id.to_string(),
                label,
                salt,
                kek,
            })
        }
    }
}

fn run() -> Result<i32> {
    match Cli::parse().command {
        Commands::Init {
            vault,
            mode,
            rp_id,
            label,
            auth,
            keyfile,
            password_stdin,
            argon2,
            require_uv,
        } => {
            if vault.exists() {
                bail!("{vault:?} already exists; refusing to overwrite it");
            }
            let enrollment = build_enrollment(
                &rp_id,
                label,
                auth,
                keyfile.as_deref(),
                password_stdin,
                &argon2,
                require_uv,
            )?;
            Vault::create(&vault, mode, &enrollment)?;
            println!("created {mode} vault at {vault:?}");
            match auth {
                AuthKind::Fido2 => println!(
                    "WARNING: this vault can only be opened by that security key. Enroll a \
                     second key you keep somewhere safe, or losing this one destroys the data."
                ),
                AuthKind::Keyfile => println!(
                    "WARNING: this vault can only be opened with that keyfile AND that password. \
                     Losing either destroys the data. Back the keyfile up somewhere the vault is \
                     not, and enroll a second factor with `fidostorers enroll`."
                ),
            }
        }
        Commands::Enroll {
            vault: path,
            label,
            auth,
            keyfile,
            password_stdin,
            argon2,
            unlock_with,
        } => {
            let mut vault = Vault::open(&path)?;

            let unlock_with = AuthArgs::from(unlock_with);
            eprintln!("First, unlock with a factor already enrolled in this vault.");
            let data_key = unlock_vault(&vault, &unlock_with)?;

            eprintln!();
            if auth == AuthKind::Fido2 {
                eprintln!("Now connect the NEW security key to add (unplug the first if they");
                eprintln!("share a port), then touch it. It will be asked for twice.");
            }
            // The rp_id comes from the vault, not the CLI default: a credential made
            // for a different rp_id could never derive a working KEK here.
            let rp_id = vault.rp_id().to_string();
            let enrollment = build_enrollment(
                &rp_id,
                label.clone(),
                auth,
                keyfile.as_deref(),
                password_stdin,
                &argon2,
                unlock_with.require_uv,
            )?;

            vault.enroll(&data_key, &enrollment)?;
            if auth == AuthKind::Keyfile {
                eprintln!();
                eprintln!(
                    "NOTE: a vault is only as strong as its weakest enrolled factor. A password\n\
                     can be guessed offline by anyone holding both this vault and its keyfile,\n\
                     which a security key alone cannot be. Keep the keyfile somewhere the vault\n\
                     is not, and keep it byte-identical - it cannot be regenerated."
                );
            }
            println!(
                "enrolled {label:?}; {path:?} now has {}",
                plural_factors(vault.credentials().len())
            );
        }
        Commands::Revoke {
            vault: path,
            id,
            credential,
            auth,
        } => {
            let hex = match (id, credential) {
                (Some(id), _) => id,
                (None, Some(credential)) => credential,
                (None, None) => bail!("specify which factor to remove with --id (see `info`)"),
            };
            let target = from_hex(&hex).context("--id must be hex")?;
            let mut vault = Vault::open(&path)?;

            let label = vault
                .credentials()
                .iter()
                .find(|entry| {
                    entry.id == target[..]
                        || entry
                            .factor
                            .credential()
                            .is_some_and(|c| c.credential_id == target)
                })
                .map(|entry| entry.label.clone());

            eprintln!("First, unlock with a factor enrolled in this vault.");
            let data_key = unlock_vault(&vault, &AuthArgs::from(auth))?;
            vault.revoke(&data_key, &target)?;

            let label = label.unwrap_or_else(|| "that factor".to_string());
            println!(
                "revoked {label:?}; {path:?} now has {}",
                plural_factors(vault.credentials().len())
            );
            eprintln!();
            eprintln!(
                "WARNING: this removes the key from THIS file only. The data key itself is\n\
                 unchanged, so anyone holding both the revoked key and an older copy of this\n\
                 vault (a backup, a synced folder, git history) can still recover it — and\n\
                 that same data key still decrypts the current contents. If the revoked key\n\
                 may be in someone else's hands, create a new vault and re-seal your data\n\
                 into it rather than relying on this."
            );
        }
        Commands::Lock {
            vault: path,
            input,
            auth,
        } => {
            let mut vault = Vault::open(&path)?;
            match vault.mode() {
                Mode::File => {
                    let data_key = unlock_vault(&vault, &auth)?;
                    vault.seal_file(&data_key, &input)?;
                    println!("locked {input:?} into {path:?}");
                }
                Mode::Dir => {
                    let data_key = unlock_vault(&vault, &auth)?;
                    vault.seal_dir(&data_key, &input)?;
                    println!("locked the tree at {input:?} into {path:?}");
                }
                mode => return Err(wrong_command_for_mode(mode)),
            }
        }
        Commands::Unlock {
            vault: path,
            output,
            auth,
        } => {
            let vault = Vault::open(&path)?;
            match vault.mode() {
                Mode::File => {
                    let data_key = unlock_vault(&vault, &auth)?;
                    vault.open_file(&data_key, &output)?;
                    println!("unlocked {path:?} into {output:?}");
                }
                Mode::Dir => {
                    let data_key = unlock_vault(&vault, &auth)?;
                    let report = vault.open_dir(&data_key, &output)?;
                    println!(
                        "unlocked {path:?} into {output:?} ({} entries)",
                        report.extracted
                    );
                    if report.modes_ignored {
                        eprintln!(
                            "warning: this platform has no Unix mode bits; permissions in \
                             the archive were not applied. They are still stored, and \
                             extracting on Linux restores them."
                        );
                    }
                    if !report.is_complete() {
                        for skipped in &report.skipped {
                            eprintln!(
                                "warning: skipped {}: {}",
                                skipped.path.display(),
                                skipped.reason
                            );
                        }
                        eprintln!(
                            "\n{} of {} entries could not be created, so the extracted tree \
                             is INCOMPLETE.",
                            report.skipped.len(),
                            report.skipped.len() + report.extracted
                        );
                        if cfg!(windows) {
                            eprintln!(
                                "On Windows, creating symlinks needs Developer Mode (Settings > \
                                 Privacy & security > For developers) or an elevated terminal."
                            );
                        }
                        return Ok(EXIT_INCOMPLETE_EXTRACTION);
                    }
                }
                mode => return Err(wrong_command_for_mode(mode)),
            }
        }
        Commands::Keyfile { command } => match command {
            KeyfileCommands::New { path } => {
                fidostorers::keyfile::generate_keyfile(&path)?;
                println!("wrote a 32-byte random keyfile to {path:?}");
                eprintln!();
                eprintln!(
                    "Back this up as carefully as the vault, and store it somewhere the vault\n\
                     is NOT - a thief who takes both is left with only your password. It must\n\
                     stay byte-identical: there is no way to regenerate it."
                );
            }
        },
        Commands::Kv { command } => match command {
            KvCommands::Set {
                vault: path,
                name,
                source,
                auth,
            } => {
                // Read the value before touching the key, so a bad --file path fails
                // immediately instead of after the user has already touched.
                let value = Zeroizing::new(source.resolve()?);
                let mut vault = open_kv_vault(&path)?;
                let data_key = unlock_vault(&vault, &auth)?;
                vault.kv_set(&data_key, &name, &value)?;
                println!("set {name:?} in {path:?}");
            }
            KvCommands::Get {
                vault: path,
                name,
                auth,
            } => {
                let vault = open_kv_vault(&path)?;
                let data_key = unlock_vault(&vault, &auth)?;
                let value = vault.kv_get(&data_key, &name)?;
                // Raw bytes, no trailing newline: values may be binary, and a
                // caller piping this into another process must get exactly what
                // was stored.
                std::io::stdout()
                    .write_all(&value)
                    .context("writing the value to stdout")?;
            }
            KvCommands::Rm {
                vault: path,
                name,
                auth,
            } => {
                let mut vault = open_kv_vault(&path)?;
                let data_key = unlock_vault(&vault, &auth)?;
                vault.kv_rm(&data_key, &name)?;
                println!("removed {name:?} from {path:?}");
            }
            KvCommands::Ls { vault: path, auth } => {
                let vault = open_kv_vault(&path)?;
                let data_key = unlock_vault(&vault, &auth)?;
                for name in vault.kv_ls(&data_key)? {
                    println!("{name}");
                }
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
            println!("enrolled factors:");
            for entry in vault.credentials() {
                println!(
                    "  {}  {:<8} {}",
                    entry.id_hex(),
                    entry.factor.kind(),
                    entry.label
                );
            }
            if vault.credentials().len() == 1 {
                println!();
                println!(
                    "Only one factor can open this vault. If it is lost, the contents are gone"
                );
                println!("for good -- `fidostorers enroll` adds a second one.");
            }
        }
    }
    Ok(0)
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("error: {err:#}");
            if let Some(hint) = hint_for(&err) {
                eprintln!("\nhint: {hint}");
            }
            std::process::exit(EXIT_ERROR);
        }
    }
}

/// Turn a typed error into advice about what to actually do next.
///
/// The error messages themselves say what went wrong; these say what to try. The
/// mapping lives here rather than in the library because it is CLI advice ("re-run
/// with...", "check `fidostorers info`"), not information about the failure.
fn hint_for(err: &anyhow::Error) -> Option<String> {
    if let Some(err) = err.downcast_ref::<fido_token::TokenError>() {
        return Some(token_hint(err));
    }
    if let Some(err) = err.downcast_ref::<fidostorers::VaultError>() {
        return vault_hint(err);
    }
    None
}

fn token_hint(err: &fido_token::TokenError) -> String {
    use fido_token::TokenError::*;
    match err {
        NoDevice => {
            let mut hint = String::from("Plug in your security key and try again.");
            if cfg!(target_os = "linux") {
                hint.push_str(
                    " On Linux, /dev/hidraw* is root-only by default; you may need a udev \
                     rule granting your user access (see the README).",
                );
            }
            hint
        }
        DeviceAccess(_) => "Windows 10 1903 and later reserve direct access to FIDO devices for \
             elevated processes. Re-run this from a terminal started with \
             'Run as Administrator'."
            .to_string(),
        HmacSecretUnsupported => "This tool needs the CTAP2 hmac-secret extension, which U2F-only \
             keys do not have. A YubiKey 5 series, SoloKey, Nitrokey 3, or Token2 will work."
            .to_string(),
        Timeout => {
            "Nothing touched the key in time. Re-run and touch it while it is blinking.".to_string()
        }
        NotAllowed => "The key declined the request, or the PIN was wrong. Try again.".to_string(),
        UnknownCredential => "That key is not enrolled in this vault. Try another key, or run \
             `fidostorers info` to see which credentials are enrolled."
            .to_string(),
        PinRequired(_) => "This key has a PIN set. Run the command from an interactive terminal \
             so the PIN can be prompted for without echoing."
            .to_string(),
        PinBlocked(_) => "Too many incorrect PIN attempts. Unplug and replug the key to reset the \
             attempt counter. If it is fully blocked, only a factory reset clears it -- which \
             destroys every credential on the key, and with them every vault they unlock."
            .to_string(),
        BackendUnavailable => "This binary was built without the `hardware` feature, so it has no \
             way to talk to a security key. Rebuild with default features enabled."
            .to_string(),
        Transport(_) | NotImplemented(_) => {
            "Re-run with RUST_LOG=trace to see the CTAP2 exchange.".to_string()
        }
    }
}

fn vault_hint(err: &fidostorers::VaultError) -> Option<String> {
    use fidostorers::VaultError::*;
    Some(match err {
        NotAVault => {
            "Check the path. This file does not start with a fidostorers header.".to_string()
        }
        FormatVersionMismatch { found, supported } => format!(
            "This vault was written in format v{found} but this build understands v{supported}. \
             Upgrade fidostorers to open it."
        ),
        AuthenticationFailed => "Either the factor supplied is not enrolled in this vault -- a \
             security key that was never enrolled, or the wrong keyfile or password -- or the \
             vault has been modified or corrupted since it was written. If you have a backup \
             copy, compare against it."
            .to_string(),
        UnknownCredential => "Run `fidostorers info` to list the credential IDs enrolled in this \
             vault."
            .to_string(),
        LastCredential => "Enroll another factor first (`fidostorers enroll`), then revoke \
             this one. A vault with no enrolled factors could never be opened again."
            .to_string(),
        AlreadyEnrolled => {
            "That key already unlocks this vault; there is nothing to do.".to_string()
        }
        WrongMode { .. } => "A vault's mode is fixed when it is created. `fidostorers info` shows \
             which mode this one is: use `lock`/`unlock` for file and dir vaults, and \
             `fidostorers kv` for kv vaults."
            .to_string(),
        NoSuchEntry(_) => "Run `fidostorers kv ls` to list the entries in this vault.".to_string(),
        UnsafeArchivePath(_) => "This vault's archive tried to write outside the directory you \
             chose. Nothing was extracted from that entry. Treat the vault as untrustworthy."
            .to_string(),
        NotADirectory(_) => "A dir-mode vault stores a directory tree; point `lock` at a \
             directory, not a file."
            .to_string(),
        RpIdMismatch { .. } => "The new credential was created for a different rp_id, so it could \
             never derive a working key for this vault. Enroll without overriding --rp-id."
            .to_string(),
        TooManyCredentials { .. } | HeaderTooLarge { .. } => {
            "Revoke a key you no longer use before enrolling another.".to_string()
        }
        MalformedHeader(_) | MalformedPayload(_) | MalformedArchive(_) => "The file is truncated \
             or corrupt. Restore it from a backup if you have one."
            .to_string(),
        UnusableKeyfile(_) => "A keyfile must be a regular, non-empty file, and must stay \
             byte-identical forever. `fidostorers keyfile new <path>` generates a suitable one."
            .to_string(),
        InvalidKdfParams(_) => "Argon2 parameters must be within the supported range; see \
             `fidostorers enroll --help`."
            .to_string(),
        WrongFactorKind { .. } => "That entry is a different kind of factor. Use --keyfile for \
             a keyfile factor, or omit it for a security key; `fidostorers info` shows which is \
             which."
            .to_string(),
        InvalidEntryName(_) | NotImplemented(_) | Io(_) | Internal(_) => return None,
    })
}

/// Hex decoding lives in `fido-token`, beside `Credential`, so this binary and
/// `fido-token`'s JSON output cannot drift on how the same value is spelled.
fn from_hex(input: &str) -> Result<Vec<u8>> {
    Ok(fido_token::from_hex(input)?)
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
                label,
                auth,
                keyfile,
                require_uv,
                ..
            } => {
                assert_eq!(vault, PathBuf::from("myvault.fido"));
                assert_eq!(mode, Mode::File);
                assert_eq!(rp_id, DEFAULT_RP_ID);
                assert_eq!(label, "primary");
                assert_eq!(auth, AuthKind::Fido2);
                assert!(keyfile.is_none());
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
            Commands::Revoke {
                vault,
                credential,
                id,
                ..
            } => {
                assert_eq!(vault, PathBuf::from("v.fido"));
                assert_eq!(credential.as_deref(), Some("aabbcc"));
                assert!(id.is_none());
            }
            _ => panic!("expected Revoke"),
        }
    }

    #[test]
    fn parses_enroll_with_a_label() {
        let cli =
            Cli::try_parse_from(["fidostorers", "enroll", "v.fido", "--label", "in the safe"])
                .unwrap();
        match cli.command {
            Commands::Enroll {
                vault, label, auth, ..
            } => {
                assert_eq!(vault, PathBuf::from("v.fido"));
                assert_eq!(label, "in the safe");
                assert_eq!(auth, AuthKind::Fido2);
            }
            _ => panic!("expected Enroll"),
        }
    }

    #[test]
    fn enroll_defaults_its_label() {
        let cli = Cli::try_parse_from(["fidostorers", "enroll", "v.fido"]).unwrap();
        match cli.command {
            Commands::Enroll { label, .. } => assert_eq!(label, "backup"),
            _ => panic!("expected Enroll"),
        }
    }

    #[test]
    fn parses_a_keyfile_init() {
        let cli = Cli::try_parse_from([
            "fidostorers",
            "init",
            "v.fido",
            "--mode",
            "kv",
            "--auth",
            "keyfile",
            "--keyfile",
            "/k/file",
            "--argon2-time",
            "5",
        ])
        .unwrap();
        match cli.command {
            Commands::Init {
                auth,
                keyfile,
                argon2,
                ..
            } => {
                assert_eq!(auth, AuthKind::Keyfile);
                assert_eq!(keyfile, Some(PathBuf::from("/k/file")));
                assert_eq!(argon2.time, 5);
                assert_eq!(argon2.memory_kib, fidostorers::keyfile::DEFAULT_M_COST_KIB);
            }
            _ => panic!("expected Init"),
        }
    }

    #[test]
    fn a_keyfile_factor_requires_a_keyfile() {
        // `--auth keyfile` without `--keyfile` must fail at parse time, not after a
        // password prompt.
        let result = Cli::try_parse_from([
            "fidostorers",
            "init",
            "v.fido",
            "--mode",
            "kv",
            "--auth",
            "keyfile",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn password_stdin_requires_a_keyfile_when_unlocking() {
        assert!(Cli::try_parse_from([
            "fidostorers",
            "unlock",
            "v.fido",
            "out",
            "--password-stdin",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "fidostorers",
            "unlock",
            "v.fido",
            "out",
            "--keyfile",
            "/k",
            "--password-stdin",
        ])
        .is_ok());
    }

    #[test]
    fn revoke_rejects_both_id_and_credential() {
        assert!(Cli::try_parse_from([
            "fidostorers",
            "revoke",
            "v.fido",
            "--id",
            "aa",
            "--credential",
            "bb",
        ])
        .is_err());
    }

    #[test]
    fn parses_keyfile_new() {
        let cli = Cli::try_parse_from(["fidostorers", "keyfile", "new", "/k/file"]).unwrap();
        match cli.command {
            Commands::Keyfile {
                command: KeyfileCommands::New { path },
            } => assert_eq!(path, PathBuf::from("/k/file")),
            _ => panic!("expected Keyfile New"),
        }
    }

    #[test]
    fn hex_round_trip() {
        let bytes = [0u8, 1, 255, 16];
        assert_eq!(from_hex(&fido_token::to_hex(&bytes)).unwrap(), bytes);
    }
}
