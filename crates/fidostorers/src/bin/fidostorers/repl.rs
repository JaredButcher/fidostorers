//! `fidostorers interactive` — a long-lived session (plan/08-interactive-mode.md).
//!
//! The session caches each open vault's **data key** so a user touches their
//! security key once per vault rather than once per command. That is a deliberate
//! reversal of this project's "every unlocking operation requires a live touch"
//! default, and the cost is stated at startup rather than buried in a document.
//!
//! The state machine lives in `fidostorers::session`, which never talks to
//! hardware and is unit-tested without a key. This module is the part that cannot
//! be: the terminal, the signals, and the orchestration that turns a typed line
//! into a `Vault` call.
//!
//! Opening a `file` or `dir` store extracts it to a plaintext **working
//! directory** so ordinary tools work on it, and closing seals it back. That is the
//! part of this design that puts unencrypted user data in the filesystem; where it
//! goes and what removing it does and does not guarantee are in
//! [`fidostorers::workdir`]. A `kv` store needs no such thing and stays
//! memory-only.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use fidostorers::session::{ClosedStore, Session, SystemClock};
use fidostorers::{orphan, workdir, Mode, Vault, VaultLock};
use rustyline::error::ReadlineError;
use rustyline::{Config, DefaultEditor, ExternalPrinter};

use crate::{
    build_enrollment, print_vault_info, unlock_vault, Argon2Args, AuthArgs, AuthKind, Interrupt,
    KvValueSource,
};

/// Where a session keeps its state: the runtime root shared by every session on
/// this machine, and this session's own directory for working trees.
struct Paths {
    root: PathBuf,
    work_base: PathBuf,
}

/// How often the idle watchdog looks at the session. Short enough that `exit`
/// does not visibly wait on it, long enough to cost nothing.
const WATCHDOG_TICK: Duration = Duration::from_millis(250);

/// How often the watchdog re-scans working directories for edits made outside the
/// REPL. Far less often than it checks the clock: the scan walks every open tree,
/// and five-second granularity is irrelevant against a fifteen-minute timeout.
const SCAN_EVERY: u32 = 20;

/// One line typed at the prompt.
///
/// No `Debug`, deliberately: [`KvValueSource`] carries `--value`, and a derived
/// `Debug` would be a way to print a secret. The one-shot [`crate::Cli`] omits it
/// for the same reason.
///
/// A REPL-shaped surface rather than the one-shot [`crate::Commands`], because the
/// two genuinely differ: commands here name an **open store** instead of a path,
/// and they carry no unlocking flags at all — the store is already unlocked, which
/// is the entire point of a session. What *is* shared is every argument group whose
/// meaning is unchanged ([`AuthArgs`], [`Argon2Args`], [`KvValueSource`],
/// [`AuthKind`], [`Mode`]), so the two spellings cannot drift on what a flag means.
#[derive(Parser)]
#[command(
    name = "",
    no_binary_name = true,
    disable_version_flag = true,
    subcommand_required = true,
    help_template = "{all-args}"
)]
struct ReplLine {
    #[command(subcommand)]
    command: ReplCommand,
}

#[derive(Subcommand)]
enum ReplCommand {
    /// Unlock a vault and keep its key for the rest of the session.
    Open {
        /// Path to the vault file.
        vault: PathBuf,
        /// Name this store, instead of taking the alias from the file name.
        #[arg(long = "as", value_name = "ALIAS")]
        alias: Option<String>,
        /// Take the vault even though another process holds its lock. Only when you
        /// know that process is gone.
        #[arg(long)]
        force: bool,
        /// Extract a file or dir store here instead of the private runtime
        /// directory. Must not already contain anything. Keep it off cloud sync and
        /// out of git: whatever lands here is plaintext.
        #[arg(long, value_name = "PATH")]
        work_dir: Option<PathBuf>,
        #[command(flatten)]
        auth: AuthArgs,
    },
    /// Drop a store's key and release its lock. `all` closes everything.
    Close {
        /// Store alias, vault path, or `all`.
        target: String,
    },
    /// List open stores, their modes, and how long each has been idle.
    Stores,
    /// Show a store's mode, format version, and enrolled factors.
    Info {
        /// Store alias or vault path. Defaults to the only open store.
        store: Option<String>,
    },
    /// Write any pending changes without closing.
    Seal {
        /// Store alias, vault path, or `all`.
        target: String,
    },
    /// Manage entries in an open kv store.
    Kv {
        #[command(subcommand)]
        command: ReplKvCommand,
    },
    /// Create a new vault and open it in this session.
    Init {
        /// Path for the new vault file.
        vault: PathBuf,
        /// What this vault will hold. Fixed for its lifetime.
        #[arg(long, value_name = "file|dir|kv")]
        mode: Mode,
        /// Relying-party identifier bound into the credential.
        #[arg(long, default_value = crate::DEFAULT_RP_ID)]
        rp_id: String,
        /// Name for this factor, shown by `info`.
        #[arg(long, default_value = "primary")]
        label: String,
        /// What kind of factor to enroll first.
        #[arg(long, value_name = "fido2|keyfile", default_value = "fido2")]
        auth: AuthKind,
        /// Keyfile for a keyfile factor. Required with `--auth keyfile`.
        #[arg(long, value_name = "PATH", required_if_eq("auth", "keyfile"))]
        keyfile: Option<PathBuf>,
        #[command(flatten)]
        argon2: Argon2Args,
        /// Require PIN or biometric verification, not just a touch.
        #[arg(long)]
        require_uv: bool,
    },
    /// Add another factor to an open store. No unlocking flags: it is already open.
    Enroll {
        /// Store alias or vault path.
        store: String,
        /// Name for the new factor (e.g. "backup in safe").
        #[arg(long, default_value = "backup")]
        label: String,
        /// What kind of factor to add.
        #[arg(long, value_name = "fido2|keyfile", default_value = "fido2")]
        auth: AuthKind,
        /// Keyfile for the new factor. Required with `--auth keyfile`.
        #[arg(long, value_name = "PATH", required_if_eq("auth", "keyfile"))]
        keyfile: Option<PathBuf>,
        #[command(flatten)]
        argon2: Argon2Args,
        /// Require PIN or biometric verification when creating the new credential.
        #[arg(long)]
        require_uv: bool,
    },
    /// Remove a factor from an open store.
    Revoke {
        /// Store alias or vault path.
        store: String,
        /// Hex entry id, as shown by `info`.
        #[arg(long, value_name = "HEX", conflicts_with = "credential")]
        id: Option<String>,
        /// Hex credential ID. Kept as an alias for `--id`; FIDO2 entries only.
        #[arg(long, value_name = "HEX")]
        credential: Option<String>,
    },
    /// Close every store and leave.
    #[command(alias = "quit")]
    Exit,
}

#[derive(Subcommand)]
enum ReplKvCommand {
    /// Store a value, replacing any existing entry of that name.
    Set {
        /// Store alias or vault path.
        store: String,
        /// Entry name.
        name: String,
        #[command(flatten)]
        source: KvValueSource,
    },
    /// Show one entry's value.
    Get { store: String, name: String },
    /// Delete one entry.
    Rm { store: String, name: String },
    /// List entry names, sorted.
    Ls { store: String },
}

/// Options for the `interactive` subcommand, kept here so the flag descriptions sit
/// beside the behaviour they select.
#[derive(Args)]
pub struct InteractiveArgs {
    /// Close every store after this many seconds with no activity. 0 disables it,
    /// which leaves the vault unlocked for as long as the session runs.
    #[arg(long, value_name = "SECS", default_value_t = fidostorers::session::DEFAULT_IDLE_TIMEOUT.as_secs())]
    pub idle_timeout: u64,
    /// Warn this many seconds before the idle timeout closes a store.
    #[arg(long, value_name = "SECS", default_value_t = fidostorers::session::DEFAULT_IDLE_WARNING.as_secs())]
    pub idle_warning: u64,
}

pub fn run(args: &InteractiveArgs, hardening: &fidostorers::Hardening) -> Result<i32> {
    // 0 means "no timeout": an explicit choice to leave vaults unlocked for the life
    // of the session, not an accidental zero-length one.
    let idle_timeout = (args.idle_timeout > 0).then(|| Duration::from_secs(args.idle_timeout));
    let idle_warning = Duration::from_secs(args.idle_warning);

    let session = Arc::new(Mutex::new(Session::new(
        Arc::new(SystemClock),
        idle_timeout,
    )));
    let signals = signals::install();

    let root = workdir::runtime_root();
    workdir::create_private_dir(&root).with_context(|| format!("preparing {}", root.display()))?;
    let paths = Paths {
        work_base: workdir::new_session_dir(&root)?,
        root,
    };

    // History is in memory and cannot reach disk: with rustyline's
    // `with-file-history` feature off, `DefaultHistory` *is* the in-memory one, so
    // `kv set --value <secret>` has nowhere to be persisted to. plan/08 asks for
    // memory-only history; a type that cannot write beats remembering not to call
    // `save_history`.
    let config = Config::builder().auto_add_history(true).build();
    let mut editor =
        DefaultEditor::with_config(config).context("starting the interactive line editor")?;

    banner(idle_timeout, hardening);

    // Before anything else: a previous session may have died holding plaintext.
    if let Err(err) = recover_orphans(&mut editor, &paths) {
        report(&err);
    }

    let watchdog = Watchdog::spawn(
        Arc::clone(&session),
        editor.create_external_printer().ok(),
        idle_warning,
    );

    let loop_result = main_loop(&mut editor, &session, &signals, &paths);
    watchdog.stop();

    let shutdown_code = shutdown(&session, &signals, &paths);
    // The session directory is ours and is empty once every store has closed;
    // leaving it behind would accumulate one per session ever run.
    let _ = std::fs::remove_dir(&paths.work_base);

    // A failure in the loop outranks the shutdown's own result; otherwise the
    // shutdown decides, since that is where sealing happens.
    match loop_result {
        Ok(0) => Ok(shutdown_code),
        other => other,
    }
}

/// Close every store, sealing as we go, and report what was written.
///
/// Interruptible *between* stores: a Ctrl+C during a long shutdown stops the ones
/// not yet reached rather than abandoning a write half-done. Anything not sealed
/// keeps its plaintext, so nothing is silently thrown away.
fn shutdown(session: &Arc<Mutex<Session>>, signals: &signals::Signals, paths: &Paths) -> i32 {
    let stores = session.lock().expect("session mutex").take_all();
    let mut failed = false;
    let mut retained: Vec<PathBuf> = Vec::new();
    let mut stores = stores.into_iter().peekable();

    while let Some(store) = stores.next() {
        if signals.take_cancel() {
            let mut abandoned = vec![store];
            abandoned.extend(stores);
            eprintln!(
                "interrupted: {} store(s) not sealed. Their plaintext is left in place and \
                 will be offered back the next time you start a session.",
                abandoned.len()
            );
            for mut store in abandoned {
                store.keep_plaintext();
                if let Some(path) = store.work_path() {
                    retained.push(path.to_path_buf());
                }
            }
            failed = true;
            break;
        }

        let alias = store.alias().to_string();
        let closed = ClosedStore::seal(store);
        match &closed.sealed {
            Ok(true) => println!("sealed {alias:?}"),
            Ok(false) => println!("{alias:?} unchanged, nothing to write"),
            Err(err) => {
                eprintln!("error: could not seal {alias:?}: {err}");
                failed = true;
                if let Some(path) = closed.store.work_path() {
                    retained.push(path.to_path_buf());
                }
            }
        }
        // Dropping the store zeroizes its data key, releases its vault lock, and
        // removes its working directory — unless a failed seal kept it.
        drop(closed);
    }

    for path in &retained {
        eprintln!("  plaintext kept at {}", path.display());
    }
    if retained.is_empty() {
        orphan::clear_record(&paths.root);
    } else {
        // Leave the record: those trees are now orphans, and the record is how the
        // next session finds them.
        eprintln!("Start a session again to seal or discard them.");
    }

    if failed {
        crate::EXIT_ERROR
    } else {
        0
    }
}

/// Offer back any working directory left by a session that did not exit cleanly.
fn recover_orphans(editor: &mut DefaultEditor, paths: &Paths) -> Result<()> {
    for orphan in orphan::find(&paths.root) {
        println!();
        println!("Found an unsealed working directory from a session that did not exit cleanly:");
        println!("  vault:   {}", orphan.store.vault.display());
        println!("  work:    {}", orphan.store.work.display());
        println!(
            "  holds:   {} entr{}{}",
            orphan.entries,
            if orphan.entries == 1 { "y" } else { "ies" },
            match orphan.last_modified {
                Some(_) => ", last modified since that session started",
                None => "",
            }
        );

        loop {
            let answer = match editor
                .readline("  [s]eal it into the vault  [d]iscard it  [l]eave it for now: ")
            {
                Ok(answer) => answer,
                // EOF here means "not now", which is the safe reading: leaving it
                // writes nothing and the prompt returns next session.
                Err(_) => return Ok(()),
            };
            match answer.trim() {
                "s" | "seal" => {
                    match seal_orphan(editor, &orphan) {
                        Ok(()) => {
                            println!("  sealed into {}", orphan.store.vault.display());
                            discard_tree(&orphan.store.work);
                            orphan::resolve(&orphan)?;
                        }
                        // Do not resolve: a failed seal must be offered again
                        // rather than quietly dropped.
                        Err(err) => report(&err),
                    }
                    break;
                }
                "d" | "discard" => {
                    discard_tree(&orphan.store.work);
                    orphan::resolve(&orphan)?;
                    println!("  discarded");
                    break;
                }
                "l" | "leave" | "" => {
                    println!("  left in place; you will be asked again next session");
                    break;
                }
                _ => continue,
            }
        }
    }
    Ok(())
}

/// Seal an orphan's tree into its vault. The data key died with the old process, so
/// this costs a fresh unlock.
fn seal_orphan(editor: &mut DefaultEditor, orphan: &orphan::Orphan) -> Result<()> {
    let mut vault = Vault::open(&orphan.store.vault)?;
    let _lock = VaultLock::acquire(&orphan.store.vault)?;

    let keyfile = editor
        .readline("  keyfile to unlock with (blank for a security key): ")
        .unwrap_or_default();
    let keyfile = keyfile.trim();
    let auth = AuthArgs {
        keyfile: (!keyfile.is_empty()).then(|| PathBuf::from(keyfile)),
        password_stdin: false,
        id: None,
        require_uv: false,
    };

    let data_key = unlock_vault(&vault, &auth, &Interrupt::none())?;
    match orphan.store.mode {
        Mode::File => vault.seal_file(&data_key, &orphan.store.work)?,
        Mode::Dir => vault.seal_dir(&data_key, &orphan.store.work)?,
        Mode::Kv => bail!("a kv store has no working directory to recover"),
    }
    Ok(())
}

fn discard_tree(path: &Path) {
    let _ = if path.is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    };
}

fn banner(idle_timeout: Option<Duration>, hardening: &fidostorers::Hardening) {
    println!(
        "fidostorers {} — `help` lists commands, `exit` closes every store and quits",
        env!("CARGO_PKG_VERSION")
    );
    match idle_timeout {
        Some(timeout) => println!(
            "Stores close automatically after {} idle.",
            format_duration(timeout)
        ),
        None => println!("Idle timeout disabled: stores stay unlocked until you close them."),
    }
    eprintln!();
    eprintln!(
        "NOTE: a session keeps each open vault's data key in memory until you close it.\n\
         That is weaker than this tool's default of one touch per command."
    );
    // Stated as measured facts, not as reassurance: "we tried to lock memory" and
    // "memory is locked" are different claims, and only the second is worth making.
    eprintln!(
        "  data keys pinned in memory (never swapped): {}",
        hardening.memory_locking
    );
    eprintln!(
        "  core dumps suppressed:                      {}",
        hardening.core_dumps
    );
    if !hardening.is_complete() {
        eprintln!(
            "  A data key could therefore reach swap or a crash dump. Treat this session\n\
             \x20 as less protected than a vault at rest."
        );
    }
    eprintln!(
        "Opening a file or dir store extracts it to a PLAINTEXT working directory that\n\
         lives until you close the store; closing seals your changes back and removes\n\
         it. Removal is deletion, not secure erasure — keep the working directory on a\n\
         tmpfs or ramdisk if that matters. kv stores need no working directory."
    );
    eprintln!();
}

fn main_loop(
    editor: &mut DefaultEditor,
    session: &Arc<Mutex<Session>>,
    signals: &signals::Signals,
    paths: &Paths,
) -> Result<i32> {
    loop {
        if signals.shutdown_requested() {
            println!("\nshutting down");
            return Ok(0);
        }

        match editor.readline("fidostorers> ") {
            Ok(line) => {
                // A signal that arrived while a command was running was deliberately
                // not acted on mid-operation (plan/08, "Signals during a write"):
                // between commands is the first safe moment to notice it.
                signals.take_cancel();
                match dispatch(&line, session, signals, paths) {
                    Ok(Flow::Continue) => {}
                    Ok(Flow::Exit) => return Ok(0),
                    Err(err) => report(&err),
                }
                if signals.take_cancel() {
                    println!(
                        "interrupted — the operation was allowed to finish, since stopping a \
                         vault write partway is the one thing that could lose data."
                    );
                }
            }
            // Ctrl+C: clear the line and carry on. Ending a session is a separate,
            // deliberate gesture (plan/07 #19).
            Err(ReadlineError::Interrupted) => continue,
            // Ctrl+D on an empty line: graceful shutdown.
            Err(ReadlineError::Eof) => {
                println!("exit");
                return Ok(0);
            }
            Err(err) => {
                // A signal delivered while blocked on the terminal surfaces here.
                if signals.shutdown_requested() {
                    println!("\nshutting down");
                    return Ok(0);
                }
                return Err(anyhow::Error::new(err).context("reading from the terminal"));
            }
        }
    }
}

enum Flow {
    Continue,
    Exit,
}

fn report(err: &anyhow::Error) {
    eprintln!("error: {err:#}");
    if let Some(hint) = crate::hint_for(err) {
        eprintln!("hint: {hint}");
    }
}

fn dispatch(
    line: &str,
    session: &Arc<Mutex<Session>>,
    signals: &signals::Signals,
    paths: &Paths,
) -> Result<Flow> {
    let tokens = match crate::tokenize::tokenize(line) {
        Ok(tokens) => tokens,
        Err(err) => bail!("{err}"),
    };
    if tokens.is_empty() {
        return Ok(Flow::Continue);
    }

    let parsed = match ReplLine::try_parse_from(tokens) {
        Ok(parsed) => parsed,
        Err(err) => {
            // `help`, `--help` and a plain mistake all arrive here. clap has already
            // written the right thing; printing it is the whole response.
            let _ = err.print();
            return Ok(Flow::Continue);
        }
    };

    execute(parsed.command, session, signals, paths)
}

fn execute(
    command: ReplCommand,
    session: &Arc<Mutex<Session>>,
    signals: &signals::Signals,
    paths: &Paths,
) -> Result<Flow> {
    match command {
        ReplCommand::Exit => return Ok(Flow::Exit),

        ReplCommand::Open {
            vault: path,
            alias,
            force,
            work_dir,
            auth,
        } => {
            open_store(
                session,
                &path,
                alias,
                force,
                work_dir.as_deref(),
                &auth,
                signals,
                paths,
            )?;
        }

        ReplCommand::Init {
            vault: path,
            mode,
            rp_id,
            label,
            auth,
            keyfile,
            argon2,
            require_uv,
        } => {
            if path.exists() {
                bail!("{path:?} already exists; refusing to overwrite it");
            }
            // Lock before creating, so two sessions racing to create the same path
            // cannot both believe they own it.
            let lock = VaultLock::acquire(&path)?;
            let enrollment = build_enrollment(
                &rp_id,
                label,
                auth,
                keyfile.as_deref(),
                false,
                &argon2,
                require_uv,
            )?;
            let vault = Vault::create(&path, mode, &enrollment)?;
            let entry_id = vault.credentials()[0].id;
            let data_key = vault.unlock_with(&entry_id, enrollment.kek.clone())?;

            let mut session = session.lock().expect("session mutex");
            let store = session.open(vault, data_key, lock, None)?;
            println!(
                "created {mode} vault {path:?} and opened it as {:?}",
                store.alias()
            );
            crate::warn_about_a_single_factor(auth);
        }

        ReplCommand::Close { target } => {
            let mut session = session.lock().expect("session mutex");
            let closed = if target == "all" {
                session.close_all()
            } else {
                vec![session.close(&target)?]
            };
            if closed.is_empty() {
                println!("no open stores");
            }
            record_open_stores(&session, paths);
            for closed in &closed {
                report_close(closed);
            }
        }

        ReplCommand::Stores => {
            let session = session.lock().expect("session mutex");
            if session.is_empty() {
                println!("no open stores — `open <vault>` unlocks one");
            }
            let now = session.now();
            for store in session.stores() {
                // A cheap stat scan, not a full read: `stores` is a status display
                // and must stay instant even for a large tree. The exact check is
                // the one that decides a write, at seal time.
                let state = match store.work_path() {
                    None => "-",
                    Some(_) if store.looks_touched() => "changed",
                    Some(_) => "clean",
                };
                println!(
                    "  {:<12} {:<5} {:<8} idle {:<6} {}",
                    store.alias(),
                    store.vault().mode().to_string(),
                    state,
                    format_duration(store.idle_for(now)),
                    store.path().display()
                );
                if let Some(work) = store.work_path() {
                    println!("       work: {}", work.display());
                }
            }
        }

        ReplCommand::Info { store } => {
            let mut session = session.lock().expect("session mutex");
            let name = sole_store_or(&session, store)?;
            let store = session.get_mut(&name)?;
            // Unlike the one-shot `info`, this *is* authenticated: opening the store
            // unwrapped the data key and verified `header_mac` with it.
            print_vault_info(store.vault(), true);
        }

        ReplCommand::Seal { target } => {
            let mut session = session.lock().expect("session mutex");
            let results = if target == "all" {
                session.seal_all()
            } else {
                let wrote = session.seal(&target)?;
                vec![(session.get(&target)?.alias().to_string(), Ok(wrote))]
            };
            if results.is_empty() {
                println!("no open stores");
            }
            let mut failed = false;
            for (alias, result) in results {
                match result {
                    Ok(true) => println!("sealed {alias:?}"),
                    Ok(false) => println!("{alias:?} unchanged, nothing to write"),
                    Err(err) => {
                        eprintln!("error: could not seal {alias:?}: {err}");
                        failed = true;
                    }
                }
            }
            if failed {
                bail!("some stores could not be sealed; their working directories are unchanged");
            }
        }

        ReplCommand::Kv { command } => return kv(command, session).map(|()| Flow::Continue),

        ReplCommand::Enroll {
            store,
            label,
            auth,
            keyfile,
            argon2,
            require_uv,
        } => {
            // Build the enrollment before taking the session lock: it can block for
            // a long time on a touch or a password, and holding the mutex would
            // stall the idle watchdog throughout.
            let rp_id = {
                let session = session.lock().expect("session mutex");
                session.get(&store)?.vault().rp_id().to_string()
            };
            if auth == AuthKind::Fido2 {
                eprintln!("Connect the NEW security key and touch it. It is asked for twice.");
            }
            let enrollment = build_enrollment(
                &rp_id,
                label.clone(),
                auth,
                keyfile.as_deref(),
                false,
                &argon2,
                require_uv,
            )?;

            let mut session = session.lock().expect("session mutex");
            let store = session.get_mut(&store)?;
            let (vault, data_key) = store.parts_mut();
            vault.enroll(data_key, &enrollment)?;
            println!(
                "enrolled {label:?}; {:?} now has {}",
                vault.path(),
                crate::plural_factors(vault.credentials().len())
            );
            if auth == AuthKind::Keyfile {
                crate::warn_about_weakest_factor();
            }
        }

        ReplCommand::Revoke {
            store,
            id,
            credential,
        } => {
            let hex = match (id, credential) {
                (Some(id), _) => id,
                (None, Some(credential)) => credential,
                (None, None) => bail!("specify which factor to remove with --id (see `info`)"),
            };
            let target = crate::from_hex(&hex).context("--id must be hex")?;

            let mut session = session.lock().expect("session mutex");
            let store = session.get_mut(&store)?;
            let (vault, data_key) = store.parts_mut();
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
                .map(|entry| entry.label.clone())
                .unwrap_or_else(|| "that factor".to_string());
            vault.revoke(data_key, &target)?;
            println!(
                "revoked {label:?}; {} remain",
                crate::plural_factors(vault.credentials().len())
            );
            crate::warn_revocation_is_not_rekeying();
        }
    }
    Ok(Flow::Continue)
}

#[allow(clippy::too_many_arguments)]
fn open_store(
    session: &Arc<Mutex<Session>>,
    path: &Path,
    alias: Option<String>,
    force: bool,
    work_dir: Option<&Path>,
    auth: &AuthArgs,
    signals: &signals::Signals,
    paths: &Paths,
) -> Result<()> {
    // Check this session first. The lock below would otherwise report the vault as
    // busy with a lock this very process holds, which is true but useless.
    {
        let session = session.lock().expect("session mutex");
        if let Ok(store) = session.get(&path.to_string_lossy()) {
            bail!("{path:?} is already open as {:?}", store.alias());
        }
    }

    // On a terminal there is nothing on stdin to read: rustyline has the line the
    // user typed, and reading a "password line" afterwards would prompt with echo
    // on — the one thing the no-echo prompt exists to prevent. Piped input is the
    // case the flag was built for and still works.
    if auth.password_stdin && std::io::stdin().is_terminal() {
        bail!(
            "--password-stdin has nothing to read here: stdin is the prompt you are typing \
             at. Omit it and the password is asked for without echo."
        );
    }

    let vault = Vault::open(path)?;
    let mode = vault.mode();
    let work_path = match (mode, work_dir) {
        (Mode::Kv, Some(_)) => {
            bail!("a kv store has no working directory, so --work-dir does nothing here")
        }
        (Mode::Kv, None) => None,
        (mode, Some(chosen)) => Some(prepare_work_dir(chosen, mode)?),
        (_, None) => Some(workdir::work_path_for(
            &paths.work_base,
            alias.as_deref().unwrap_or(&default_alias(path)),
        )),
    };

    let lock = if force {
        if let Some(info) = fidostorers::lock::holder(path) {
            eprintln!(
                "warning: taking {path:?} from pid {} on {}. If that process is still \
                 running, one of you will lose changes.",
                info.pid, info.hostname
            );
        }
        VaultLock::steal(path)?
    } else {
        VaultLock::acquire(path)?
    };

    // Unlock outside the session mutex: a touch can block for the full 30-second
    // device timeout, and holding the mutex would stop the idle watchdog for it.
    let data_key = unlock_vault(&vault, auth, &Interrupt::watching(signals.cancel_flag()))?;

    let mut session = session.lock().expect("session mutex");
    let (store, report) =
        session.open_with_work_dir(vault, data_key, lock, alias, work_path.as_deref())?;

    match store.work_path() {
        Some(work) => println!("opened {:?} ({mode}) at {}", store.alias(), work.display()),
        None => println!("opened {:?} ({mode})", store.alias()),
    }
    if report.modes_ignored {
        eprintln!(
            "warning: this platform has no Unix mode bits, so permissions in the archive \
             were not applied. They are still stored, and will be preserved when this \
             store is sealed."
        );
    }
    for skipped in &report.skipped {
        eprintln!(
            "warning: skipped {}: {}",
            skipped.path.display(),
            skipped.reason
        );
    }
    if !report.is_complete() {
        eprintln!(
            "{} entr{} could not be extracted, so this working directory is INCOMPLETE. \
             Sealing it would write back a tree missing those entries — close without \
             changing anything, or discard your changes, unless you know better.",
            report.skipped.len(),
            if report.skipped.len() == 1 {
                "y"
            } else {
                "ies"
            }
        );
    }
    record_open_stores(&session, paths);
    Ok(())
}

/// Validate a `--work-dir` the user chose.
///
/// It must be empty or absent, because closing the store removes what we put there
/// and we must never delete something the user already had. The sync check is the
/// same one the keyfile warnings use, for the same reason: anything written into a
/// synced folder or a git repo is about to be copied somewhere else, and here that
/// something is plaintext.
fn prepare_work_dir(chosen: &Path, mode: Mode) -> Result<PathBuf> {
    // A `file` store's working path *is* the file, so anything already there would
    // be overwritten on open and deleted on close.
    if chosen.exists() {
        match mode {
            Mode::File => bail!(
                "{chosen:?} already exists; --work-dir for a file store must be a path that \
                 does not exist yet, since the store is written there directly"
            ),
            _ if !chosen.is_dir() => bail!("{chosen:?} is not a directory"),
            _ if chosen.read_dir()?.next().is_some() => {
                bail!("{chosen:?} is not empty; --work-dir must be an empty or new directory")
            }
            _ => {}
        }
    }
    if workdir::looks_synced(chosen) {
        eprintln!(
            "warning: {} looks like a git repository or a synced folder. Everything \
             extracted there is PLAINTEXT, and sync or version history would keep a copy \
             long after this store is closed.",
            chosen.display()
        );
    }
    Ok(chosen.to_path_buf())
}

/// Record what is open, so a session that is killed can be recovered from.
///
/// Rewritten whenever the open set changes rather than only at startup, so the
/// record always matches what is actually extracted.
fn record_open_stores(session: &Session, paths: &Paths) {
    if let Err(err) = orphan::write_record(&paths.root, session.records()) {
        // Not fatal: the session still works, it just would not be recoverable.
        eprintln!("warning: could not record open stores for crash recovery: {err}");
    }
}

fn report_close(closed: &ClosedStore) {
    match &closed.sealed {
        Ok(true) => println!("sealed and closed {:?}", closed.alias()),
        Ok(false) => println!("closed {:?} (unchanged)", closed.alias()),
        Err(err) => {
            eprintln!("error: could not seal {:?}: {err}", closed.alias());
            if let Some(path) = closed.store.work_path() {
                eprintln!("  plaintext kept at {}", path.display());
            }
        }
    }
}

/// The alias a vault gets when the user does not name one: its file stem.
fn default_alias(path: &Path) -> String {
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    if stem.is_empty() {
        "store".to_string()
    } else {
        stem
    }
}

fn kv(command: ReplKvCommand, session: &Arc<Mutex<Session>>) -> Result<()> {
    let mut session = session.lock().expect("session mutex");
    match command {
        ReplKvCommand::Set {
            store,
            name,
            source,
        } => {
            // In a session, stdin is the prompt. Reading a value from it would eat
            // the rest of the user's input, so this is refused rather than left to
            // misbehave.
            if source.stdin {
                bail!(
                    "--stdin cannot be used inside a session: stdin is the prompt you are \
                     typing at. Use --file <path>, or run `fidostorers kv set` as a one-shot \
                     command."
                );
            }
            if source.value.is_some() {
                eprintln!(
                    "warning: --value leaves the secret in this terminal's scrollback. \
                     --file <path> does not."
                );
            }
            let value = zeroize::Zeroizing::new(source.resolve()?);
            let store = session.get_mut(&store)?;
            let (vault, data_key) = store.parts_mut();
            vault.kv_set(data_key, &name, &value)?;
            println!("set {name:?}");
        }
        ReplKvCommand::Get { store, name } => {
            let store = session.get_mut(&store)?;
            let value = store.vault().kv_get(store.data_key(), &name)?;
            // The one-shot command writes raw bytes for a pipe to consume. At a
            // prompt there is no pipe, and spraying control bytes at the terminal
            // helps nobody.
            match std::str::from_utf8(&value) {
                Ok(text) => println!("{text}"),
                Err(_) => println!(
                    "<{} bytes, not valid UTF-8 — use the one-shot `fidostorers kv get` and \
                     redirect it to a file>",
                    value.len()
                ),
            }
        }
        ReplKvCommand::Rm { store, name } => {
            let store = session.get_mut(&store)?;
            let (vault, data_key) = store.parts_mut();
            vault.kv_rm(data_key, &name)?;
            println!("removed {name:?}");
        }
        ReplKvCommand::Ls { store } => {
            let store = session.get_mut(&store)?;
            let names = store.vault().kv_ls(store.data_key())?;
            if names.is_empty() {
                println!("(no entries)");
            }
            for name in names {
                println!("{name}");
            }
        }
    }
    Ok(())
}

/// Let `info` with one open store mean that store, and say so plainly otherwise.
fn sole_store_or(session: &Session, requested: Option<String>) -> Result<String> {
    if let Some(name) = requested {
        return Ok(name);
    }
    match session.stores() {
        [only] => Ok(only.alias().to_string()),
        [] => bail!("no open stores — `open <vault>` unlocks one"),
        _ => bail!("several stores are open; name one (see `stores`)"),
    }
}

/// Durations in status output are read at a glance, so seconds below a minute and
/// whole minutes above is as much precision as is useful.
fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{secs}s")
    } else {
        format!("{}m", secs / 60)
    }
}

/// A countdown rounds *up*: with 2.9 seconds left, "closes in 2s" would be both
/// wrong and alarming a second early.
fn format_countdown(remaining: Duration) -> String {
    let secs = remaining.as_secs() + u64::from(remaining.subsec_nanos() > 0);
    format_duration(Duration::from_secs(secs))
}

/// Closes stores that have gone idle, from a thread, so a session left unattended
/// does not stay unlocked (plan/07 #18).
struct Watchdog {
    running: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Watchdog {
    fn spawn(
        session: Arc<Mutex<Session>>,
        printer: Option<impl ExternalPrinter + Send + 'static>,
        idle_warning: Duration,
    ) -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let stop = Arc::clone(&running);
        let handle = std::thread::spawn(move || {
            let mut printer = printer;
            // Warn once per idle period, not once per tick.
            let mut warned: Vec<String> = Vec::new();
            let mut ticks: u32 = 0;

            let mut emit = move |message: String| match printer.as_mut() {
                // Printing through rustyline redraws the prompt around the message,
                // so a warning that arrives mid-typing does not eat the line.
                Some(printer) => {
                    let _ = printer.print(message);
                }
                None => eprintln!("{message}"),
            };

            while stop.load(Ordering::Relaxed) {
                std::thread::sleep(WATCHDOG_TICK);
                ticks = ticks.wrapping_add(1);

                let mut session = match session.lock() {
                    Ok(session) => session,
                    Err(_) => return,
                };
                if session.idle_timeout().is_none() {
                    continue;
                }

                // Editing files in another window is working, not idling. Done on a
                // slower cadence than the clock check because it walks every open
                // tree, and five-second granularity is irrelevant against a
                // fifteen-minute timeout.
                if ticks % SCAN_EVERY == 0 {
                    for alias in session.note_external_activity() {
                        warned.retain(|warned| warned != &alias);
                    }
                }

                for closed in session.expire() {
                    warned.retain(|alias| alias != closed.alias());
                    let alias = closed.alias().to_string();
                    match &closed.sealed {
                        Ok(true) => emit(format!(
                            "\n{alias:?} was idle too long: sealed, closed, key dropped."
                        )),
                        Ok(false) => emit(format!(
                            "\n{alias:?} was idle too long: closed unchanged, key dropped."
                        )),
                        Err(err) => emit(format!(
                            "\n{alias:?} was idle too long, but could not be sealed: {err}\n\
                             Its plaintext is left in place and will be offered back next \
                             session."
                        )),
                    }
                }

                let expiring = session.expiring_within(idle_warning);
                warned.retain(|alias| expiring.iter().any(|(name, _)| name == alias));
                for (alias, remaining) in expiring {
                    if !warned.contains(&alias) {
                        warned.push(alias.clone());
                        emit(format!(
                            "\n{alias:?} closes in {} unless you use it.",
                            format_countdown(remaining)
                        ));
                    }
                }
            }
        });
        Watchdog {
            running,
            handle: Some(handle),
        }
    }

    fn stop(mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Signal handling.
///
/// Handlers only ever set a flag; the main loop reads it *between* commands. That
/// is what plan/08 means by deferring a signal that arrives during a write: an
/// in-progress vault write is never interrupted, because nothing checks the flag
/// while one is running.
mod signals {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    pub struct Signals {
        shutdown: Arc<AtomicBool>,
        cancel: Arc<AtomicBool>,
    }

    impl Signals {
        pub fn shutdown_requested(&self) -> bool {
            self.shutdown.load(Ordering::Relaxed)
        }

        /// Read and clear the cancellation flag.
        pub fn take_cancel(&self) -> bool {
            self.cancel.swap(false, Ordering::Relaxed)
        }

        pub fn cancel_flag(&self) -> Arc<AtomicBool> {
            Arc::clone(&self.cancel)
        }
    }

    #[cfg(unix)]
    pub fn install() -> Signals {
        let shutdown = Arc::new(AtomicBool::new(false));
        let cancel = Arc::new(AtomicBool::new(false));

        // SIGTERM and SIGHUP run the same graceful path as `exit`. SIGINT does not:
        // a reflexive Ctrl+C must not end a session (plan/07 #19), so it only asks
        // the current operation to stop at its next safe point.
        for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGHUP] {
            // A failure here costs the graceful path for that signal, not the
            // session; the default disposition still applies.
            let _ = signal_hook::flag::register(signal, Arc::clone(&shutdown));
        }
        let _ = signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&cancel));

        Signals { shutdown, cancel }
    }

    /// Windows has no SIGTERM or SIGHUP, and rustyline handles Ctrl+C at the prompt
    /// itself. A Ctrl+C during an operation therefore ends the process there — which
    /// is safe for the vault, since `Vault::write` renames a complete temp file into
    /// place, but does end the session.
    #[cfg(not(unix))]
    pub fn install() -> Signals {
        Signals {
            shutdown: Arc::new(AtomicBool::new(false)),
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(line: &str) -> Result<ReplLine, clap::Error> {
        ReplLine::try_parse_from(crate::tokenize::tokenize(line).unwrap())
    }

    #[test]
    fn repl_definition_is_valid() {
        ReplLine::command().debug_assert();
    }

    #[test]
    fn parses_open_with_an_alias() {
        match parse("open /a/tokens.fido --as work").unwrap().command {
            ReplCommand::Open { vault, alias, .. } => {
                assert_eq!(vault, PathBuf::from("/a/tokens.fido"));
                assert_eq!(alias.as_deref(), Some("work"));
            }
            _ => panic!("expected Open"),
        }
    }

    #[test]
    fn open_accepts_the_shared_auth_flags() {
        // The point of reusing `AuthArgs`: a flag cannot mean one thing one-shot and
        // another here.
        match parse("open v.fido --keyfile /k --password-stdin --id ab12")
            .unwrap()
            .command
        {
            ReplCommand::Open { auth, .. } => {
                assert_eq!(auth.keyfile, Some(PathBuf::from("/k")));
                assert!(auth.password_stdin);
                assert_eq!(auth.id.as_deref(), Some("ab12"));
            }
            _ => panic!("expected Open"),
        }
    }

    #[test]
    fn quit_is_an_alias_for_exit() {
        assert!(matches!(parse("quit").unwrap().command, ReplCommand::Exit));
        assert!(matches!(parse("exit").unwrap().command, ReplCommand::Exit));
    }

    #[test]
    fn kv_commands_name_a_store_not_a_path() {
        match parse("kv get tokens github").unwrap().command {
            ReplCommand::Kv {
                command: ReplKvCommand::Get { store, name },
            } => {
                assert_eq!(store, "tokens");
                assert_eq!(name, "github");
            }
            _ => panic!("expected Kv Get"),
        }
    }

    #[test]
    fn enroll_takes_no_unlocking_flags() {
        // The session is already unlocked; offering --unlock-keyfile here would be
        // offering to do something twice.
        assert!(parse("enroll tokens --unlock-keyfile /k").is_err());
        match parse("enroll tokens --label \"backup in safe\"")
            .unwrap()
            .command
        {
            ReplCommand::Enroll { store, label, .. } => {
                assert_eq!(store, "tokens");
                assert_eq!(label, "backup in safe");
            }
            _ => panic!("expected Enroll"),
        }
    }

    #[test]
    fn a_keyfile_factor_still_requires_a_keyfile() {
        assert!(parse("enroll tokens --auth keyfile").is_err());
        assert!(parse("enroll tokens --auth keyfile --keyfile /k").is_ok());
        assert!(parse("init v.fido --mode kv --auth keyfile").is_err());
    }

    #[test]
    fn revoke_rejects_both_id_and_credential() {
        assert!(parse("revoke tokens --id aa --credential bb").is_err());
        assert!(parse("revoke tokens --id aa").is_ok());
    }

    #[test]
    fn info_and_close_take_their_targets() {
        assert!(matches!(
            parse("info").unwrap().command,
            ReplCommand::Info { store: None }
        ));
        match parse("close all").unwrap().command {
            ReplCommand::Close { target } => assert_eq!(target, "all"),
            _ => panic!("expected Close"),
        }
    }

    #[test]
    fn one_shot_only_commands_are_not_offered() {
        // `lock`/`unlock` deliberately are not REPL commands: extraction happens at
        // `open` and sealing at `close`, so reusing those verbs would mislead.
        assert!(parse("lock tokens ./dir").is_err());
        assert!(parse("unlock tokens ./out").is_err());
    }

    #[test]
    fn an_unknown_command_is_an_error_not_a_panic() {
        assert!(parse("frobnicate").is_err());
    }

    #[test]
    fn idle_time_is_reported_in_human_units() {
        assert_eq!(format_duration(Duration::from_secs(0)), "0s");
        assert_eq!(format_duration(Duration::from_secs(59)), "59s");
        assert_eq!(format_duration(Duration::from_secs(60)), "1m");
        assert_eq!(format_duration(Duration::from_secs(900)), "15m");
    }

    #[test]
    fn a_countdown_rounds_up_so_it_never_reads_low() {
        assert_eq!(format_countdown(Duration::from_millis(2900)), "3s");
        assert_eq!(format_countdown(Duration::from_secs(3)), "3s");
        assert_eq!(format_countdown(Duration::from_millis(1)), "1s");
        assert_eq!(format_countdown(Duration::ZERO), "0s");
    }
}
