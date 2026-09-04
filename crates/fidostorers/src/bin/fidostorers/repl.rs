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
//! **Working directories for `file` and `dir` stores are not here yet** — they are
//! the next milestone, and they are the part that puts plaintext on disk. So a
//! `file`/`dir` store can be opened (its key is cached, so `info`, `enroll` and
//! `revoke` need no further touches) but its contents are not extracted, and `kv`
//! stores are the ones that work end to end.

use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use fidostorers::session::{Session, SystemClock};
use fidostorers::{Mode, Vault, VaultLock};
use rustyline::error::ReadlineError;
use rustyline::{Config, DefaultEditor, ExternalPrinter};

use crate::{
    build_enrollment, print_vault_info, unlock_vault, Argon2Args, AuthArgs, AuthKind, Interrupt,
    KvValueSource,
};

/// How often the idle watchdog looks at the session. Short enough that `exit`
/// does not visibly wait on it, long enough to cost nothing.
const WATCHDOG_TICK: Duration = Duration::from_millis(250);

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

pub fn run(args: &InteractiveArgs) -> Result<i32> {
    // 0 means "no timeout": an explicit choice to leave vaults unlocked for the life
    // of the session, not an accidental zero-length one.
    let idle_timeout = (args.idle_timeout > 0).then(|| Duration::from_secs(args.idle_timeout));
    let idle_warning = Duration::from_secs(args.idle_warning);

    let session = Arc::new(Mutex::new(Session::new(
        Arc::new(SystemClock),
        idle_timeout,
    )));
    let signals = signals::install();

    // History is in memory and cannot reach disk: with rustyline's
    // `with-file-history` feature off, `DefaultHistory` *is* the in-memory one, so
    // `kv set --value <secret>` has nowhere to be persisted to. plan/08 asks for
    // memory-only history; a type that cannot write beats remembering not to call
    // `save_history`.
    let config = Config::builder().auto_add_history(true).build();
    let mut editor =
        DefaultEditor::with_config(config).context("starting the interactive line editor")?;

    banner(idle_timeout);

    let watchdog = Watchdog::spawn(
        Arc::clone(&session),
        editor.create_external_printer().ok(),
        idle_warning,
    );

    let exit_code = main_loop(&mut editor, &session, &signals);
    watchdog.stop();

    let closed = session.lock().expect("session mutex").close_all();
    if !closed.is_empty() {
        println!(
            "closing {}",
            closed
                .iter()
                .map(|s| s.alias().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    // Dropping each `Store` zeroizes its data key and releases its vault lock.
    drop(closed);
    exit_code
}

fn banner(idle_timeout: Option<Duration>) {
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
         That is weaker than this tool's default of one touch per command. Memory\n\
         pinning and core-dump suppression are not implemented yet, so do not treat a\n\
         running session as equivalent to a vault at rest."
    );
    eprintln!(
        "Opening a file or dir store caches its key — so `info`, `enroll` and `revoke`\n\
         cost no further touches — but does not extract its contents. kv stores are\n\
         fully usable here."
    );
    eprintln!();
}

fn main_loop(
    editor: &mut DefaultEditor,
    session: &Arc<Mutex<Session>>,
    signals: &signals::Signals,
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
                match dispatch(&line, session, signals) {
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

fn dispatch(line: &str, session: &Arc<Mutex<Session>>, signals: &signals::Signals) -> Result<Flow> {
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

    execute(parsed.command, session, signals)
}

fn execute(
    command: ReplCommand,
    session: &Arc<Mutex<Session>>,
    signals: &signals::Signals,
) -> Result<Flow> {
    match command {
        ReplCommand::Exit => return Ok(Flow::Exit),

        ReplCommand::Open {
            vault: path,
            alias,
            force,
            auth,
        } => {
            open_store(session, &path, alias, force, &auth, signals)?;
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
            for store in &closed {
                println!("closed {:?}", store.alias());
            }
        }

        ReplCommand::Stores => {
            let session = session.lock().expect("session mutex");
            if session.is_empty() {
                println!("no open stores — `open <vault>` unlocks one");
            }
            let now = session.now();
            for store in session.stores() {
                println!(
                    "  {:<12} {:<5} idle {:<6} {}",
                    store.alias(),
                    store.vault().mode().to_string(),
                    format_duration(store.idle_for(now)),
                    store.path().display()
                );
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
            let session = session.lock().expect("session mutex");
            if target != "all" {
                session.get(&target)?;
            }
            // Honest rather than a silent no-op: `seal` flushes a working directory,
            // and working directories are the next milestone. Until then every
            // change a session makes is written to the vault as it is made.
            println!(
                "nothing to seal: every change is written to the vault file as you make it.\n\
                 `seal` becomes meaningful once file and dir stores are extracted to a\n\
                 working directory."
            );
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

fn open_store(
    session: &Arc<Mutex<Session>>,
    path: &std::path::Path,
    alias: Option<String>,
    force: bool,
    auth: &AuthArgs,
    signals: &signals::Signals,
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
    let store = session.open(vault, data_key, lock, alias)?;
    let mode = store.vault().mode();
    println!("opened {:?} ({mode})", store.alias());
    if mode != Mode::Kv {
        println!(
            "  its key is cached, so `info`, `enroll` and `revoke` need no further touches.\n\
             \x20 Extracting its contents to a working directory is not implemented yet."
        );
    }
    Ok(())
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
                let mut session = match session.lock() {
                    Ok(session) => session,
                    Err(_) => return,
                };
                if session.idle_timeout().is_none() {
                    continue;
                }

                for store in session.expire() {
                    warned.retain(|alias| alias != store.alias());
                    emit(format!(
                        "\n{:?} was idle too long: closed, key dropped.",
                        store.alias()
                    ));
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
