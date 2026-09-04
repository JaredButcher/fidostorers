//! Long-lived sessions: a vault's data key held in memory so a user touches their
//! security key once per vault rather than once per command (plan/08).
//!
//! This is a deliberate reversal of "every unlocking operation requires a live
//! touch". What survives is the guarantee that matters most: a vault at rest, with
//! no session running, is exactly as protected as before. What weakens is the window
//! while a session is open — which is why that window is bounded by an idle timeout
//! and shown in `stores`.
//!
//! Nothing here talks to hardware. A [`Store`] is handed an **already-derived** data
//! key, exactly as [`crate::Vault`] is handed an already-derived KEK, so every test
//! below runs without a security key (plan/08, "Testing").

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::hardening::SecretKey;
use crate::lock::VaultLock;
use crate::workdir::{Scan, WorkDir};
use crate::{ExtractReport, Mode, Vault, VaultError};

/// The default idle timeout (plan/07 #18). On by default so that a session does not
/// quietly become an always-unlocked vault on an unattended machine.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// How long before expiry the user is warned, so an idle timeout does not arrive
/// with no notice.
pub const DEFAULT_IDLE_WARNING: Duration = Duration::from_secs(60);

/// Source of "now", injectable so the idle timeout is testable without sleeping.
pub trait Clock: Send + Sync + std::fmt::Debug {
    fn now(&self) -> Instant;
}

/// The real clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

#[derive(thiserror::Error, Debug)]
pub enum SessionError {
    #[error("no open store named {0:?}")]
    NoSuchStore(String),

    #[error("{path:?} is already open in this session as {alias:?}")]
    AlreadyOpen { alias: String, path: PathBuf },

    #[error(transparent)]
    Vault(#[from] VaultError),
}

/// One vault held open by a session.
///
/// **Only the data key is cached, never the KEK or the raw `hmac-secret` output.**
/// The data key is sufficient for every [`Vault`] operation and is the narrowest
/// thing that works: it cannot derive anything for another vault, and it says
/// nothing about the security key that produced it.
///
/// It is held in a [`SecretKey`] — its own `mlock`ed page — rather than an ordinary
/// `Zeroizing`, because a session holds it for minutes or hours rather than for one
/// command, which is long enough to be paged out to swap.
#[derive(Debug)]
pub struct Store {
    alias: String,
    vault: Vault,
    data_key: SecretKey,
    last_activity: Instant,
    /// `file` and `dir` stores are edited through a plaintext tree on disk; a `kv`
    /// store has no such thing and stays memory-only.
    work: Option<WorkDir>,
    /// The last stat-only summary of `work`, so the idle watchdog can tell that a
    /// user editing files in another window is working rather than idle, without
    /// re-reading the tree on every tick.
    last_scan: Scan,
    /// Held for as long as the store is open, so a second session — and any other
    /// `fidostorers` command touching this vault — refuses rather than racing us.
    /// Dropped, and so released, when this `Store` is.
    _lock: VaultLock,
}

impl Store {
    pub fn alias(&self) -> &str {
        &self.alias
    }

    pub fn vault(&self) -> &Vault {
        &self.vault
    }

    pub fn path(&self) -> &Path {
        self.vault.path()
    }

    pub fn data_key(&self) -> &[u8; 32] {
        &self.data_key
    }

    /// Whether this store's data key is actually pinned in memory. False means the
    /// page could not be locked, which the session reports rather than hides.
    pub fn key_is_locked(&self) -> bool {
        self.data_key.is_locked()
    }

    /// Mutable vault and its data key together.
    ///
    /// Every mutating `Vault` method needs both at once, and taking them through
    /// two accessors would borrow `self` mutably and immutably at the same call.
    pub fn parts_mut(&mut self) -> (&mut Vault, &[u8; 32]) {
        (&mut self.vault, &self.data_key)
    }

    pub fn idle_for(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.last_activity)
    }

    pub fn mode(&self) -> Mode {
        self.vault.mode()
    }

    /// Leave this store's plaintext on disk when it is dropped, so it can be
    /// recovered later. For a seal that failed or was not attempted.
    pub fn keep_plaintext(&mut self) {
        if let Some(work) = &mut self.work {
            work.keep();
        }
    }

    /// Where this store's plaintext is, for `file` and `dir` stores.
    pub fn work_path(&self) -> Option<&Path> {
        self.work.as_ref().map(|work| work.path())
    }

    /// Whether a seal would write anything.
    ///
    /// Reads the working tree, because this is the answer that decides a write: a
    /// cheap guess that said "unchanged" would silently discard the user's edits.
    /// A `kv` store is never pending — its writes go straight to the vault as they
    /// are made.
    pub fn is_pending(&self) -> Result<bool, VaultError> {
        match &self.work {
            Some(work) => Ok(work.pending()?.is_some()),
            None => Ok(false),
        }
    }

    /// Cheap "has anything been touched?", for status display and idle activity.
    /// May report a change that turns out not to alter the sealed bytes; never used
    /// to decide whether to write.
    pub fn looks_touched(&self) -> bool {
        self.work
            .as_ref()
            .is_some_and(|work| work.scan() != self.last_scan)
    }

    /// Write the working tree into the vault if it has changed, and report whether
    /// anything was written.
    ///
    /// Building the archive is the expensive half of sealing a large tree, and the
    /// check has already built it — so the bytes are sealed directly rather than
    /// walking the tree a second time.
    pub fn seal(&mut self) -> Result<bool, VaultError> {
        let Some(work) = &mut self.work else {
            return Ok(false);
        };
        let Some(pending) = work.pending()? else {
            return Ok(false);
        };

        match self.vault.mode() {
            Mode::File => self
                .vault
                .seal_file_bytes(&self.data_key, &pending.payload)?,
            Mode::Dir => self
                .vault
                .seal_dir_archive(&self.data_key, &pending.payload)?,
            Mode::Kv => return Ok(false),
        }
        // Only after the write succeeded: a failed seal must leave the store
        // pending, so exiting again still tries.
        work.mark_sealed(pending.digest);
        self.last_scan = work.scan();
        Ok(true)
    }
}

/// A store that has been taken out of the session, with what happened when it was
/// sealed on the way out.
///
/// The seal result travels with the store because the two are decided together and
/// reported together: "closed, wrote 3 changed files" and "closed, but the write
/// failed" are the messages a user needs, and neither can be reconstructed from the
/// store alone.
#[derive(Debug)]
pub struct ClosedStore {
    pub store: Store,
    /// `Ok(true)` if the vault was written, `Ok(false)` if nothing had changed.
    pub sealed: Result<bool, VaultError>,
}

impl ClosedStore {
    /// Seal a store on its way out of the session.
    ///
    /// Failure is carried rather than raised: the store is already out of the
    /// session, and the caller has to be able to finish closing the others and
    /// still report this one.
    pub fn seal(store: Store) -> Self {
        seal_and_take(store)
    }

    pub fn alias(&self) -> &str {
        self.store.alias()
    }
}

fn seal_and_take(mut store: Store) -> ClosedStore {
    let sealed = store.seal();
    if sealed.is_err() {
        // The working tree is now the only copy of the user's changes. Removing it
        // would turn a failed write into data loss, so it is kept and becomes an
        // orphan the next session offers to recover.
        store.keep_plaintext();
    }
    ClosedStore { store, sealed }
}

/// One process, any number of open stores.
#[derive(Debug)]
pub struct Session {
    /// Open order is preserved: shutdown seals in the order stores were opened, so
    /// a report of what was written reads the way the user built it up.
    stores: Vec<Store>,
    clock: Arc<dyn Clock>,
    /// `None` disables expiry entirely (`--idle-timeout 0`).
    idle_timeout: Option<Duration>,
}

impl Session {
    pub fn new(clock: Arc<dyn Clock>, idle_timeout: Option<Duration>) -> Self {
        Session {
            stores: Vec::new(),
            clock,
            idle_timeout,
        }
    }

    pub fn idle_timeout(&self) -> Option<Duration> {
        self.idle_timeout
    }

    pub fn now(&self) -> Instant {
        self.clock.now()
    }

    pub fn stores(&self) -> &[Store] {
        &self.stores
    }

    pub fn is_empty(&self) -> bool {
        self.stores.is_empty()
    }

    /// Add an unlocked vault to the session, returning the alias it was given.
    ///
    /// `lock` is taken by value because the session owns it for the store's
    /// lifetime: an open store with no held lock is exactly the state the lock
    /// exists to prevent.
    pub fn open(
        &mut self,
        vault: Vault,
        data_key: Zeroizing<[u8; 32]>,
        lock: VaultLock,
        requested_alias: Option<String>,
    ) -> Result<&Store, SessionError> {
        self.open_with_work_dir(vault, data_key, lock, requested_alias, None)
            .map(|(store, _)| store)
    }

    /// Open a store, extracting `file`/`dir` contents into `work_path`.
    ///
    /// `work_path` is required for those modes and rejected for `kv`, which has
    /// nothing to extract. The extraction report comes back alongside the store
    /// because a `dir` payload can hold entries this platform cannot create, and
    /// the caller has to be able to say which.
    pub fn open_with_work_dir(
        &mut self,
        vault: Vault,
        data_key: Zeroizing<[u8; 32]>,
        lock: VaultLock,
        requested_alias: Option<String>,
        work_path: Option<&Path>,
    ) -> Result<(&Store, ExtractReport), SessionError> {
        // The lock would already have caught another *process*, but not this one:
        // we hold our own lock, so a second `open` of the same file would report
        // the session as busy with itself. Saying "already open, as `tokens`" is
        // the answer the user needs.
        if let Some(existing) = self.find_by_path(vault.path()) {
            return Err(SessionError::AlreadyOpen {
                alias: self.stores[existing].alias.clone(),
                path: vault.path().to_path_buf(),
            });
        }

        let alias = match requested_alias {
            Some(alias) => self.unique_alias(&alias),
            None => self.unique_alias(&default_alias(vault.path())),
        };

        let (work, report) = match (vault.mode(), work_path) {
            (Mode::Kv, _) => (None, ExtractReport::default()),
            (mode, Some(path)) => {
                // Decrypt and extract before the store exists, so a failure here
                // leaves nothing half-open and releases the lock on the way out.
                let payload = match mode {
                    Mode::File => vault.read_file_payload(&data_key)?,
                    _ => vault.read_dir_archive(&data_key)?,
                };
                let (work, report) = WorkDir::extract_into(path, mode, &payload)?;
                (Some(work), report)
            }
            (mode, None) => {
                return Err(SessionError::Vault(VaultError::Internal(format!(
                    "a {mode} store needs a working directory"
                ))))
            }
        };

        let last_scan = work.as_ref().map(|work| work.scan()).unwrap_or_default();
        self.stores.push(Store {
            alias,
            vault,
            // The caller's `Zeroizing` copy is dropped and wiped on return; from
            // here the only surviving copy is the locked one.
            data_key: SecretKey::new(&data_key),
            last_activity: self.clock.now(),
            work,
            last_scan,
            _lock: lock,
        });
        Ok((self.stores.last().expect("just pushed"), report))
    }

    /// Resolve a name the user typed: an alias, or the path the store was opened
    /// with. Both are accepted because both are on screen — `stores` prints the
    /// alias, but the user typed the path at `open`.
    pub fn resolve(&self, name: &str) -> Result<usize, SessionError> {
        if let Some(index) = self.stores.iter().position(|s| s.alias == name) {
            return Ok(index);
        }
        self.find_by_path(Path::new(name))
            .ok_or_else(|| SessionError::NoSuchStore(name.to_string()))
    }

    pub fn get(&self, name: &str) -> Result<&Store, SessionError> {
        Ok(&self.stores[self.resolve(name)?])
    }

    /// Resolve a store for a command that will use it, recording the activity that
    /// holds the idle timeout off.
    pub fn get_mut(&mut self, name: &str) -> Result<&mut Store, SessionError> {
        let index = self.resolve(name)?;
        let now = self.clock.now();
        self.stores[index].last_activity = now;
        Ok(&mut self.stores[index])
    }

    /// Close one store, sealing it first. Dropping the returned value zeroizes the
    /// data key, removes the working directory, and releases the lock.
    pub fn close(&mut self, name: &str) -> Result<ClosedStore, SessionError> {
        let index = self.resolve(name)?;
        Ok(seal_and_take(self.stores.remove(index)))
    }

    /// Close every store, in the order they were opened.
    ///
    /// One store failing to seal does not stop the others: the rest still get
    /// written and their plaintext still gets removed, and the caller reports the
    /// failure and exits non-zero.
    pub fn close_all(&mut self) -> Vec<ClosedStore> {
        self.take_all().into_iter().map(seal_and_take).collect()
    }

    /// Remove every store from the session *without* sealing.
    ///
    /// For a shutdown that seals them one at a time and has to stay interruptible
    /// between stores: the caller seals each in turn and can stop partway, keeping
    /// the plaintext of whatever it did not get to.
    pub fn take_all(&mut self) -> Vec<Store> {
        std::mem::take(&mut self.stores)
    }

    /// Seal one open store without closing it — the explicit checkpoint.
    pub fn seal(&mut self, name: &str) -> Result<bool, SessionError> {
        let index = self.resolve(name)?;
        let now = self.clock.now();
        self.stores[index].last_activity = now;
        Ok(self.stores[index].seal()?)
    }

    /// Seal every open store, reporting each by alias.
    pub fn seal_all(&mut self) -> Vec<(String, Result<bool, VaultError>)> {
        let now = self.clock.now();
        self.stores
            .iter_mut()
            .map(|store| {
                store.last_activity = now;
                (store.alias.clone(), store.seal())
            })
            .collect()
    }

    /// What this session has open, for the crash-recovery record.
    pub fn records(&self) -> Vec<crate::orphan::StoreRecord> {
        self.stores
            .iter()
            .filter_map(|store| {
                Some(crate::orphan::StoreRecord {
                    alias: store.alias.clone(),
                    vault: store.vault.path().to_path_buf(),
                    work: store.work_path()?.to_path_buf(),
                    mode: store.vault.mode(),
                })
            })
            .collect()
    }

    /// Notice edits made inside working directories and count them as activity.
    ///
    /// A user editing files in another window for twenty minutes is working, not
    /// idle, and a timeout that only watched the prompt would seal the tree out
    /// from under their editor. Cheap by construction — a stat walk, no file
    /// contents — because it runs on a timer.
    ///
    /// Returns the aliases that had been touched, so a caller can say why a
    /// countdown reset.
    pub fn note_external_activity(&mut self) -> Vec<String> {
        let now = self.clock.now();
        let mut touched = Vec::new();
        for store in &mut self.stores {
            let Some(work) = &store.work else { continue };
            let scan = work.scan();
            if scan != store.last_scan {
                store.last_scan = scan;
                store.last_activity = now;
                touched.push(store.alias.clone());
            }
        }
        touched
    }

    /// Close every store that has been idle past the timeout, sealing first.
    ///
    /// Expiry is a *full* close rather than merely dropping the key: a store owns a
    /// plaintext working directory, and reporting "locked" while that directory sat
    /// readable on disk would be a lie. Each result carries whether that store was
    /// written and any error, because an expiry that failed to seal must not
    /// silently discard the tree it is about to delete.
    pub fn expire(&mut self) -> Vec<ClosedStore> {
        let Some(timeout) = self.idle_timeout else {
            return Vec::new();
        };
        let now = self.clock.now();
        let mut expired = Vec::new();
        let mut index = 0;
        while index < self.stores.len() {
            if self.stores[index].idle_for(now) >= timeout {
                expired.push(seal_and_take(self.stores.remove(index)));
            } else {
                index += 1;
            }
        }
        expired
    }

    /// Stores within `warning` of expiring, with how long each has left.
    ///
    /// The session prints this ahead of the timeout so an expiry does not arrive
    /// unannounced while an editor holds an unsaved buffer.
    pub fn expiring_within(&self, warning: Duration) -> Vec<(String, Duration)> {
        let Some(timeout) = self.idle_timeout else {
            return Vec::new();
        };
        let now = self.clock.now();
        self.stores
            .iter()
            .filter_map(|store| {
                let remaining = timeout.checked_sub(store.idle_for(now))?;
                (remaining <= warning).then(|| (store.alias.clone(), remaining))
            })
            .collect()
    }

    /// How long until the earliest expiry, for a caller deciding when to look again.
    pub fn next_expiry(&self) -> Option<Duration> {
        let timeout = self.idle_timeout?;
        let now = self.clock.now();
        self.stores
            .iter()
            .map(|store| timeout.saturating_sub(store.idle_for(now)))
            .min()
    }

    fn find_by_path(&self, path: &Path) -> Option<usize> {
        // Compare canonical paths so `./tokens.fido` and an absolute path are one
        // store, but fall back to the literal path: a vault being created does not
        // exist yet, and canonicalize would fail on it.
        let canonical = path.canonicalize().ok();
        self.stores.iter().position(|store| {
            store.path() == path
                || canonical
                    .as_ref()
                    .is_some_and(|c| store.path().canonicalize().ok().as_ref() == Some(c))
        })
    }

    /// `tokens.fido` -> `tokens`, with a counter appended on a collision.
    fn unique_alias(&self, base: &str) -> String {
        if !self.stores.iter().any(|s| s.alias == base) {
            return base.to_string();
        }
        (2..)
            .map(|n| format!("{base}-{n}"))
            .find(|candidate| !self.stores.iter().any(|s| &s.alias == candidate))
            .expect("the range is unbounded")
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Enrollment, Factor, Mode};
    use std::sync::Mutex;

    /// A clock the test drives by hand, so idle-timeout behaviour is asserted
    /// rather than slept through.
    #[derive(Debug)]
    struct TestClock(Mutex<Instant>);

    impl TestClock {
        fn new() -> Arc<Self> {
            Arc::new(TestClock(Mutex::new(Instant::now())))
        }

        fn advance(&self, by: Duration) {
            let mut now = self.0.lock().unwrap();
            *now += by;
        }
    }

    impl Clock for TestClock {
        fn now(&self) -> Instant {
            *self.0.lock().unwrap()
        }
    }

    /// A stand-in for whatever `fido_token::derive_secret` would have produced.
    fn test_enrollment(rp_id: &str) -> (Enrollment, Zeroizing<[u8; 32]>) {
        let kek = Zeroizing::new([7u8; 32]);
        let enrollment = Enrollment {
            factor: Factor::Fido2(fido_token::Credential {
                rp_id: rp_id.to_string(),
                credential_id: vec![1, 2, 3, 4],
                device_hint: None,
            }),
            rp_id: rp_id.to_string(),
            label: "primary".to_string(),
            salt: [9u8; 32],
            kek: kek.clone(),
        };
        (enrollment, kek)
    }

    /// Create a kv vault and return it already unlocked, the way `open` would.
    fn open_vault(path: &Path) -> (Vault, Zeroizing<[u8; 32]>) {
        let (enrollment, kek) = test_enrollment("fidostorers.local");
        let vault = Vault::create(path, Mode::Kv, &enrollment).unwrap();
        let entry_id = vault.credentials()[0].id;
        let data_key = vault.unlock_with(&entry_id, kek).unwrap();
        (vault, data_key)
    }

    fn session(clock: Arc<TestClock>, timeout: Option<Duration>) -> Session {
        Session::new(clock, timeout)
    }

    #[test]
    fn aliases_default_to_the_file_stem() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.fido");
        let (vault, data_key) = open_vault(&path);
        let lock = VaultLock::acquire(&path).unwrap();

        let mut session = session(TestClock::new(), None);
        let store = session.open(vault, data_key, lock, None).unwrap();
        assert_eq!(store.alias(), "tokens");
    }

    #[test]
    fn colliding_aliases_get_a_counter() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let mut session = session(TestClock::new(), None);

        for dir in [&first, &second] {
            let path = dir.path().join("tokens.fido");
            let (vault, data_key) = open_vault(&path);
            let lock = VaultLock::acquire(&path).unwrap();
            session.open(vault, data_key, lock, None).unwrap();
        }

        let aliases: Vec<&str> = session.stores().iter().map(|s| s.alias()).collect();
        assert_eq!(aliases, ["tokens", "tokens-2"]);
    }

    #[test]
    fn a_requested_alias_is_used() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.fido");
        let (vault, data_key) = open_vault(&path);
        let lock = VaultLock::acquire(&path).unwrap();

        let mut session = session(TestClock::new(), None);
        let store = session
            .open(vault, data_key, lock, Some("work".to_string()))
            .unwrap();
        assert_eq!(store.alias(), "work");
    }

    #[test]
    fn opening_the_same_vault_twice_is_rejected_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.fido");
        let (vault, data_key) = open_vault(&path);
        let lock = VaultLock::acquire(&path).unwrap();
        let mut session = session(TestClock::new(), None);
        session.open(vault, data_key.clone(), lock, None).unwrap();

        // Re-opening in the *same* session must say "already open as tokens",
        // not report the vault as busy with a lock this very process holds.
        let reopened = Vault::open(&path).unwrap();
        let lock = VaultLock::steal(&path).unwrap();
        match session.open(reopened, data_key, lock, None) {
            Err(SessionError::AlreadyOpen { alias, .. }) => assert_eq!(alias, "tokens"),
            other => panic!("expected AlreadyOpen, got {other:?}"),
        }
    }

    #[test]
    fn stores_resolve_by_alias_or_by_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.fido");
        let (vault, data_key) = open_vault(&path);
        let lock = VaultLock::acquire(&path).unwrap();
        let mut session = session(TestClock::new(), None);
        session.open(vault, data_key, lock, None).unwrap();

        assert!(session.get("tokens").is_ok());
        assert!(session.get(path.to_str().unwrap()).is_ok());
        assert!(matches!(
            session.get("nope"),
            Err(SessionError::NoSuchStore(_))
        ));
    }

    #[test]
    fn closing_releases_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.fido");
        let (vault, data_key) = open_vault(&path);
        let lock = VaultLock::acquire(&path).unwrap();
        let mut session = session(TestClock::new(), None);
        session.open(vault, data_key, lock, None).unwrap();

        assert!(crate::lock::holder(&path).is_some());
        drop(session.close("tokens").unwrap());
        assert!(
            crate::lock::holder(&path).is_none(),
            "closing a store must release its vault lock"
        );
        assert!(session.is_empty());
    }

    #[test]
    fn the_session_survives_a_store_being_closed_by_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.fido");
        let (vault, data_key) = open_vault(&path);
        let lock = VaultLock::acquire(&path).unwrap();
        let mut session = session(TestClock::new(), None);
        session.open(vault, data_key, lock, None).unwrap();

        let closed = session.close(path.to_str().unwrap()).unwrap();
        assert_eq!(closed.alias(), "tokens");
    }

    #[test]
    fn an_idle_store_expires_and_a_busy_one_does_not() {
        let clock = TestClock::new();
        let dir = tempfile::tempdir().unwrap();
        let mut session = session(clock.clone(), Some(Duration::from_secs(900)));

        for name in ["idle.fido", "busy.fido"] {
            let path = dir.path().join(name);
            let (vault, data_key) = open_vault(&path);
            let lock = VaultLock::acquire(&path).unwrap();
            session.open(vault, data_key, lock, None).unwrap();
        }

        clock.advance(Duration::from_secs(600));
        // Using a store is what holds its timeout off.
        session.get_mut("busy").unwrap();
        clock.advance(Duration::from_secs(600));

        let expired = session.expire();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].alias(), "idle");
        assert_eq!(session.stores().len(), 1);
        assert_eq!(session.stores()[0].alias(), "busy");
    }

    #[test]
    fn expiry_releases_the_expired_store_lock() {
        let clock = TestClock::new();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.fido");
        let (vault, data_key) = open_vault(&path);
        let lock = VaultLock::acquire(&path).unwrap();
        let mut session = session(clock.clone(), Some(Duration::from_secs(60)));
        session.open(vault, data_key, lock, None).unwrap();

        clock.advance(Duration::from_secs(61));
        let expired = session.expire();
        assert_eq!(expired.len(), 1);
        drop(expired);
        assert!(crate::lock::holder(&path).is_none());
    }

    #[test]
    fn a_disabled_timeout_never_expires() {
        let clock = TestClock::new();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.fido");
        let (vault, data_key) = open_vault(&path);
        let lock = VaultLock::acquire(&path).unwrap();
        let mut session = session(clock.clone(), None);
        session.open(vault, data_key, lock, None).unwrap();

        clock.advance(Duration::from_secs(365 * 24 * 60 * 60));
        assert!(session.expire().is_empty());
        assert!(session.next_expiry().is_none());
        assert!(session.expiring_within(Duration::from_secs(60)).is_empty());
    }

    #[test]
    fn the_warning_fires_before_the_expiry_does() {
        let clock = TestClock::new();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.fido");
        let (vault, data_key) = open_vault(&path);
        let lock = VaultLock::acquire(&path).unwrap();
        let mut session = session(clock.clone(), Some(Duration::from_secs(900)));
        session.open(vault, data_key, lock, None).unwrap();

        let warning = Duration::from_secs(60);
        assert!(session.expiring_within(warning).is_empty());

        clock.advance(Duration::from_secs(850));
        let warned = session.expiring_within(warning);
        assert_eq!(warned.len(), 1);
        assert_eq!(warned[0].0, "tokens");
        assert_eq!(warned[0].1, Duration::from_secs(50));
        // Warned, but still open: the warning must not itself close anything.
        assert!(session.expire().is_empty());
    }

    #[test]
    fn close_all_returns_stores_in_open_order() {
        let dir = tempfile::tempdir().unwrap();
        let mut session = session(TestClock::new(), None);
        for name in ["a.fido", "b.fido", "c.fido"] {
            let path = dir.path().join(name);
            let (vault, data_key) = open_vault(&path);
            let lock = VaultLock::acquire(&path).unwrap();
            session.open(vault, data_key, lock, None).unwrap();
        }

        let closed: Vec<String> = session
            .close_all()
            .iter()
            .map(|s| s.alias().to_string())
            .collect();
        assert_eq!(closed, ["a", "b", "c"]);
        assert!(session.is_empty());
    }

    #[test]
    fn a_cached_data_key_still_drives_the_vault() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.fido");
        let (vault, data_key) = open_vault(&path);
        let lock = VaultLock::acquire(&path).unwrap();
        let mut session = session(TestClock::new(), None);
        session.open(vault, data_key, lock, None).unwrap();

        // The point of the whole milestone: one unlock, many operations.
        let store = session.get_mut("tokens").unwrap();
        let (vault, data_key) = store.parts_mut();
        vault.kv_set(data_key, "github", b"token").unwrap();
        vault.kv_set(data_key, "gitlab", b"other").unwrap();

        let store = session.get("tokens").unwrap();
        assert_eq!(
            store.vault().kv_ls(store.data_key()).unwrap(),
            ["github", "gitlab"]
        );
        assert_eq!(
            &store.vault().kv_get(store.data_key(), "github").unwrap()[..],
            b"token"
        );
    }

    #[test]
    fn writes_through_a_session_are_durable_after_it_closes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.fido");
        let (vault, data_key) = open_vault(&path);
        let lock = VaultLock::acquire(&path).unwrap();
        let mut session = session(TestClock::new(), None);
        session.open(vault, data_key, lock, None).unwrap();

        let store = session.get_mut("tokens").unwrap();
        let (vault, data_key) = store.parts_mut();
        vault.kv_set(data_key, "github", b"token").unwrap();
        drop(session.close_all());

        // Re-open from scratch, as a separate process would.
        let (_, kek) = test_enrollment("fidostorers.local");
        let reopened = Vault::open(&path).unwrap();
        let entry_id = reopened.credentials()[0].id;
        let data_key = reopened.unlock_with(&entry_id, kek).unwrap();
        assert_eq!(&reopened.kv_get(&data_key, "github").unwrap()[..], b"token");
    }

    /// A dir vault, seeded with a tree, returned unlocked the way `open` would.
    fn open_dir_vault(path: &Path, files: &[(&str, &[u8])]) -> (Vault, Zeroizing<[u8; 32]>) {
        let (enrollment, kek) = test_enrollment("fidostorers.local");
        let mut vault = Vault::create(path, Mode::Dir, &enrollment).unwrap();
        let entry_id = vault.credentials()[0].id;
        let data_key = vault.unlock_with(&entry_id, kek).unwrap();

        let source = tempfile::tempdir().unwrap();
        for (name, contents) in files {
            let file = source.path().join(name);
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(file, contents).unwrap();
        }
        vault.seal_dir(&data_key, source.path()).unwrap();
        (vault, data_key)
    }

    #[test]
    fn opening_a_dir_store_extracts_it_and_closing_removes_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backup.fido");
        let (vault, data_key) = open_dir_vault(&path, &[("a.txt", b"one")]);
        let lock = VaultLock::acquire(&path).unwrap();
        let work = dir.path().join("work");

        let mut session = session(TestClock::new(), None);
        let (store, report) = session
            .open_with_work_dir(vault, data_key, lock, None, Some(&work))
            .unwrap();
        assert!(report.is_complete());
        assert_eq!(store.work_path(), Some(work.as_path()));
        assert_eq!(std::fs::read(work.join("a.txt")).unwrap(), b"one");

        drop(session.close("backup").unwrap());
        assert!(!work.exists(), "closing must remove the plaintext");
    }

    #[test]
    fn an_untouched_store_is_closed_without_writing_the_vault() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backup.fido");
        let (vault, data_key) = open_dir_vault(&path, &[("a.txt", b"one")]);
        let lock = VaultLock::acquire(&path).unwrap();
        let before = std::fs::read(&path).unwrap();

        let mut session = session(TestClock::new(), None);
        session
            .open_with_work_dir(vault, data_key, lock, None, Some(&dir.path().join("work")))
            .unwrap();

        let closed = session.close("backup").unwrap();
        assert!(!closed.sealed.unwrap(), "nothing changed, nothing written");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "an unchanged store must leave the vault byte-identical"
        );
    }

    #[test]
    fn an_edit_is_sealed_on_close_and_survives_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backup.fido");
        let (vault, data_key) = open_dir_vault(&path, &[("a.txt", b"one")]);
        let lock = VaultLock::acquire(&path).unwrap();
        let work = dir.path().join("work");

        let mut session = session(TestClock::new(), None);
        session
            .open_with_work_dir(vault, data_key, lock, None, Some(&work))
            .unwrap();
        std::fs::write(work.join("a.txt"), b"edited").unwrap();
        std::fs::write(work.join("added.txt"), b"new").unwrap();

        let closed = session.close("backup").unwrap();
        assert!(
            *closed.sealed.as_ref().unwrap(),
            "an edited store must be written"
        );
        drop(closed);

        // Reopen from scratch and confirm the vault really holds the edit.
        let (_, kek) = test_enrollment("fidostorers.local");
        let reopened = Vault::open(&path).unwrap();
        let entry_id = reopened.credentials()[0].id;
        let data_key = reopened.unlock_with(&entry_id, kek).unwrap();
        let restored = dir.path().join("restored");
        reopened.open_dir(&data_key, &restored).unwrap();
        assert_eq!(std::fs::read(restored.join("a.txt")).unwrap(), b"edited");
        assert_eq!(std::fs::read(restored.join("added.txt")).unwrap(), b"new");
    }

    #[test]
    fn seal_writes_without_closing_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backup.fido");
        let (vault, data_key) = open_dir_vault(&path, &[("a.txt", b"one")]);
        let lock = VaultLock::acquire(&path).unwrap();
        let work = dir.path().join("work");

        let mut session = session(TestClock::new(), None);
        session
            .open_with_work_dir(vault, data_key, lock, None, Some(&work))
            .unwrap();

        assert!(!session.seal("backup").unwrap(), "nothing to write yet");
        std::fs::write(work.join("a.txt"), b"edited").unwrap();
        assert!(session.seal("backup").unwrap(), "a checkpoint writes");
        assert!(
            !session.seal("backup").unwrap(),
            "sealing twice must not rewrite an unchanged store"
        );

        // And closing after an explicit seal has nothing left to do.
        assert!(!session.close("backup").unwrap().sealed.unwrap());
    }

    #[test]
    fn editing_a_working_directory_counts_as_activity() {
        let clock = TestClock::new();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backup.fido");
        let (vault, data_key) = open_dir_vault(&path, &[("a.txt", b"one")]);
        let lock = VaultLock::acquire(&path).unwrap();
        let work = dir.path().join("work");

        let mut session = session(clock.clone(), Some(Duration::from_secs(900)));
        session
            .open_with_work_dir(vault, data_key, lock, None, Some(&work))
            .unwrap();

        clock.advance(Duration::from_secs(800));
        // A user editing files in another window is working, not idle. Without
        // this, the tree would be sealed out from under their editor.
        std::fs::write(work.join("a.txt"), b"still working").unwrap();
        assert_eq!(session.note_external_activity(), ["backup"]);

        clock.advance(Duration::from_secs(800));
        assert!(
            session.expire().is_empty(),
            "the edit should have reset the countdown"
        );
        clock.advance(Duration::from_secs(200));
        assert_eq!(session.expire().len(), 1, "and then it expires as usual");
    }

    #[test]
    fn expiry_seals_before_it_drops_the_key() {
        let clock = TestClock::new();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backup.fido");
        let (vault, data_key) = open_dir_vault(&path, &[("a.txt", b"one")]);
        let lock = VaultLock::acquire(&path).unwrap();
        let work = dir.path().join("work");

        let mut session = session(clock.clone(), Some(Duration::from_secs(60)));
        session
            .open_with_work_dir(vault, data_key, lock, None, Some(&work))
            .unwrap();
        std::fs::write(work.join("a.txt"), b"edited just before stepping away").unwrap();

        clock.advance(Duration::from_secs(61));
        let expired = session.expire();
        assert_eq!(expired.len(), 1);
        assert!(
            expired[0].sealed.as_ref().unwrap(),
            "an idle timeout must not throw away unsaved work"
        );
        drop(expired);
        assert!(
            !work.exists(),
            "expiry is a full close, not just a dropped key"
        );
    }

    #[test]
    fn a_store_that_cannot_be_sealed_keeps_its_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backup.fido");
        let (vault, data_key) = open_dir_vault(&path, &[("a.txt", b"one")]);
        let lock = VaultLock::acquire(&path).unwrap();
        let work = dir.path().join("work");

        let mut session = session(TestClock::new(), None);
        session
            .open_with_work_dir(vault, data_key, lock, None, Some(&work))
            .unwrap();
        std::fs::write(work.join("a.txt"), b"edited").unwrap();

        // Make the write fail by removing the vault's directory out from under it.
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(crate::lock::lock_path(&path)).unwrap();
        std::fs::remove_dir_all(dir.path().join("restored")).ok();
        std::fs::create_dir_all(&path).unwrap(); // a directory where the file was

        let closed = session.close("backup").unwrap();
        assert!(closed.sealed.is_err(), "the seal should have failed");
        drop(closed);
        assert!(
            work.join("a.txt").exists(),
            "a failed seal must not delete the only copy of the user's changes"
        );
    }

    #[test]
    fn records_describe_the_stores_with_working_directories() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backup.fido");
        let (vault, data_key) = open_dir_vault(&path, &[("a.txt", b"one")]);
        let lock = VaultLock::acquire(&path).unwrap();
        let work = dir.path().join("work");

        let mut session = session(TestClock::new(), None);
        session
            .open_with_work_dir(vault, data_key, lock, None, Some(&work))
            .unwrap();

        // A kv store has no working directory and so nothing to recover.
        let kv_path = dir.path().join("tokens.fido");
        let (kv_vault, kv_key) = open_vault(&kv_path);
        let kv_lock = VaultLock::acquire(&kv_path).unwrap();
        session.open(kv_vault, kv_key, kv_lock, None).unwrap();

        let records = session.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].alias, "backup");
        assert_eq!(records[0].work, work);
    }

    #[test]
    fn default_alias_falls_back_when_a_path_has_no_stem() {
        assert_eq!(default_alias(Path::new("tokens.fido")), "tokens");
        assert_eq!(default_alias(Path::new("/a/b/backup.fido")), "backup");
        assert_eq!(default_alias(Path::new("noext")), "noext");
        assert_eq!(default_alias(Path::new("/")), "store");
    }
}
