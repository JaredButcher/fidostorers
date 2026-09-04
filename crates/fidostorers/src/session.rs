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

use crate::lock::VaultLock;
use crate::{Vault, VaultError};

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
#[derive(Debug)]
pub struct Store {
    alias: String,
    vault: Vault,
    data_key: Zeroizing<[u8; 32]>,
    last_activity: Instant,
    /// Held for as long as the store is open, so a second session — and any
    /// one-shot command that writes — refuses rather than racing us.
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

    pub fn data_key(&self) -> &Zeroizing<[u8; 32]> {
        &self.data_key
    }

    /// Mutable vault and its data key together.
    ///
    /// Every mutating `Vault` method needs both at once, and taking them through
    /// two accessors would borrow `self` mutably and immutably at the same call.
    pub fn parts_mut(&mut self) -> (&mut Vault, &Zeroizing<[u8; 32]>) {
        (&mut self.vault, &self.data_key)
    }

    pub fn idle_for(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.last_activity)
    }
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
        self.stores.push(Store {
            alias,
            vault,
            data_key,
            last_activity: self.clock.now(),
            _lock: lock,
        });
        Ok(self.stores.last().expect("just pushed"))
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

    /// Close one store, returning it so the caller can report on it. Dropping the
    /// returned value zeroizes the data key and releases the lock.
    pub fn close(&mut self, name: &str) -> Result<Store, SessionError> {
        let index = self.resolve(name)?;
        Ok(self.stores.remove(index))
    }

    /// Close every store, in the order they were opened.
    pub fn close_all(&mut self) -> Vec<Store> {
        std::mem::take(&mut self.stores)
    }

    /// Close every store that has been idle past the timeout.
    ///
    /// Expiry is a *full* close rather than merely dropping the key: from M10 a
    /// store also owns a plaintext working directory, and reporting "locked" while
    /// that directory stayed readable would be a lie. Doing the full close here
    /// keeps that the only meaning "expired" ever has.
    pub fn expire(&mut self) -> Vec<Store> {
        let Some(timeout) = self.idle_timeout else {
            return Vec::new();
        };
        let now = self.clock.now();
        let mut expired = Vec::new();
        let mut index = 0;
        while index < self.stores.len() {
            if self.stores[index].idle_for(now) >= timeout {
                expired.push(self.stores.remove(index));
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

    #[test]
    fn default_alias_falls_back_when_a_path_has_no_stem() {
        assert_eq!(default_alias(Path::new("tokens.fido")), "tokens");
        assert_eq!(default_alias(Path::new("/a/b/backup.fido")), "backup");
        assert_eq!(default_alias(Path::new("noext")), "noext");
        assert_eq!(default_alias(Path::new("/")), "store");
    }
}
