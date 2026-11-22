//! Reverse DNS that never blocks the sample loop.
//!
//! The loop used to fork `getent hosts <ip>` inline, once per uncached
//! address. `getent` has no timeout of its own, so an unresponsive resolver
//! stalled every poll for as long as `resolv.conf` allowed, once per IP; a
//! per-pass budget only bounded how many of those stalls one pass could take.
//!
//! Lookups now run in-process (`getnameinfo` with `NI_NAMEREQD`, the same
//! hosts database `getent hosts` reads) on worker threads. The loop asks for a
//! name, gets one only if it is already known, and otherwise queues the
//! address and moves on; finished lookups are collected on a later pass. A
//! resolver that never answers costs the loop nothing but names that arrive
//! late.
//!
//! Only a definite answer is cached: a name, or `EAI_NONAME` (the address has
//! none). Any other failure, `EAI_AGAIN` from a resolver timeout above all, says
//! nothing about the address, so it is asked about again after [`RETRY_AFTER`].
//! Caching those as "no name" blanked a named host for the daemon's lifetime
//! after one resolver hiccup (measured 2026-10-10: 2 of 8 PTR-bearing peers).
//! musl's `getnameinfo` reports a timed-out reverse lookup as `EAI_NONAME` under
//! `NI_NAMEREQD`, so a musl build cannot tell the two apart and still caches it.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::mpsc::{self, Receiver, Sender, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Worker threads. Two keeps one hung lookup from starving the rest without
/// fanning a fresh backlog out into a burst of concurrent queries.
pub const WORKERS: usize = 2;
/// Addresses waiting for a worker. A full queue drops the request; the caller
/// asks again on a later pass.
pub const QUEUE: usize = 256;
/// How long an address whose lookup failed transiently waits before it is
/// asked about again. Long enough that a dead resolver is not hammered.
pub const RETRY_AFTER: Duration = Duration::from_secs(60);

/// A lookup that could not tell whether the address has a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transient;

/// `Ok(Some(name))`, `Ok(None)` for an address with no name, or `Err(Transient)`.
pub type Lookup = Arc<dyn Fn(IpAddr) -> Result<Option<String>, Transient> + Send + Sync>;

pub struct Resolver {
    /// Answered lookups. An empty string is a lookup that found no name; it is
    /// cached too, so a nameless address is asked about once.
    names: HashMap<IpAddr, String>,
    inflight: HashSet<IpAddr>,
    /// Addresses whose last lookup failed transiently, and when they may be
    /// asked about again.
    retry_at: HashMap<IpAddr, Instant>,
    retry_after: Duration,
    /// `None` when lookups are disabled.
    queue: Option<SyncSender<IpAddr>>,
    done: Receiver<(IpAddr, Result<String, Transient>)>,
}

impl Resolver {
    /// Lookups through the host's resolver.
    pub fn system() -> Self {
        Self::spawn(WORKERS, QUEUE, Arc::new(ptr_lookup))
    }

    /// Lookups through `lookup` on `workers` threads.
    pub fn spawn(workers: usize, queue: usize, lookup: Lookup) -> Self {
        let (tx, rx) = mpsc::sync_channel::<IpAddr>(queue);
        let (done_tx, done) = mpsc::channel();
        let rx = Arc::new(Mutex::new(rx));
        let mut started = 0;
        for i in 0..workers {
            let rx = Arc::clone(&rx);
            let done_tx: Sender<(IpAddr, Result<String, Transient>)> = done_tx.clone();
            let lookup = Arc::clone(&lookup);
            let spawned = std::thread::Builder::new()
                .name(format!("kub0d-rdns-{i}"))
                .spawn(move || loop {
                    // Hold the lock only while waiting for work, never across
                    // a lookup, so a hung lookup blocks one worker, not all.
                    let next = rx.lock().ok().and_then(|r| r.recv().ok());
                    let Some(ip) = next else { return };
                    let answer = lookup(ip).map(Option::unwrap_or_default);
                    if done_tx.send((ip, answer)).is_err() {
                        return;
                    }
                });
            if spawned.is_ok() {
                started += 1;
            }
        }
        if started == 0 {
            eprintln!("kub0d: no reverse-DNS worker could start; hostnames stay empty");
            return Self::disabled();
        }
        Self {
            names: HashMap::new(),
            inflight: HashSet::new(),
            retry_at: HashMap::new(),
            retry_after: RETRY_AFTER,
            queue: Some(tx),
            done,
        }
    }

    /// Never looks anything up: every address is known to have no name.
    pub fn disabled() -> Self {
        let (_, done) = mpsc::channel();
        Self {
            names: HashMap::new(),
            inflight: HashSet::new(),
            retry_at: HashMap::new(),
            retry_after: RETRY_AFTER,
            queue: None,
            done,
        }
    }

    /// The name for `ip` if one is already known, without waiting.
    ///
    /// `Some("")` means the lookup finished and found no name (or lookups are
    /// disabled). `None` means not yet: a lookup is queued or in flight, or the
    /// last one failed transiently and the address waits out its retry delay.
    /// Never blocks.
    pub fn name(&mut self, ip: IpAddr) -> Option<&str> {
        if self.names.contains_key(&ip) {
            return self.names.get(&ip).map(String::as_str);
        }
        if let Some(at) = self.retry_at.get(&ip) {
            if Instant::now() < *at {
                return None;
            }
            self.retry_at.remove(&ip);
        }
        let Some(queue) = &self.queue else {
            return Some("");
        };
        if !self.inflight.contains(&ip) {
            match queue.try_send(ip) {
                Ok(()) => {
                    self.inflight.insert(ip);
                }
                // Full: ask again later. Disconnected: every worker is gone,
                // so stop asking.
                Err(TrySendError::Full(_)) => {}
                Err(TrySendError::Disconnected(_)) => {
                    self.queue = None;
                    return Some("");
                }
            }
        }
        None
    }

    /// Move finished lookups into the cache. Returns how many settled.
    pub fn collect(&mut self) -> usize {
        let mut n = 0;
        while let Ok((ip, answer)) = self.done.try_recv() {
            self.inflight.remove(&ip);
            match answer {
                Ok(name) => {
                    self.names.insert(ip, name);
                }
                Err(Transient) => {
                    self.retry_at.insert(ip, Instant::now() + self.retry_after);
                }
            }
            n += 1;
        }
        n
    }

    pub fn inflight(&self) -> usize {
        self.inflight.len()
    }
}

/// One PTR lookup through the C library's resolver: `/etc/hosts`, NSS and DNS
/// on glibc, `/etc/hosts` and `resolv.conf` on musl.
pub fn ptr_lookup(ip: IpAddr) -> Result<Option<String>, Transient> {
    let mut host = [0 as libc::c_char; 1025];
    // SAFETY: each sockaddr is zero-initialised and fully describes `ip`, its
    // length is passed alongside it, and `host` is a writable buffer whose
    // length is passed too. No service buffer is requested.
    let rc = unsafe {
        match ip {
            IpAddr::V4(v4) => {
                let mut sa: libc::sockaddr_in = std::mem::zeroed();
                sa.sin_family = libc::AF_INET as libc::sa_family_t;
                sa.sin_addr.s_addr = u32::from_ne_bytes(v4.octets());
                #[cfg(target_vendor = "apple")]
                {
                    sa.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
                }
                libc::getnameinfo(
                    &sa as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    host.as_mut_ptr(),
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
            IpAddr::V6(v6) => {
                let mut sa: libc::sockaddr_in6 = std::mem::zeroed();
                sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                sa.sin6_addr.s6_addr = v6.octets();
                #[cfg(target_vendor = "apple")]
                {
                    sa.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
                }
                libc::getnameinfo(
                    &sa as *const libc::sockaddr_in6 as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    host.as_mut_ptr(),
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
        }
    };
    if rc != 0 {
        return answer(rc, "");
    }
    // SAFETY: getnameinfo NUL-terminates `host` on success.
    let name = unsafe { std::ffi::CStr::from_ptr(host.as_ptr()) }.to_string_lossy();
    answer(rc, &name)
}

/// What a `getnameinfo` return code and host buffer say about the address.
/// Only `EAI_NONAME` means it has no name; every other error is transient.
fn answer(rc: libc::c_int, host: &str) -> Result<Option<String>, Transient> {
    match rc {
        0 => {
            let name = host.trim().trim_end_matches('.');
            Ok((!name.is_empty()).then(|| name.to_string()))
        }
        libc::EAI_NONAME => Ok(None),
        _ => Err(Transient),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([198, 51, 100, n])
    }

    fn settle(r: &mut Resolver, want: usize) {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut got = 0;
        while got < want && Instant::now() < deadline {
            got += r.collect();
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(got, want, "lookups did not settle");
    }

    #[test]
    fn a_hung_resolver_never_blocks_the_caller() {
        // Every lookup takes far longer than a sample interval.
        let mut r = Resolver::spawn(
            2,
            QUEUE,
            Arc::new(|_| {
                std::thread::sleep(Duration::from_secs(3));
                Ok(Some("slow.example".into()))
            }),
        );
        let t0 = Instant::now();
        for n in 0..100 {
            assert_eq!(r.name(ip(n)), None);
        }
        // Asking again for the same address queues nothing new.
        assert_eq!(r.name(ip(0)), None);
        assert_eq!(r.inflight(), 100);
        assert!(
            t0.elapsed() < Duration::from_millis(200),
            "100 uncached lookups held the caller for {:?}",
            t0.elapsed()
        );
    }

    #[test]
    fn names_arrive_on_a_later_pass_and_are_cached() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        let mut r = Resolver::spawn(
            1,
            QUEUE,
            Arc::new(move |ip| {
                seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                match ip {
                    IpAddr::V4(v) if v.octets()[3] == 1 => Ok(Some("one.example".into())),
                    _ => Ok(None),
                }
            }),
        );
        assert_eq!(r.name(ip(1)), None);
        assert_eq!(r.name(ip(2)), None);
        settle(&mut r, 2);
        assert_eq!(r.name(ip(1)), Some("one.example"));
        // No name is an answer too, and is not asked again.
        assert_eq!(r.name(ip(2)), Some(""));
        assert_eq!(r.name(ip(2)), Some(""));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(r.inflight(), 0);
    }

    #[test]
    fn a_full_queue_drops_the_request_and_asks_again_later() {
        let gate = Arc::new(Mutex::new(()));
        let held = gate.lock().unwrap();
        let wait = Arc::clone(&gate);
        let mut r = Resolver::spawn(
            1,
            1,
            Arc::new(move |_| {
                let _g = wait.lock().unwrap();
                Ok(Some("late.example".into()))
            }),
        );
        // One taken by the worker (blocked), one in the queue, the rest refused.
        for n in 0..4 {
            assert_eq!(r.name(ip(n)), None);
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(r.inflight() < 4, "a full queue must not record a lookup it dropped");
        drop(held);
        let queued = r.inflight();
        settle(&mut r, queued);
        for n in 0..4 {
            while r.name(ip(n)).is_none() {
                settle(&mut r, 1);
            }
            assert_eq!(r.name(ip(n)), Some("late.example"));
        }
    }

    #[test]
    fn disabled_lookups_answer_no_name_at_once() {
        let mut r = Resolver::disabled();
        assert_eq!(r.name(ip(1)), Some(""));
        assert_eq!(r.inflight(), 0);
    }

    #[test]
    fn a_transient_failure_is_asked_again_and_never_cached_as_no_name() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        let mut r = Resolver::spawn(
            1,
            QUEUE,
            Arc::new(move |_| {
                // First answer: the resolver timed out. Second: the name.
                if seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                    Err(Transient)
                } else {
                    Ok(Some("back.example".into()))
                }
            }),
        );
        r.retry_after = Duration::from_millis(300);
        assert_eq!(r.name(ip(7)), None);
        settle(&mut r, 1);
        // Not "no name", and not asked again inside the retry delay.
        assert_eq!(r.name(ip(7)), None);
        assert_eq!(r.inflight(), 0);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        std::thread::sleep(Duration::from_millis(400));
        assert_eq!(r.name(ip(7)), None, "asked again after the delay");
        assert_eq!(r.inflight(), 1);
        settle(&mut r, 1);
        assert_eq!(r.name(ip(7)), Some("back.example"));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[test]
    fn only_eai_noname_means_no_name() {
        assert_eq!(answer(0, "host.example."), Ok(Some("host.example".into())));
        assert_eq!(answer(0, " "), Ok(None));
        assert_eq!(answer(libc::EAI_NONAME, ""), Ok(None));
        for rc in [
            libc::EAI_AGAIN,
            libc::EAI_FAIL,
            libc::EAI_SYSTEM,
            libc::EAI_MEMORY,
        ] {
            assert_eq!(answer(rc, ""), Err(Transient), "rc {rc}");
        }
    }

    /// The old path's answer for `ip`: the canonical name `getent hosts` prints.
    fn getent(ip: IpAddr) -> Option<String> {
        let out = std::process::Command::new("getent")
            .args(["hosts", &ip.to_string()])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        text.split_whitespace().nth(1).map(str::to_string)
    }

    #[test]
    fn the_in_process_lookup_agrees_with_getent_on_loopback() {
        // Loopback answers from the local hosts database without touching
        // the network. A wrong sockaddr (byte order, family, length) would
        // ask about a different address and disagree here.
        let mut checked = 0;
        for addr in [IpAddr::from([127, 0, 0, 1]), "::1".parse().unwrap()] {
            let Some(want) = getent(addr) else { continue };
            assert_eq!(ptr_lookup(addr), Ok(Some(want.clone())), "{addr}");
            checked += 1;
        }
        if checked == 0 {
            eprintln!("skipped: no getent answer for loopback on this host");
        }
    }
}
