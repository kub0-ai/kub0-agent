//! Guarded reads for files vallum does not own.
//!
//! Ported from omasnatch's `collector.py` (weedwhitesandwine, MIT) — see
//! `THIRD-PARTY.md` section 2. The techniques are not novel and a clean
//! reimplementation would owe nothing, but these were read before they were
//! written, so they are credited.
//!
//! Everything here reads configuration and databases that belong to OpenSnitch,
//! and whose paths come out of a config file rather than out of vallum. A
//! restored backup, a dotfile manager, or a hostile `settings.conf` can leave
//! anything at all at those paths.

use std::fs::File;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// A read-only SQLite file URI for a path that came out of someone else's
/// config.
///
/// The path is percent-encoded, so a value containing `?` cannot append its own
/// URI parameters. Without this, a `settings.conf` naming
/// `/tmp/x.db?mode=rwc` would defeat the read-only open, and vallum would hold
/// a writable handle on OpenSnitch's database — which is the one thing this
/// integration must never do.
pub fn ro_uri(path: &Path) -> String {
    let mut out = String::from("file:");
    for b in path.to_string_lossy().as_bytes() {
        match b {
            // RFC 3986 unreserved, plus the separators a filesystem path needs
            // to survive intact. Everything else, `?` and `#` above all, is
            // encoded.
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out.push_str("?mode=ro");
    out
}

/// Read a file to a ceiling, or `None`.
///
/// One reader for every file vallum reads back that it did not write:
///
/// * the path is resolved first, so a dotfile-managed symlink still reads;
/// * the resolved path is opened non-blocking and the *file descriptor* is
///   stat'd for regular-file-ness, so a planted FIFO cannot park the read
///   forever — the check is on what was actually opened, not on what the path
///   pointed at a moment earlier;
/// * one byte past the ceiling is requested, so an oversized file is refused
///   rather than loaded whole.
///
/// Every failure is `None`, and every caller treats `None` as "not configured".
/// There is no error path that is worth telling a user about here: the file
/// belonging to another program being absent, unreadable, or absurd are all the
/// same situation from vallum's side.
pub fn read_capped(path: &Path, ceiling: usize) -> Option<String> {
    read_guarded(path, ceiling, None)
}

/// `read_capped` for a file in another account's home, read by a daemon that
/// is root: the file that was opened must also belong to `owner`.
///
/// Root can open anything, and the path is the other account's to choose. A
/// link there to a file only root may read would otherwise have root read it
/// on that account's behalf. A file the account owns is one it could read
/// itself. The price is that an entry linked in from a root-owned store (a
/// package manager's, say) is not read; the shared directories name those.
pub fn read_capped_owned(path: &Path, ceiling: usize, owner: u32) -> Option<String> {
    read_guarded(path, ceiling, Some(owner))
}

fn read_guarded(path: &Path, ceiling: usize, owner: Option<u32>) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let real = std::fs::canonicalize(path).ok()?;
    let file = File::options()
        .read(true)
        // O_NOCTTY: a terminal opened by a daemon that has none must not
        // become its controlling terminal.
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(real)
        .ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || owner.is_some_and(|uid| meta.uid() != uid) {
        return None;
    }
    let mut buf = Vec::with_capacity(ceiling.min(64 * 1024) + 1);
    file.take(ceiling as u64 + 1).read_to_end(&mut buf).ok()?;
    if buf.len() > ceiling {
        return None;
    }
    String::from_utf8(buf).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("vallum-fileguard-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn uri_encodes_query_injection() {
        // The canary. If this ever passes a bare `?`, the read-only guarantee
        // is gone and the test that proves it is gone is this one.
        let u = ro_uri(Path::new("/home/alice/x.db?mode=rwc"));
        assert!(u.ends_with("?mode=ro"), "{u}");
        // `=` is encoded too, so the injected parameter cannot even be read as
        // a key/value pair. Stricter than it needs to be, deliberately.
        assert!(u.contains("%3Fmode%3Drwc"), "{u}");
        assert_eq!(u.matches('?').count(), 1, "{u}");
    }

    #[test]
    fn uri_keeps_ordinary_paths_readable() {
        assert_eq!(
            ro_uri(Path::new("/home/alice/.config/opensnitch/db.sqlite")),
            "file:/home/alice/.config/opensnitch/db.sqlite?mode=ro"
        );
    }

    #[test]
    fn uri_encodes_fragment_and_space() {
        let u = ro_uri(Path::new("/tmp/a b#c"));
        assert!(u.contains("%20"), "{u}");
        assert!(u.contains("%23"), "{u}");
    }

    #[test]
    fn capped_read_refuses_oversize_without_loading_it() {
        let d = tmpdir("cap");
        let p = d.join("big");
        File::create(&p)
            .unwrap()
            .write_all(&vec![b'x'; 4096])
            .unwrap();
        assert!(read_capped(&p, 4095).is_none());
        assert_eq!(read_capped(&p, 4096).unwrap().len(), 4096);
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn capped_read_follows_a_symlink_to_a_regular_file() {
        let d = tmpdir("link");
        let target = d.join("real");
        File::create(&target).unwrap().write_all(b"ok").unwrap();
        let link = d.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(read_capped(&link, 64).as_deref(), Some("ok"));
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn capped_read_refuses_a_fifo_instead_of_hanging() {
        let d = tmpdir("fifo");
        let p = d.join("pipe");
        let c = std::ffi::CString::new(p.to_str().unwrap()).unwrap();
        // SAFETY: a path we just created a directory for; mkfifo only creates.
        let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo failed");
        // Without O_NONBLOCK this call never returns: opening a FIFO for
        // reading blocks until a writer arrives, and nothing is ever going to
        // write. A test suite that hangs is how you find out you removed it.
        assert!(read_capped(&p, 64).is_none());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn owned_read_refuses_a_file_that_is_someone_elses() {
        use std::os::unix::fs::MetadataExt;
        let d = tmpdir("owned");
        let p = d.join("mine");
        File::create(&p).unwrap().write_all(b"ok").unwrap();
        let me = std::fs::metadata(&p).unwrap().uid();
        assert_eq!(read_capped_owned(&p, 64, me).as_deref(), Some("ok"));
        // The same bytes, asked for on behalf of an account that does not own them.
        assert!(read_capped_owned(&p, 64, me.wrapping_add(1)).is_none());
        // Ownership is the opened file's, not the link's: a link of mine to
        // a file that is not mine is still not mine.
        let link = d.join("link");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert_eq!(read_capped_owned(&link, 64, me).as_deref(), Some("ok"));
        assert!(read_capped_owned(&link, 64, me.wrapping_add(1)).is_none());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn capped_read_refuses_a_device_without_reading_it() {
        // /dev/zero never ends; a plain read of it fills memory.
        assert!(read_capped(Path::new("/dev/zero"), 64).is_none());
        assert!(read_capped_owned(Path::new("/dev/zero"), 64, 0).is_none());
    }

    #[test]
    fn capped_read_refuses_a_directory() {
        let d = tmpdir("dir");
        assert!(read_capped(&d, 64).is_none());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn missing_path_is_none_not_an_error() {
        assert!(read_capped(Path::new("/nonexistent/vallum/nope"), 64).is_none());
    }
}
