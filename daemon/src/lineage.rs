//! Where a process came from: its ancestors, its command line, its working
//! directory. Read once per new connection from `/proc`, attached to the
//! row's evidence, never used to name an app.
//!
//! App identity stays the exe path (`docs/SCHEMA.md` 2.1). Lineage is the
//! context that makes an identity readable: `curl` from `/tmp` is one thing,
//! `curl` from `/tmp` whose parent is a browser's content process is another,
//! and only the chain says which. The chain is capped so a fork bomb or a
//! deep container init does not turn one row into a page.

use serde::{Deserialize, Serialize};

/// Ancestors kept, the process itself excluded. Eight reaches `systemd --user`
/// from any desktop app on this machine with room to spare.
pub const MAX_ANCESTORS: usize = 8;
/// Command lines longer than this are cut with an ellipsis. Long enough for a
/// browser's content process; short enough that an argument carrying a
/// document never bloats history.
pub const CMDLINE_MAX: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ancestor {
    pub pid: u32,
    pub comm: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub exe: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Lineage {
    /// Parent first, then grandparent, up to [`MAX_ANCESTORS`]. Empty for pid 1.
    pub ancestors: Vec<Ancestor>,
    /// Arguments joined by single spaces, cut at [`CMDLINE_MAX`].
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cmdline: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cwd: String,
    /// The chain stopped before pid 1: an ancestor vanished or was unreadable.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

/// Parent pid from the text of `/proc/<pid>/stat`. The comm field is
/// parenthesised and may itself contain spaces and parentheses, so the split
/// is after the last `)`.
pub fn parse_ppid(stat: &str) -> Option<u32> {
    let after = stat.get(stat.rfind(')')? + 1..)?;
    after.split_whitespace().nth(1)?.parse().ok()
}

/// `/proc/<pid>/cmdline` is NUL-separated; render it for a person.
pub fn render_cmdline(raw: &[u8]) -> String {
    let parts: Vec<String> = raw
        .split(|b| *b == 0)
        .filter(|p| !p.is_empty())
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .collect();
    let mut s = parts.join(" ");
    if s.chars().count() > CMDLINE_MAX {
        s = s.chars().take(CMDLINE_MAX).collect::<String>() + "…";
    }
    s
}

/// Read the lineage of a live process. Every read is best effort: a process
/// that exits mid-walk gives a truncated chain, never an error. `None` where
/// there is no `/proc` (macOS): an empty chain there would claim `truncated`,
/// that an ancestor had gone, when nothing was ever readable.
pub fn read(pid: u32) -> Option<Lineage> {
    if pid == 0 || !cfg!(target_os = "linux") {
        return None;
    }
    let mut out = Lineage {
        cmdline: std::fs::read(format!("/proc/{pid}/cmdline"))
            .map(|b| render_cmdline(&b))
            .unwrap_or_default(),
        cwd: std::fs::read_link(format!("/proc/{pid}/cwd"))
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default(),
        ..Default::default()
    };
    let mut cur = pid;
    while out.ancestors.len() < MAX_ANCESTORS {
        let Some(stat) = std::fs::read_to_string(format!("/proc/{cur}/stat")).ok() else {
            out.truncated = true;
            break;
        };
        let Some(ppid) = parse_ppid(&stat) else {
            out.truncated = true;
            break;
        };
        if ppid == 0 {
            break;
        }
        out.ancestors.push(Ancestor {
            pid: ppid,
            comm: crate::identity::read_comm(ppid),
            exe: crate::identity::read_exe(ppid),
        });
        if ppid == 1 {
            break;
        }
        cur = ppid;
    }
    if out.ancestors.len() == MAX_ANCESTORS && out.ancestors.last().is_some_and(|a| a.pid != 1) {
        out.truncated = true;
    }
    Some(out)
}

/// One line for a person: `bash ← kitty ← systemd`.
pub fn summary(l: &Lineage) -> String {
    let mut s = l
        .ancestors
        .iter()
        .map(|a| if a.comm.is_empty() { a.pid.to_string() } else { a.comm.clone() })
        .collect::<Vec<_>>()
        .join(" ← ");
    if l.truncated {
        s.push_str(" ← …");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ppid_survives_a_hostile_comm() {
        assert_eq!(parse_ppid("42 (bash) S 7 42 42 0 -1 4194560"), Some(7));
        assert_eq!(parse_ppid("42 (a) b) S 7 42"), Some(7), "parentheses in comm");
        assert_eq!(parse_ppid("42 (sp ace) S 7 42"), Some(7), "space in comm");
        assert_eq!(parse_ppid("garbage"), None);
        assert_eq!(parse_ppid("42 (bash)"), None, "truncated right after comm: no panic");
        assert_eq!(parse_ppid("42 (bash) "), None);
        assert_eq!(parse_ppid(")"), None);
        assert_eq!(parse_ppid("1 (systemd) S 0 1"), Some(0));
    }

    #[test]
    fn cmdline_renders_and_caps() {
        assert_eq!(render_cmdline(b"curl\0-s\0https://x\0"), "curl -s https://x");
        assert_eq!(render_cmdline(b""), "");
        let long = vec![b'a'; CMDLINE_MAX + 50];
        let r = render_cmdline(&long);
        assert_eq!(r.chars().count(), CMDLINE_MAX + 1);
        assert!(r.ends_with('…'));
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn no_lineage_without_proc() {
        assert!(read(std::process::id()).is_none(), "not an empty chain claiming truncated");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn our_own_lineage_reads_up_to_init() {
        let l = read(std::process::id()).expect("own pid");
        assert!(!l.ancestors.is_empty(), "a test has a parent");
        assert!(l.cmdline.contains("kub0d") || !l.cmdline.is_empty());
        assert!(!l.cwd.is_empty());
        assert!(l.ancestors.len() <= MAX_ANCESTORS);
        let s = summary(&l);
        assert!(!s.is_empty());
        assert!(read(0).is_none());
        assert!(read(u32::MAX).is_some_and(|l| l.truncated && l.ancestors.is_empty()), "a missing pid is a truncated chain, not a panic");
    }
}
