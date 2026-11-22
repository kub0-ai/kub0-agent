//! Persisted labels for network keys, and the fleet vote that decides when
//! someone else's tag is worth offering on this host.
//!
//! `suggest` names a connection from evidence already on the row. The rest --
//! measured 123 of 457 unknowns on one live desktop -- a person tags by hand.
//! This module holds those tags, and scores reports from other org nodes so a
//! second host can be offered a name instead of a blank.
//!
//! Two properties keep that offer honest:
//!
//! * Quorum counts **distinct nodes**, never reports. A node submitting the
//!   same label ten times is one opinion. Counting reports scores the loudest
//!   host, not the truest one, and a single chatty or compromised machine
//!   could name anything it likes for the whole org.
//! * A fleet tag never yields [`Confidence::Certain`]. Certain means a local
//!   authority was consulted -- `/etc/passwd`, the loopback range. Other
//!   people's claims cap at Strong. That distinction is why the ladder can be
//!   trusted.

use crate::suggest::{Confidence, Kind};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Who wrote the tag. Serde lowercase so the file reads `"user"` / `"fleet"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    User,
    Fleet,
}

/// One label for one network key, as stored on disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tag {
    pub network_key: String,
    pub label: String,
    pub kind: Kind,
    pub ptr_suffix: String,
    pub ts: u64,
    pub source: Source,
}

/// JSON document at `<state_dir>/tags.json`.
///
/// A missing or corrupt file loads as empty and never panics: a daemon that
/// refuses to start because one state file is malformed is worse than a
/// daemon with no tags.
pub struct TagStore {
    path: PathBuf,
    tags: HashMap<String, Tag>,
}

impl TagStore {
    pub fn load(state_dir: &Path) -> Self {
        let path = state_dir.join("tags.json");
        let tags = std::fs::read_to_string(&path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        Self { path, tags }
    }

    pub fn save(&self) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = serde_json::to_string_pretty(&self.tags)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    pub fn get(&self, network_key: &str) -> Option<&Tag> {
        self.tags.get(network_key)
    }

    pub fn set(&mut self, tag: Tag) {
        self.tags.insert(tag.network_key.clone(), tag);
    }

    pub fn remove(&mut self, network_key: &str) -> Option<Tag> {
        self.tags.remove(network_key)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Tag> {
        self.tags.values()
    }
}

/// One org node claim as it arrives from the API.
///
/// `kind` and `ptr_suffix` travel with the report so a scored tag can be
/// applied on another host. They are not votes: [`score`] still keys only on
/// `network_key`, `label`, and `node`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetReport {
    pub network_key: String,
    pub label: String,
    pub node: String,
    pub kind: Kind,
    pub ptr_suffix: String,
}

/// A label that survived quorum: enough distinct nodes, and enough of them
/// agreed, that it is worth offering on another host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetTag {
    pub label: String,
    pub agreeing: usize,
    pub reporters: usize,
}

/// Score reports for one network key.
///
/// Returns `Some` only when `agreeing >= 2` and `agreeing / reporters >= 0.6`.
/// One node is one opinion -- on a second host that is hearsay, not collective
/// knowledge. A three-three split has settled nothing and must surface nothing.
///
/// Each node votes once. Last label from that node for this key wins, so a
/// host that changes its mind is not counted twice, and a host that repeats
/// itself is not a quorum.
pub fn score(reports: &[FleetReport], network_key: &str) -> Option<FleetTag> {
    let mut by_node: HashMap<&str, &str> = HashMap::new();
    for r in reports {
        if r.network_key == network_key {
            by_node.insert(r.node.as_str(), r.label.as_str());
        }
    }
    let reporters = by_node.len();
    if reporters == 0 {
        return None;
    }

    let mut counts: HashMap<&str, usize> = HashMap::new();
    for label in by_node.values() {
        *counts.entry(*label).or_insert(0) += 1;
    }
    let (&label, &agreeing) = counts.iter().max_by_key(|(_, n)| *n)?;

    // 0.6 is 3/5. Integer compare so 3-of-5 is in and 3-of-6 is out, with no
    // f64 rounding of a threshold the comments treat as exact.
    if agreeing >= 2 && agreeing.saturating_mul(5) >= reporters.saturating_mul(3) {
        Some(FleetTag {
            label: label.to_string(),
            agreeing,
            reporters,
        })
    } else {
        None
    }
}

/// Provenance of a fleet tag, given the PTR stored with it and the PTR this
/// host sees now.
///
/// Strong when `tag_ptr_suffix` is empty (nothing to corroborate) or is a
/// suffix of `local_ptr`. Weak when both are non-empty and disagree: a key
/// whose reverse DNS changed since it was tagged may have been reassigned, so
/// the stored label is stale evidence rather than a current fact.
///
/// Never Certain. That is the whole reason the ladder can be trusted.
pub fn fleet_confidence(tag: &FleetTag, tag_ptr_suffix: &str, local_ptr: &str) -> Confidence {
    // Vote size already gated `score`. A unanimous fleet is still other people.
    let _ = tag;
    if ptr_corroborates(tag_ptr_suffix, local_ptr) {
        Confidence::Strong
    } else {
        Confidence::Weak
    }
}

/// Empty stored suffix is "no PTR to check" -- not a disagreement.
/// Otherwise the stored suffix must be the local name, or a trailing label of
/// it (`tailscale.com` vs `derp15c.tailscale.com`). A bare `ends_with` would
/// let `scale.com` corroborate `tailscale.com`.
fn ptr_corroborates(tag_ptr_suffix: &str, local_ptr: &str) -> bool {
    let tag = tag_ptr_suffix.trim_end_matches('.').to_ascii_lowercase();
    if tag.is_empty() {
        return true;
    }
    let local = local_ptr.trim_end_matches('.').to_ascii_lowercase();
    local == tag || local.ends_with(&format!(".{tag}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(key: &str, label: &str, node: &str) -> FleetReport {
        FleetReport {
            network_key: key.into(),
            label: label.into(),
            node: node.into(),
            kind: Kind::Service,
            ptr_suffix: String::new(),
        }
    }

    fn sample_tag(key: &str, label: &str) -> Tag {
        Tag {
            network_key: key.into(),
            label: label.into(),
            kind: Kind::Service,
            ptr_suffix: "example.com".into(),
            ts: 1,
            source: Source::User,
        }
    }

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "vallum-tags-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|t| t.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    // The load-bearing security property: ten copies of one node's opinion
    // are still one node. If this ever returns Some, the scorer is counting
    // reports, and a single host can name anything it likes for the org.
    #[test]
    fn single_node_repeating_is_not_a_quorum() {
        let reports: Vec<_> = (0..10)
            .map(|_| report("1.2.3.0/24", "Plex", "node-a"))
            .collect();
        assert!(
            score(&reports, "1.2.3.0/24").is_none(),
            "one node repeating itself is hearsay, not a quorum"
        );
    }

    #[test]
    fn two_distinct_agreeing_nodes_are_a_quorum() {
        let reports = [
            report("1.2.3.0/24", "Plex", "node-a"),
            report("1.2.3.0/24", "Plex", "node-b"),
        ];
        let tag = score(&reports, "1.2.3.0/24").expect("two agreeing nodes are a quorum");
        assert_eq!(tag.label, "Plex");
        assert_eq!(tag.agreeing, 2);
        assert_eq!(tag.reporters, 2);
    }

    // 3-3 is 0.5, under the 0.6 floor. Surfacing either side would present a
    // coin flip as collective knowledge.
    #[test]
    fn three_three_split_returns_none() {
        let reports = [
            report("1.2.3.0/24", "Plex", "a"),
            report("1.2.3.0/24", "Plex", "b"),
            report("1.2.3.0/24", "Plex", "c"),
            report("1.2.3.0/24", "Jellyfin", "d"),
            report("1.2.3.0/24", "Jellyfin", "e"),
            report("1.2.3.0/24", "Jellyfin", "f"),
        ];
        assert!(score(&reports, "1.2.3.0/24").is_none());
    }

    #[test]
    fn fleet_tag_is_never_certain() {
        let tag = FleetTag {
            label: "Plex".into(),
            agreeing: 5,
            reporters: 5,
        };
        for (stored, local) in [
            ("", ""),
            ("", "derp.tailscale.com"),
            ("tailscale.com", "derp.tailscale.com"),
            ("old.example.com", "new.example.net"),
        ] {
            let c = fleet_confidence(&tag, stored, local);
            assert_ne!(
                c,
                Confidence::Certain,
                "fleet tag minted Certain for stored={stored:?} local={local:?}"
            );
            assert!(
                c == Confidence::Strong || c == Confidence::Weak,
                "fleet_confidence must return Strong or Weak, got {c:?}"
            );
        }
    }

    #[test]
    fn changed_ptr_downgrades_strong_to_weak() {
        let tag = FleetTag {
            label: "Plex".into(),
            agreeing: 2,
            reporters: 2,
        };
        assert_eq!(
            fleet_confidence(&tag, "tailscale.com", "derp15c.tailscale.com"),
            Confidence::Strong,
            "stored suffix still matches local PTR"
        );
        assert_eq!(
            fleet_confidence(&tag, "", "anything.example.net"),
            Confidence::Strong,
            "empty stored suffix has nothing to disagree with"
        );
        assert_eq!(
            fleet_confidence(&tag, "tailscale.com", "static.example.net"),
            Confidence::Weak,
            "PTR changed; the stored label may name a previous tenant"
        );
    }

    #[test]
    fn corrupt_tags_json_loads_empty() {
        let dir = tmpdir("corrupt");
        std::fs::write(dir.join("tags.json"), "{this is not json").unwrap();
        let store = TagStore::load(&dir);
        assert!(store.get("1.2.3.0/24").is_none());
        assert_eq!(store.iter().count(), 0);

        let missing = tmpdir("missing");
        let store = TagStore::load(&missing);
        assert_eq!(store.iter().count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&missing);
    }

    #[test]
    fn round_trip_preserves_a_tag() {
        let dir = tmpdir("roundtrip");
        let mut store = TagStore::load(&dir);
        let tag = sample_tag("1.2.3.0/24", "Plex");
        store.set(tag.clone());
        store.save().unwrap();

        let loaded = TagStore::load(&dir);
        assert_eq!(loaded.get("1.2.3.0/24"), Some(&tag));

        let mut loaded = loaded;
        assert!(loaded.remove("1.2.3.0/24").is_some());
        loaded.save().unwrap();
        let empty = TagStore::load(&dir);
        assert!(empty.get("1.2.3.0/24").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // Two nodes saying X, one node shouting Y a hundred times: X still wins,
    // because the shout is one vote. If this flips to Y, reports are being
    // counted and the loudest host names the org.
    #[test]
    fn loud_minority_does_not_win() {
        let mut reports = vec![
            report("9.9.9.0/24", "X", "node-a"),
            report("9.9.9.0/24", "X", "node-b"),
        ];
        reports.extend((0..100).map(|_| report("9.9.9.0/24", "Y", "node-c")));
        let tag = score(&reports, "9.9.9.0/24").expect("2-of-3 for X is a quorum");
        assert_eq!(tag.label, "X");
        assert_eq!(tag.agreeing, 2);
        assert_eq!(tag.reporters, 3);
    }

    #[test]
    fn two_of_three_meets_the_threshold() {
        let reports = [
            report("1.2.3.0/24", "Plex", "a"),
            report("1.2.3.0/24", "Plex", "b"),
            report("1.2.3.0/24", "Other", "c"),
        ];
        let tag = score(&reports, "1.2.3.0/24").unwrap();
        assert_eq!(tag.agreeing, 2);
        assert_eq!(tag.reporters, 3);
    }

    #[test]
    fn three_of_five_is_exactly_the_floor() {
        let reports = [
            report("1.2.3.0/24", "Plex", "a"),
            report("1.2.3.0/24", "Plex", "b"),
            report("1.2.3.0/24", "Plex", "c"),
            report("1.2.3.0/24", "Other", "d"),
            report("1.2.3.0/24", "Else", "e"),
        ];
        let tag = score(&reports, "1.2.3.0/24").expect("3/5 == 0.6 must pass");
        assert_eq!(tag.agreeing, 3);
        assert_eq!(tag.reporters, 5);
    }

    #[test]
    fn source_serializes_lowercase() {
        assert_eq!(serde_json::to_string(&Source::User).unwrap(), "\"user\"");
        assert_eq!(serde_json::to_string(&Source::Fleet).unwrap(), "\"fleet\"");
    }
}
