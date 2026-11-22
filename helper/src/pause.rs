//! Enforcement pause: one tagged `accept` at the head of vallum's own output
//! chain. An accept only ends evaluation of the chain it sits in, so the system
//! firewall's own chains still run; what it skips is every vallum drop below
//! it. Blocks, cgroup memberships and the IP sets are left exactly as they
//! were, so resuming is deleting that one rule.
//!
//! The marker file, not the rule, is the truth. The panel runs `status`
//! without privilege and `nft list` needs root, so the rule is invisible to
//! it; every privileged call brings the kernel back in line with the marker.

pub const PAUSE_COMMENT: &str = "vallum-paused";
/// The pause marker, under the state directory in use.
pub fn marker_path() -> std::path::PathBuf {
    crate::rename::state_path("paused")
}

/// Rule lines of an `nft -a list chain ...` listing, in chain order. The
/// table and chain headers carry a handle too, so they are skipped by name.
fn rule_lines(listing: &str) -> impl Iterator<Item = &str> {
    listing.lines().map(str::trim).filter(|l| {
        l.contains("# handle") && !l.starts_with("table ") && !l.starts_with("chain ")
    })
}

fn is_pause_rule(line: &str) -> bool {
    let body = line.split("# handle").next().unwrap_or("");
    body.contains(&format!("comment \"{PAUSE_COMMENT}\""))
        && body.split_whitespace().any(|t| t == "accept")
}

fn handle_of(line: &str) -> Option<String> {
    let h = line.rsplit("# handle").next()?.trim();
    (!h.is_empty() && h.chars().all(|c| c.is_ascii_digit())).then(|| h.to_string())
}

/// Handles of every pause rule in the listing.
pub fn pause_rule_handles(listing: &str) -> Vec<String> {
    rule_lines(listing)
        .filter(|l| is_pause_rule(l))
        .filter_map(handle_of)
        .collect()
}

/// True only when the chain's first rule is the pause rule. A pause rule with
/// a drop ahead of it does not pause that drop.
pub fn pause_rule_is_first(listing: &str) -> bool {
    rule_lines(listing).next().is_some_and(is_pause_rule)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAUSED: &str = r#"table inet vallum { # handle 7
	chain out { # handle 1
		type filter hook output priority filter; policy accept;
		accept comment "vallum-paused" # handle 9
		socket cgroupv2 level 2 "vallum.slice/vallum-firefox" drop # handle 3
		ip daddr @blocked4 drop # handle 5
	}
}
"#;

    const ACTIVE: &str = r#"table inet vallum { # handle 7
	chain out { # handle 1
		type filter hook output priority filter; policy accept;
		socket cgroupv2 level 2 "vallum.slice/vallum-firefox" drop # handle 3
		ip daddr @blocked4 drop # handle 5
	}
}
"#;

    #[test]
    fn finds_the_pause_rule_and_not_the_headers() {
        assert_eq!(pause_rule_handles(PAUSED), vec!["9"]);
        assert!(pause_rule_is_first(PAUSED));
    }

    #[test]
    fn an_enforcing_chain_has_no_pause_rule() {
        assert!(pause_rule_handles(ACTIVE).is_empty());
        assert!(!pause_rule_is_first(ACTIVE));
        assert!(!pause_rule_is_first(""));
    }

    #[test]
    fn a_pause_rule_behind_a_drop_is_not_first() {
        let late = ACTIVE.replace(
            "\t\tip daddr @blocked4 drop # handle 5\n",
            "\t\tip daddr @blocked4 drop # handle 5\n\t\taccept comment \"vallum-paused\" # handle 9\n",
        );
        assert_eq!(pause_rule_handles(&late), vec!["9"]);
        assert!(!pause_rule_is_first(&late));
    }

    #[test]
    fn only_an_accept_with_the_exact_comment_counts() {
        let drop = PAUSED.replace("accept comment", "drop comment");
        assert!(pause_rule_handles(&drop).is_empty());
        let other = PAUSED.replace("vallum-paused", "vallum-paused-not");
        assert!(pause_rule_handles(&other).is_empty());
    }

    #[test]
    fn every_duplicate_is_found_so_resume_removes_them_all() {
        let twice = PAUSED.replace(
            "\t\taccept comment \"vallum-paused\" # handle 9\n",
            "\t\taccept comment \"vallum-paused\" # handle 9\n\t\taccept comment \"vallum-paused\" # handle 11\n",
        );
        assert_eq!(pause_rule_handles(&twice), vec!["9", "11"]);
    }
}
