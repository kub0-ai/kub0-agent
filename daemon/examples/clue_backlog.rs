//! Measure the clue ladder against a real `unknown.ndjson` backlog.
//!
//! ```sh
//! cargo run --example clue_backlog -- ~/.local/state/kub0/unknown.ndjson
//! ```
//!
//! Unit tests pin the ladder's behaviour on fixtures the author chose, which
//! is exactly the wrong evidence for "does this name a real machine's
//! unknowns?". This replays the rules over rows the daemon actually wrote and
//! reports the naming rate by confidence tier, so a change that looks tidy in
//! isolation has to justify itself against live data.
//!
//! Reverse DNS is performed here the same way the daemon does it, so the run
//! is as slow as the host resolver and its results are as current.

use std::collections::HashMap;
use std::net::IpAddr;
use vallumd::suggest::{clue, sys_uid_max, Accounts, Confidence, Evidence};

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        format!(
            "{}/.local/state/kub0/unknown.ndjson",
            std::env::var("HOME").unwrap_or_default()
        )
    });
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{path}: {e}");
            std::process::exit(2);
        }
    };

    let accounts = Accounts::load();
    let max_uid = sys_uid_max();
    // The real table from the machine running the replay: the route rungs are
    // the whole point of measuring against a live backlog.
    let routes = vallumd::routes::load();
    let mut cache: HashMap<IpAddr, String> = HashMap::new();

    let (mut rows, mut named) = (0usize, 0usize);
    let mut by_tier: HashMap<String, usize> = HashMap::new();
    let mut by_label: HashMap<String, usize> = HashMap::new();

    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some(ip) = v["remote"]["ip"].as_str().and_then(|s| s.parse::<IpAddr>().ok()) else {
            continue;
        };
        rows += 1;
        let port = v["remote"]["port"].as_u64().unwrap_or(0) as u16;
        let uid = v["uid"].as_u64().map(|u| u as u32);

        // The daemon only looks up what it can: loopback and private ranges
        // never reach the resolver.
        let host = if ip.is_loopback() || vallumd::geo::is_private(ip) {
            String::new()
        } else {
            cache
                .entry(ip)
                .or_insert_with(|| lookup(ip).unwrap_or_default())
                .clone()
        };

        match clue(&Evidence {
            uid,
            sys_uid_max: max_uid,
            account: uid.and_then(|u| accounts.get(u)),
            hostname: &host,
            remote: ip,
            port,
            routes: &routes,
        }) {
            Some(c) => {
                named += 1;
                *by_tier.entry(format!("{:?}", c.confidence)).or_default() += 1;
                *by_label.entry(c.label.clone()).or_default() += 1;
                if c.confidence == Confidence::Certain {
                    // Certain clues are the ones the UI applies without
                    // asking, so they are the ones worth eyeballing.
                    eprintln!("  certain: {:<46} {}", c.label, c.basis);
                }
            }
            None => *by_label.entry("(still unknown)".into()).or_default() += 1,
        }
    }

    println!("\nrows={rows}  named={named}  ({:.0}%)", pct(named, rows));
    let mut tiers: Vec<_> = by_tier.into_iter().collect();
    tiers.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    for (tier, n) in tiers {
        println!("  {tier:<10} {n:>4}  ({:.0}%)", pct(n, rows));
    }
    println!("\ntop labels:");
    let mut labels: Vec<_> = by_label.into_iter().collect();
    labels.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    for (label, n) in labels.into_iter().take(12) {
        println!("  {n:>4}  {label}");
    }
}

fn pct(n: usize, of: usize) -> f64 {
    if of == 0 {
        0.0
    } else {
        n as f64 * 100.0 / of as f64
    }
}

fn lookup(ip: IpAddr) -> Option<String> {
    let out = std::process::Command::new("getent")
        .args(["hosts", &ip.to_string()])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    s.split_whitespace().nth(1).map(str::to_string)
}
