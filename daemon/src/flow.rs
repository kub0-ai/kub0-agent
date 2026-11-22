//! vallum wire schema v0 — see `docs/SCHEMA.md`.
//!
//! This is the internal contract every source driver normalises into. It is
//! deliberately not the same type as [`crate::event::Connection`], which is
//! upstream's socket-shaped record: a `Flow` can describe a socket that is
//! already closed, that no longer has an inode, or that was decided by another
//! engine entirely. [`Flow::to_legacy`] projects one back down so the existing
//! QML panel keeps rendering while the UI catches up.
//!
//! Serde rules that are load-bearing (schema doc, preamble):
//!   * every record carries `schema`
//!   * unknown fields are ignored on the way in, never an error
//!   * nothing is ever removed or repurposed within a major version

use crate::event::{AppIdentity, Connection, Endpoint};
use serde::{Deserialize, Serialize};

/// Bumped only for a breaking change. Additive fields do not bump it.
pub const SCHEMA_VERSION: u32 = 0;

/// Which driver observed the flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceKind {
    Opensnitch,
    Procfs,
    Ebpf,
    /// macOS live socket sampling. Additive: a new variant is not a breaking
    /// change, and `SCHEMA_VERSION` does not move for one.
    Libproc,
}

/// Whether the flow is open, finished, or was merely seen without a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlowState {
    Live,
    Closed,
    Observed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
    Reject,
    Ask,
    Observed,
}

/// Who decided. See `docs/SCHEMA.md` 3.2 — this is the field the fleet tier is
/// built on, which is why it is required rather than optional.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Provenance {
    User,
    RuleList,
    FleetPolicy,
    Default,
    /// Another enforcement engine decided this, not vallum. Reporting an
    /// OpenSnitch `deny` as `default` would claim vallum made a decision it
    /// did not make, and the fleet console cannot audit a rule it does not own.
    External,
    /// Read-only sampling; no engine made an allow/deny decision.
    Observation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    pub ip: String,
    pub port: u16,
    /// Hostname when the source knew one. Never reverse-resolved here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct App {
    /// Absolute executable path. The one identity every source can produce.
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desktop: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// `sha256:...` once anything computes it. Reserved from v0 because it is a
    /// rule subject: see `docs/SCHEMA.md` 2.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    /// `flatpak:org.mozilla.firefox`, `docker:<id>`, ...
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    /// Another uid, no desktop identity recoverable without privilege.
    #[serde(default)]
    pub system: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verdict {
    pub action: Action,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Geo {
    pub country: String,
    pub lat: f64,
    pub lon: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
}

/// Cumulative octets. Absent means unmeasured; a present zero means measured
/// and idle. Never synthesise one from the other (`docs/SCHEMA.md` 2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bytes {
    pub tx: u64,
    pub rx: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Flow {
    pub schema: u32,
    /// Always `"flow"`. Present so a reader can dispatch on record kind before
    /// it knows the rest of the shape.
    pub kind: String,
    /// Milliseconds since the Unix epoch.
    pub ts: u64,
    pub id: String,
    pub source: SourceKind,
    pub state: FlowState,
    pub app: App,
    pub proto: String,
    /// Null when the source does not observe the local endpoint. A database of
    /// past decisions knows the destination; it need not have kept the
    /// ephemeral source port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local: Option<Peer>,
    pub remote: Peer,
    pub verdict: Verdict,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geo: Option<Geo>,
    #[serde(default)]
    pub bytes: Option<Bytes>,
    #[serde(default)]
    pub new_network: bool,
    #[serde(default)]
    pub network_key: String,
}

impl Flow {
    /// Project down to upstream's socket record so the existing QML panel can
    /// render a flow it was never designed for.
    ///
    /// This is lossy on purpose and only in one direction. Everything the panel
    /// cannot show directly is preserved under `evidence` where available.
    pub fn to_legacy(&self) -> Connection {
        let (country, lat, lon) = match &self.geo {
            Some(g) => (g.country.clone(), g.lat, g.lon),
            None => (String::new(), 0.0, 0.0),
        };
        Connection {
            id: self.id.clone(),
            proto: self.proto.clone(),
            // Upstream keys sockets by inode. A flow read out of a database has
            // none, and inventing one would make two different flows collide in
            // the panel's seen-set. Zero is the documented "not a live socket".
            inode: 0,
            app: AppIdentity {
                id: self.app.key.clone(),
                name: self
                    .app
                    .name
                    .clone()
                    .unwrap_or_else(|| basename(&self.app.key).to_string()),
                icon: self.app.icon.clone().unwrap_or_default(),
                desktop: self.app.desktop.clone().unwrap_or_default(),
                pid: self.app.pid.unwrap_or(0),
                system: self.app.system,
                // `key` is the absolute executable path for every source.
                exe: self.app.key.clone(),
                owner: None,
            },
            local: self
                .local
                .as_ref()
                .map(|p| Endpoint {
                    ip: p.ip.clone(),
                    port: p.port,
                })
                .unwrap_or(Endpoint {
                    ip: String::new(),
                    port: 0,
                }),
            remote: Endpoint {
                ip: self.remote.ip.clone(),
                port: self.remote.port,
            },
            state: match self.state {
                FlowState::Live => "ESTABLISHED".into(),
                FlowState::Closed => "CLOSED".into(),
                FlowState::Observed => "OBSERVED".into(),
            },
            country,
            lat,
            lon,
            // The panel refuses to draw an arc without a remote address, which
            // is exactly the right behaviour for a row we cannot place.
            unresolved: self.remote.ip.is_empty(),
            new_network: self.new_network,
            network_key: self.network_key.clone(),
            hostname: self.remote.host.clone().unwrap_or_default(),
            hostname_source: if self.remote.host.is_some() { "source".into() } else { String::new() },
            uid: None,
            reason: String::new(),
            // Flow-sourced rows arrive already attributed -- that is what the
            // flow source is for -- so there is nothing here to guess about.
            clue: None,
            tag: None,
            bytes: self
                .bytes
                .as_ref()
                .map(|b| crate::traffic::Bytes { tx: b.tx, rx: b.rx }),
            exe: self.app.key.clone(),
            evidence: Some(crate::event::ConnectionEvidence {
                source: self.source,
                recorded_at: self.ts,
                verdict: Some(self.verdict.clone()),
                owner_method: "source-reported process identity".into(),
                hash: self.app.hash.clone(),
                container: self.app.container.clone(),
                lineage: None,
                package: None,
            }),
            policy: Vec::new(),
            asn: self.geo.as_ref().and_then(|g| g.asn),
            org: self.geo.as_ref().and_then(|g| g.org.clone()),
            indicators: Vec::new(),
        }
    }

    pub fn to_line(&self) -> String {
        let mut s = serde_json::to_string(self).unwrap_or_default();
        s.push('\n');
        s
    }
}

pub fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Flow {
        Flow {
            schema: SCHEMA_VERSION,
            kind: "flow".into(),
            ts: 1_757_600_000_000,
            id: "os:deadbeef".into(),
            source: SourceKind::Opensnitch,
            state: FlowState::Observed,
            app: App {
                key: "/usr/bin/firefox".into(),
                name: None,
                desktop: None,
                icon: None,
                pid: None,
                hash: None,
                container: None,
                system: false,
            },
            proto: "tcp".into(),
            local: None,
            remote: Peer {
                ip: "142.250.1.1".into(),
                port: 443,
                host: Some("google.com".into()),
            },
            verdict: Verdict {
                action: Action::Allow,
                rule_id: None,
                provenance: Provenance::External,
            },
            geo: None,
            bytes: None,
            new_network: false,
            network_key: "142.250.1.0/24".into(),
        }
    }

    #[test]
    fn unknown_fields_are_ignored_not_rejected() {
        // The whole compatibility contract rests on this: a newer producer must
        // be able to add a field without breaking every deployed consumer, on a
        // free tier that cannot be forced to upgrade.
        let line = r#"{"schema":0,"kind":"flow","ts":1,"id":"x","source":"ebpf",
            "state":"live","app":{"key":"/bin/x"},"proto":"tcp",
            "remote":{"ip":"1.2.3.4","port":53},
            "verdict":{"action":"deny","provenance":"fleetPolicy"},
            "somethingFromTheFuture":{"nested":true}}"#;
        let f: Flow = serde_json::from_str(line).expect("unknown field must not be fatal");
        assert_eq!(f.verdict.provenance, Provenance::FleetPolicy);
        assert!(f.bytes.is_none());
    }

    #[test]
    fn absent_bytes_never_serialises_as_zero() {
        // null means unmeasured, zero means measured-and-idle. A UI that cannot
        // tell them apart reports a busy app as quiet.
        let json = serde_json::to_string(&sample()).unwrap();
        assert!(json.contains("\"bytes\":null"), "{json}");
        assert!(!json.contains("\"bytes\":{\"tx\":0"));
    }

    #[test]
    fn camel_case_is_pinned() {
        let json = serde_json::to_string(&sample()).unwrap();
        assert!(json.contains("\"networkKey\""));
        assert!(json.contains("\"newNetwork\""));
        assert!(json.contains("\"provenance\":\"external\""));
    }

    #[test]
    fn legacy_projection_keeps_the_panel_honest() {
        let mut f = sample();
        f.app.name = Some("Firefox".into());
        let c = f.to_legacy();
        assert_eq!(c.inode, 0);
        assert_eq!(c.app.name, "Firefox");
        assert_eq!(c.hostname, "google.com");
        let evidence = c.evidence.unwrap();
        assert_eq!(evidence.source, f.source);
        assert_eq!(evidence.verdict, Some(f.verdict.clone()));
        assert_eq!(evidence.recorded_at, f.ts);
        assert!(!c.unresolved);

        // No remote address means no arc, whatever else we know.
        f.remote.ip = String::new();
        assert!(f.to_legacy().unresolved);
    }

    #[test]
    fn legacy_name_falls_back_to_basename() {
        let c = sample().to_legacy();
        assert_eq!(c.app.name, "firefox");
    }
}
