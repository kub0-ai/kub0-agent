//! The `Connection` wire contract, owned by the serde structs.
//!
//! `tests/fixtures/connection-contract.json` is GENERATED here from a
//! `Connection` with every field set to a non-default value, and
//! `tests/test_wire_contract.js` drives it through the panel's real ingest
//! path. `ConnectionModel.normalizeConn` is an allow-list: a field the daemon
//! sends and the list does not name is invisible to the whole UI, and that has
//! shipped three times (`clue`/`tag`, a fleet `name`, then `hostname`). With
//! the fixture generated from the struct, adding a field to `Connection` is a
//! compile error here until it is given a value, the fixture then carries it,
//! and the JS test fails until the panel keeps it or says why it does not.
//!
//! Regenerate after changing a wire struct:
//!     KUB0_BLESS=1 cargo test -p vallumd --test wire_contract

use serde::de::{DeserializeOwned, Visitor};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::PathBuf;
use vallumd::event::{AppIdentity, AppOwner, Connection, ConnectionEvidence, Endpoint, Event};
use vallumd::execgate::{ExecGateCounters, ExecGateDecision, ExecGateDeny, ExecGateFrame};
use vallumd::flow::{Action, Provenance, SourceKind, Verdict};
use vallumd::kub0::FleetSnapshot;
use vallumd::trust::TrustedDigest;
use vallumd::intel::{Attack, Indicator, Severity};
use vallumd::lineage::{Ancestor, Lineage};
use vallumd::netpolicy::ConnPolicy;
use vallumd::suggest::{Clue, Confidence, Kind};
use vallumd::tags::{Source, Tag};
use vallumd::traffic::Bytes;

const BLESS: &str = "KUB0_BLESS=1 cargo test -p vallumd --test wire_contract";

/// Every field set, none to its default: an absent or default value would let
/// a dropped field compare equal to whatever the JS falls back to.
fn fully_populated() -> Connection {
    // A struct literal, never `..Default::default()`: a new field must be
    // given a value here before this compiles.
    Connection {
        id: "tcp:4242:203.0.113.7:443".into(),
        proto: "tcp".into(),
        inode: 4242,
        app: AppIdentity {
            id: "fixture-app".into(),
            name: "Fixture App".into(),
            icon: "fixture-icon".into(),
            desktop: "fixture-app.desktop".into(),
            pid: 31337,
            system: true,
            exe: "/usr/bin/fixture-app".into(),
            owner: Some(AppOwner {
                uid: 1000,
                name: "fixture-user".into(),
            }),
        },
        local: Endpoint {
            ip: "192.0.2.10".into(),
            port: 40001,
        },
        remote: Endpoint {
            ip: "203.0.113.7".into(),
            port: 443,
        },
        state: "ESTABLISHED".into(),
        country: "DE".into(),
        lat: 50.1109,
        lon: 8.6821,
        unresolved: true,
        new_network: true,
        network_key: "203.0.113.0/24".into(),
        hostname: "edge-7.fixture.example".into(),
        hostname_source: "dns".into(),
        uid: Some(1000),
        reason: "unreadable".into(),
        clue: Some(Clue {
            label: "Fixture relay".into(),
            basis: "PTR edge-7.fixture.example".into(),
            confidence: Confidence::Strong,
            kind: Kind::Relay,
        }),
        tag: Some(Tag {
            network_key: "203.0.113.0/24".into(),
            label: "Fixture network".into(),
            kind: Kind::Service,
            ptr_suffix: "fixture.example".into(),
            ts: 1_700_000_000_000,
            source: Source::User,
        }),
        bytes: Some(Bytes { tx: 1024, rx: 2048 }),
        exe: "/usr/bin/fixture-app".into(),
        evidence: Some(ConnectionEvidence {
            source: SourceKind::Procfs,
            recorded_at: 1_700_000_000_123,
            verdict: Some(Verdict {
                action: Action::Deny,
                rule_id: Some("fixture-rule".into()),
                provenance: Provenance::FleetPolicy,
            }),
            owner_method: "fixture owner method".into(),
            hash: Some("sha256:fixture".into()),
            container: Some("fixture-container".into()),
            lineage: Some(Lineage {
                ancestors: vec![Ancestor {
                    pid: 31336,
                    comm: "fixture-shell".into(),
                    exe: "/usr/bin/fixture-shell".into(),
                }],
                cmdline: "fixture-app --fixture".into(),
                cwd: "/home/fixture".into(),
                truncated: true,
            }),
            package: Some("fixture-app 1.0-1".into()),
        }),
        policy: vec![ConnPolicy {
            rule_id: "fixture-policy-rule".into(),
            label: "Fixture policy".into(),
        }],
        asn: Some(64496),
        org: Some("Fixture Networks LLC".into()),
        indicators: vec![Indicator {
            id: "fixture-indicator".into(),
            severity: Severity::Notice,
            attack: Some(Attack {
                id: "T0000".into(),
                name: "Fixture Technique".into(),
            }),
            basis: "fixture basis".into(),
        }],
    }
}

const TS: u64 = 1_700_000_000_456;

/// The fixture: the record, and the two events that carry it, exactly as the
/// daemon serializes them onto the socket.
fn render() -> String {
    let conn = fully_populated();
    let line = |ev: Event| -> Value { serde_json::from_str(ev.to_line().trim()).unwrap() };
    let doc = serde_json::json!({
        "generatedBy": format!("daemon/tests/wire_contract.rs; regenerate with: {BLESS}"),
        "connection": serde_json::to_value(&conn).unwrap(),
        "events": {
            "snapshot": line(Event::Snapshot { ts: TS, connections: vec![conn.clone()] }),
            "connect": line(Event::Connect { ts: TS, conn }),
        },
    });
    serde_json::to_string_pretty(&doc).unwrap() + "\n"
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/connection-contract.json")
}

/// The exec-gate frame with every field set, none to its default. A struct
/// literal, so a new field is a compile error here until it has a value.
fn fully_populated_exec_gate() -> ExecGateFrame {
    ExecGateFrame {
        enabled: true,
        armed: true,
        keys: 3,
        source: "live".into(),
        observed_at: 1_700_000_000_789,
        counters: ExecGateCounters {
            blocked: 1,
            allowed_once: 2,
            trusted: 3,
            failopen: 4,
            hashed: 5,
            cache_hit: 6,
            allowlisted: 7,
            over_cap: 8,
            error: 9,
            deadline: 10,
            overflow: 11,
            marks: 12,
            uncovered: 13,
        },
        denies: vec![ExecGateDeny {
            ts: 1_700_000_000_500,
            pid: 4242,
            ppid: 4241,
            comm: "fixture-sample".into(),
            exe: "/home/fixture/Downloads/fixture-sample".into(),
            sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
            reason: "fixture reason".into(),
            promoted_by: "fixture-auto".into(),
            created_at: "2026-10-20T01:02:03Z".into(),
            decision: ExecGateDecision::AllowedFailopen,
        }],
        trusted: vec![TrustedDigest {
            sha256: "2222222222222222222222222222222222222222222222222222222222222222".into(),
            comm: "fixture-trusted".into(),
            exe: "/opt/fixture/fixture-trusted".into(),
            added_at: 1_700_000_000_100,
            note: "fixture note".into(),
        }],
        once_pending: 1,
        list_received_at: 1_700_000_000_300,
        list_restored: true,
    }
}

/// The exec-gate fixture: the frame, and the fleet event that carries it.
fn render_exec_gate() -> String {
    let frame = fully_populated_exec_gate();
    let mut snap = FleetSnapshot::default();
    snap.exec_gate = frame.clone();
    snap.denylist_live = Some(true);
    let line: Value = serde_json::from_str(snap.to_event(TS).to_line().trim()).unwrap();
    let doc = serde_json::json!({
        "generatedBy": format!("daemon/tests/wire_contract.rs; regenerate with: {BLESS}"),
        "execGate": serde_json::to_value(&frame).unwrap(),
        "events": { "fleet": line },
    });
    serde_json::to_string_pretty(&doc).unwrap() + "\n"
}

fn exec_gate_fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/execgate-contract.json")
}

#[test]
fn the_checked_in_exec_gate_fixture_is_what_the_structs_generate() {
    let generated = render_exec_gate();
    let path = exec_gate_fixture_path();
    if std::env::var_os("KUB0_BLESS").is_some() {
        std::fs::write(&path, &generated).unwrap();
    }
    let on_disk = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}; generate it with: {BLESS}", path.display()));
    assert!(
        on_disk == generated,
        "{} is stale against the exec-gate structs; regenerate with: {BLESS}",
        path.display()
    );
}

#[test]
fn the_exec_gate_fixture_round_trips_through_serde() {
    let frame = fully_populated_exec_gate();
    let back: ExecGateFrame = serde_json::from_value(serde_json::to_value(&frame).unwrap()).unwrap();
    assert_eq!(back, frame);
    // Every wire name is camelCase: the panel's allow-list is written in it.
    let v = serde_json::to_value(&frame).unwrap();
    let names: Vec<&str> = v.as_object().unwrap().keys().map(|k| k.as_str()).collect();
    for n in &names {
        assert!(!n.contains('_'), "{n} is not camelCase");
    }
    assert_eq!(v["denies"][0]["decision"], "allowed_failopen");
}

#[test]
fn the_checked_in_fixture_is_what_the_structs_generate() {
    let generated = render();
    let path = fixture_path();
    if std::env::var_os("KUB0_BLESS").is_some() {
        std::fs::write(&path, &generated).unwrap();
    }
    let on_disk = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}; generate it with: {BLESS}", path.display()));
    assert!(
        on_disk == generated,
        "{} is stale against the wire structs; regenerate with: {BLESS}",
        path.display()
    );
}

#[test]
fn the_fixture_round_trips_through_serde() {
    let conn = fully_populated();
    let back: Connection = serde_json::from_value(serde_json::to_value(&conn).unwrap()).unwrap();
    assert_eq!(back, conn);
}

/// The wire names serde itself would accept for `T`, renames applied: captured
/// from the field list a derived `Deserialize` hands its deserializer.
fn wire_fields<T: DeserializeOwned>() -> BTreeSet<&'static str> {
    struct Capture(Option<&'static [&'static str]>);
    impl<'de> serde::Deserializer<'de> for &mut Capture {
        type Error = serde::de::value::Error;
        fn deserialize_struct<V: Visitor<'de>>(
            self,
            _name: &'static str,
            fields: &'static [&'static str],
            _visitor: V,
        ) -> Result<V::Value, Self::Error> {
            self.0 = Some(fields);
            Err(serde::de::Error::custom("captured"))
        }
        fn deserialize_any<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
            Err(serde::de::Error::custom("not a plain struct"))
        }
        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
            bytes byte_buf option unit unit_struct newtype_struct seq tuple
            tuple_struct map enum identifier ignored_any
        }
    }
    let mut c = Capture(None);
    let _ = T::deserialize(&mut c);
    c.0.unwrap_or_else(|| panic!("{} is not a plain struct", std::any::type_name::<T>()))
        .iter()
        .copied()
        .collect()
}

fn keys(v: &Value) -> BTreeSet<&str> {
    v.as_object().unwrap().keys().map(String::as_str).collect()
}

#[test]
fn every_wire_field_of_every_struct_is_in_the_fixture() {
    // skip_serializing_if hides a field whose value is a default, so a
    // fixture could silently lose one. Compare against the struct's own field
    // list instead of against what happened to serialize.
    let c = serde_json::to_value(fully_populated()).unwrap();
    let e = &c["evidence"];
    for (what, value, want) in [
        ("Connection", &c, wire_fields::<Connection>()),
        ("AppIdentity", &c["app"], wire_fields::<AppIdentity>()),
        ("AppOwner", &c["app"]["owner"], wire_fields::<AppOwner>()),
        ("Endpoint (local)", &c["local"], wire_fields::<Endpoint>()),
        ("Endpoint (remote)", &c["remote"], wire_fields::<Endpoint>()),
        ("Clue", &c["clue"], wire_fields::<Clue>()),
        ("Tag", &c["tag"], wire_fields::<Tag>()),
        ("Bytes", &c["bytes"], wire_fields::<Bytes>()),
        ("ConnectionEvidence", e, wire_fields::<ConnectionEvidence>()),
        ("Verdict", &e["verdict"], wire_fields::<Verdict>()),
        ("Lineage", &e["lineage"], wire_fields::<Lineage>()),
        ("Ancestor", &e["lineage"]["ancestors"][0], wire_fields::<Ancestor>()),
        ("ConnPolicy", &c["policy"][0], wire_fields::<ConnPolicy>()),
        ("Indicator", &c["indicators"][0], wire_fields::<Indicator>()),
        ("Attack", &c["indicators"][0]["attack"], wire_fields::<Attack>()),
    ] {
        assert!(want.len() >= 2, "{what}: parsed fields {want:?}");
        assert_eq!(keys(value), want, "{what}: fixture keys differ from the struct's wire fields");
    }
    // Nested objects the walk above does not name would escape the check.
    let named: BTreeSet<&str> = [
        "app", "local", "remote", "clue", "tag", "bytes", "evidence", "policy", "indicators",
    ]
    .into_iter()
    .collect();
    for (k, v) in c.as_object().unwrap() {
        if v.is_object() || v.is_array() {
            assert!(named.contains(k.as_str()), "nested field {k} is not checked");
        }
    }
}

#[test]
fn no_value_in_the_fixture_is_a_default() {
    fn walk(path: &str, v: &Value, bad: &mut Vec<String>) {
        match v {
            Value::Null => bad.push(format!("{path} is null")),
            Value::Bool(false) => bad.push(format!("{path} is false")),
            Value::String(s) if s.is_empty() => bad.push(format!("{path} is empty")),
            Value::Number(n) if n.as_f64() == Some(0.0) => bad.push(format!("{path} is 0")),
            Value::Array(a) if a.is_empty() => bad.push(format!("{path} is []")),
            Value::Array(a) => {
                for (i, x) in a.iter().enumerate() {
                    walk(&format!("{path}[{i}]"), x, bad);
                }
            }
            Value::Object(o) => {
                for (k, x) in o {
                    walk(&format!("{path}.{k}"), x, bad);
                }
            }
            _ => {}
        }
    }
    let mut bad = Vec::new();
    walk("connection", &serde_json::to_value(fully_populated()).unwrap(), &mut bad);
    assert!(bad.is_empty(), "not fully populated: {bad:?}");
}

/// The hello frame's capability flags, which clients branch on. `requests`:
/// the daemon answers `req`-tagged requests. `as_uid`: it honours `as_uid`
/// from root, so `kub0` under pkexec or sudo may name the user it acts for;
/// `kub0` sends `as_uid` to no daemon that leaves this out, because an older
/// daemon would ignore the field and act as root.
#[test]
fn the_hello_frame_names_its_capabilities() {
    let hello = Event::Hello {
        version: "0.0.0".into(),
        pid: 1,
        coverage: "tcp".into(),
        rdns: false,
        mode: Default::default(),
        account: Default::default(),
        requests: true,
        as_uid: true,
    };
    let v = serde_json::to_value(&hello).unwrap();
    assert_eq!(v["type"], "hello");
    assert_eq!(v["requests"], true);
    assert_eq!(v["as_uid"], true);
    // A daemon from before the flag sends a hello without it: no as_uid.
    let old: Event = serde_json::from_str(
        r#"{"type":"hello","version":"0.4.3","pid":1,"coverage":"tcp","rdns":false,"mode":"system","requests":true}"#,
    )
    .unwrap();
    match old {
        Event::Hello { requests, as_uid, .. } => {
            assert!(requests);
            assert!(!as_uid, "an older daemon does not honour as_uid");
        }
        _ => panic!("not a hello"),
    }
}
