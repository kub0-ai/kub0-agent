"use strict";
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const K = require("../js/Kub0.js");

function testConnectLineParser() {
  let c = K.emptyConnect();
  assert.strictEqual(c.connectState, "idle");
  const waiting = K.beginConnect(c);
  assert.strictEqual(waiting.connectState, "waiting");
  const noop = K.beginConnect(waiting);
  assert.strictEqual(noop.connectState, "waiting");
  assert.strictEqual(noop.connectCode, "");

  const now = 1_000_000;
  c = K.applyConnectLine(waiting, JSON.stringify({
    event: "code",
    user_code: "ABCD-EFGH",
    connect_url: "https://kub0.ai/connect",
    expires_in: 900,
    interval: 5
  }), now);
  assert.strictEqual(c.connectState, "waiting");
  assert.strictEqual(c.connectCode, "ABCD-EFGH");
  assert.strictEqual(c.connectUrl, "https://kub0.ai/connect");
  assert.strictEqual(c.connectExpiresAt, now + 900 * 1000);
  assert.strictEqual(c.connectInterval, 5);

  // The daemon replaces a code that expired unused; the newest event wins.
  const renewed = K.applyConnectLine(c, JSON.stringify({
    event: "code",
    user_code: "WXYZ-5678",
    connect_url: "https://kub0.ai/connect",
    expires_in: 900,
    interval: 3
  }), now + 900 * 1000);
  assert.strictEqual(renewed.connectState, "waiting");
  assert.strictEqual(renewed.connectCode, "WXYZ-5678");
  assert.strictEqual(renewed.connectExpiresAt, now + 1800 * 1000);
  assert.strictEqual(renewed.connectInterval, 3);
  assert.strictEqual(renewed.connectError, "");

  const connected = K.applyConnectLine(c, JSON.stringify({
    event: "connected",
    github_username: "alice"
  }), now);
  assert.strictEqual(connected.connectState, "connected");

  const err = K.applyConnectLine(waiting, JSON.stringify({
    event: "error",
    message: "device login expired"
  }), now);
  assert.strictEqual(err.connectState, "error");
  assert.strictEqual(err.connectError, "device login expired");

  const ignored = K.applyConnectLine(waiting, "not json", now);
  assert.strictEqual(ignored.connectState, "waiting");
}

function testDenylistMatches() {
  const apps = [
    { id: "curl", name: "curl", exe: "/usr/bin/curl", comm: "curl" },
    { id: "firefox", name: "Firefox", exe: "/usr/lib/firefox/firefox", comm: "firefox" },
    { id: "wget", name: "wget" }
  ];
  const denylist = [
    { comm: "curl", path: "/usr/bin/curl", action: "block", reason: "org policy" },
    { comm: "wget", path: "", action: "block", reason: "fetch" }
  ];
  const hits = K.denylistMatches(apps, denylist);
  assert.strictEqual(hits.length, 2);
  assert.strictEqual(hits[0].id, "curl");
  assert.strictEqual(hits[1].id, "wget");
  assert.strictEqual(K.denylistMatches(apps, []).length, 0);
  assert.strictEqual(K.denylistMatches([], denylist).length, 0);
  const pathOnly = K.denylistMatches(
    [{ id: "x", exe: "/usr/bin/curl" }],
    [{ comm: "", path: "/usr/bin/curl", action: "block", reason: "" }]
  );
  assert.strictEqual(pathOnly.length, 1);
}

function testHelloFleetIngest() {
  const text = fs.readFileSync(path.join(__dirname, "fixtures/kub0-hello-fleet.ndjson"), "utf8");
  const lines = text.trim().split("\n");
  assert.strictEqual(lines.length, 2);
  const hello = JSON.parse(lines[0]);
  const fleet = JSON.parse(lines[1]);
  let k = K.emptyKub0();
  k = K.applyHelloAccount(k, hello.account);
  assert.strictEqual(k.connected, true);
  assert.strictEqual(k.githubUsername, "alice");
  assert.strictEqual(k.nodeName, "host-a");
  assert.strictEqual(k.lastHeartbeatOk, true);
  k = K.applyFleet(k, fleet);
  assert.strictEqual(k.orgEndpoints, 3);
  assert.strictEqual(k.nodeLimit, 10);
  assert.strictEqual(k.selfState, "enforced");
  assert.strictEqual(k.denylistVersion, 7);
  assert.strictEqual(k.denylist.length, 2);
  assert.strictEqual(k.denylist[0].comm, "curl");
  // Panel.qml titles each row with `name`; dropping it drew "Unnamed rule".
  assert.strictEqual(k.denylist[0].name, "No command-line downloads");
  assert.strictEqual(k.denylist[1].name, "Block wget");
  const acct = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures/kub0-account.json"), "utf8"));
  const blob = lines.join("\n");
  assert.ok(acct.token);
  assert.strictEqual(blob.indexOf(acct.token), -1);
  assert.strictEqual(blob.indexOf("\"token\""), -1);
}

function testConnectUpdatesKub0Username() {
  let k = K.emptyKub0();
  k = K.applyConnectToKub0(k, JSON.stringify({
    event: "connected",
    github_username: "alice"
  }));
  assert.strictEqual(k.connected, true);
  assert.strictEqual(k.githubUsername, "alice");
}

// normalizeDenylistEntry is an allow-list, so a field the daemon adds to
// DenylistEntry is invisible to the panel until it is listed there. Read the
// struct's fields from the Rust source and require every one to survive.
function testEveryDaemonDenylistFieldReachesThePanel() {
  const src = fs.readFileSync(path.join(__dirname, "../daemon/src/event.rs"), "utf8");
  const m = src.match(/pub struct DenylistEntry \{([\s\S]*?)\n\}/);
  assert.ok(m, "DenylistEntry not found in daemon/src/event.rs");
  const fields = [...m[1].matchAll(/^\s*pub (\w+):/gm)].map((f) => f[1]);
  assert.ok(fields.includes("name") && fields.length >= 5, "parsed fields: " + fields);
  const entry = {};
  for (const f of fields) entry[f] = "x-" + f;
  const k = K.applyFleet(K.emptyKub0(), { connected: true, denylist: [entry] });
  for (const f of fields)
    assert.strictEqual(k.denylist[0][f], "x-" + f, "panel drops DenylistEntry." + f);
}

testConnectLineParser();
testDenylistMatches();
testHelloFleetIngest();
testEveryDaemonDenylistFieldReachesThePanel();
testConnectUpdatesKub0Username();
{
  const endpoint = { nodeName: "host-a", state: "monitoring", lastSeen: "2026-10-04T00:00:00Z", blocksActive: 0,
    agentVer: "0.2.0", arch: "aarch64", kernelVersion: "6.12", token: "extra-field" };
  let k = K.applyHelloAccount(K.emptyKub0(), {connected:true, github_username:"alice"});
  k = K.applyFleet(k, {connected:true, endpoints:[endpoint], endpointsUpdatedAt:42, endpointsRefreshOk:true});
  assert.strictEqual(k.endpoints.length, 1);
  assert.strictEqual(k.endpoints[0].blocksActive, 0);
  assert.strictEqual(k.endpoints[0].token, undefined);
  k = K.applyFleet(k, {connected:true, endpointsRefreshOk:false});
  assert.strictEqual(k.endpoints.length, 1);
  assert.strictEqual(k.endpointsUpdatedAt, 42);
  assert.strictEqual(k.endpointsRefreshOk, false);
  assert.deepStrictEqual(K.applyHelloAccount(k, {connected:true, github_username:"bob"}).endpoints, []);
  assert.deepStrictEqual(K.applyConnectToKub0(k, JSON.stringify({event:"connected", github_username:"bob"})).endpoints, []);
  assert.deepStrictEqual(K.applyConnectToKub0(k, JSON.stringify({event:"connected", github_username:"alice"})).endpoints, []);
  assert.deepStrictEqual(K.applyHelloAccount(k, {connected:false}).endpoints, []);
  assert.deepStrictEqual(K.applyFleet(k, {connected:false, endpoints:[endpoint]}).endpoints, []);
  assert.deepStrictEqual(K.applyFleet(K.emptyKub0(), {connected:true}).endpoints, []);
  const malformed = K.applyFleet(k, {connected:true, endpoints:[null, [], {}, {nodeName:" "}], endpointsUpdatedAt:NaN});
  assert.deepStrictEqual(malformed.endpoints, []);
  assert.strictEqual(malformed.endpointsUpdatedAt, 0);
}

// Org network policies: an allow-list, cleared on disconnect, captions say what a rule saw.
{
  const ev = {type: "fleet", connected: true, netpolicies: [
    {id: "p1", name: "Known C2", mode: "monitor", token: "never-copied", rules: [
      {id: "r1", kind: "intel", label: "Known C2: kub0 threat intel addresses", action: "monitor",
       size: 412, hits: 3, suppressed: 1, lastHitTs: 5, serverSuppressed: 2, serverWithheld: 4, secret: "x"},
      {id: "r2", kind: "domain", label: "future", action: "monitor", size: 0, hits: 0}]},
    {name: "no id, dropped"}]};
  const k = K.applyFleet(K.emptyKub0(), ev);
  assert.strictEqual(k.netpolicies.length, 1, "a policy without an id is dropped");
  const p = k.netpolicies[0];
  assert.strictEqual(p.token, undefined, "unknown policy fields never reach the panel");
  assert.strictEqual(p.rules[0].secret, undefined, "unknown rule fields never reach the panel");
  assert.strictEqual(p.rules[0].hits, 3);
  assert.strictEqual(p.rules[1].kind, "unknown");
  assert.strictEqual(K.policyRuleDetail(p.rules[0]),
    "412 addresses · 3 matches this session · 1 never-block · 4 withheld (not TLP:CLEAR)");
  assert.strictEqual(K.policyRuleDetail(p.rules[1]), "not supported by this kub0d · no matches yet");
  assert.strictEqual(K.policyRuleDetail({kind: "country", size: 1, hits: 1, suppressed: 0, serverWithheld: 0}),
    "1 country · 1 match this session");
  // Survives a copy, then vanishes on disconnect.
  assert.strictEqual(K.copyKub0(k).netpolicies.length, 1);
  assert.deepStrictEqual(K.applyFleet(k, {type: "fleet", connected: false}).netpolicies, []);
  // A fleet frame without the field (older daemon) keeps the last-good list.
  assert.strictEqual(K.applyFleet(k, {type: "fleet", connected: true}).netpolicies.length, 1);
}
// Enforcement status and block-aware captions.
{
  const ev = {type: "fleet", connected: true,
    netpolicyEnforcement: {state: "enforcing", enforcing: true, entries: 412, sharedRanges: 9000, appliedTs: 5, rules: ["r1"], secret: "x"},
    netpolicies: [{id: "p1", name: "C2", mode: "block", rules: [
      {id: "r1", kind: "intel", label: "C2: kub0 threat intel addresses", action: "block", effectiveAction: "block",
       enforced: true, size: 412, hits: 5, wouldBlock: 4, blocked: 4, shared: 1, canSnooze: false},
      {id: "r2", kind: "ip", label: "C2: traffic to 198.51.100.0/24", action: "block", effectiveAction: "block",
       enforced: false, notEnforcedReason: "app-scoped blocks are not enforced yet", hits: 2, wouldBlock: 2,
       canSnooze: true, snoozedUntil: 0}]}]};
  const k = K.applyFleet(K.emptyKub0(), ev);
  assert.deepStrictEqual(Object.keys(k.netpolicyEnforcement).sort(),
    ["appliedTs", "enforcing", "entries", "reason", "sharedRanges", "state"], "enforcement is an allow-list");
  assert.ok(K.policyEnforcementText(k.netpolicyEnforcement).startsWith("Known applied plan: 412 ranges"));
  const [r1, r2] = k.netpolicies[0].rules;
  assert.strictEqual(K.policyRuleDetail(r1),
    "blocking · 412 addresses · 5 matches this session · 4 matches to the known applied block plan · 1 on shared infrastructure (never blocked)");
  assert.strictEqual(K.policyRuleDetail(r2),
    "block (not enforced here) · 2 matches this session · 2 would block · app-scoped blocks are not enforced yet");
  assert.strictEqual(r2.canSnooze, true);
  assert.strictEqual(K.policyEnforcementText({state: "monitor", reason: "Block rules are enforced only when vallum runs as the system service"}),
    "Block rules are enforced only when vallum runs as the system service");
  assert.ok(K.policyEnforcementText({state: "error", reason: "fleet-sync failed: x"}).startsWith("Policy error:"));
  assert.strictEqual(K.policyEnforcementText({state: "none"}), "Daemon reports no current block plan.");
  // An unknown state never reads as enforcing.
  assert.strictEqual(K.normalizeEnforcement({state: "armed", enforcing: "yes"}).state, "unknown");
  assert.strictEqual(K.normalizeEnforcement({state: "armed", enforcing: "yes"}).enforcing, false);
  assert.strictEqual(K.applyFleet(k, {type: "fleet", connected: false}).netpolicyEnforcement.state, "unknown");
}
// A failed policy refresh keeps the last list received and says so. The field is an
// allow-list entry like the rest: before it was carried, a 404 left the old list on
// screen with nothing to say it was stale.
{
  const policies = [{id: "p1", name: "C2", mode: "block", rules: [{id: "r1", kind: "ip", label: "C2: traffic to 198.51.100.0/24"}]}];
  let k = K.applyFleet(K.emptyKub0(), {type: "fleet", connected: true, netpolicyRefreshOk: true, netpolicies: policies});
  assert.strictEqual(k.netpolicyRefreshOk, true);
  assert.strictEqual(K.policyRefreshText(k), "");
  k = K.applyFleet(k, {type: "fleet", connected: true, netpolicyRefreshOk: false, netpolicies: policies});
  assert.strictEqual(k.netpolicyRefreshOk, false);
  assert.strictEqual(k.netpolicies.length, 1, "the last policies received stay listed");
  assert.strictEqual(K.policyRefreshText(k), "Policy refresh failed. Showing the last policies received.");
  assert.strictEqual(K.copyKub0(k).netpolicyRefreshOk, false, "survives a copy");
  assert.strictEqual(K.applyFleet(k, {type: "fleet", connected: true}).netpolicyRefreshOk, false, "a frame without the field keeps it");
  assert.strictEqual(K.applyFleet(k, {type: "fleet", connected: true, netpolicyRefreshOk: "no"}).netpolicyRefreshOk, null);
  assert.strictEqual(K.applyFleet(k, {type: "fleet", connected: false}).netpolicyRefreshOk, null);
  assert.strictEqual(K.copyKub0({connected: false, netpolicyRefreshOk: false}).netpolicyRefreshOk, null);
  assert.strictEqual(K.policyRefreshText(K.emptyKub0()), "");
  assert.strictEqual(K.policyRefreshText(null), "");
  assert.strictEqual(K.policyRefreshText(K.applyFleet(K.emptyKub0(), {type: "fleet", connected: true, netpolicyRefreshOk: false})),
    "Policy refresh failed. No policies to show.", "nothing received yet is not 'showing the last policies'");
}
// The stale note as Panel.qml binds it, read out of the file and evaluated: shown whenever
// the refresh failed, with a list or before any arrived, and under its heading.
{
  const fs = require("fs");
  const path = require("path");
  const vm = require("vm");
  const lines = fs.readFileSync(path.join(__dirname, "../Panel.qml"), "utf8").split("\n");
  // The single-line bindings of the Text element whose binding is `marker`.
  const textElement = (marker) => {
    const at = lines.findIndex((l) => l.trim() === marker);
    assert.ok(at >= 0, "Panel.qml has no Text with " + marker);
    let start = at;
    while (!/^\s*Text \{$/.test(lines[start])) start--;
    const indent = lines[start].match(/^\s*/)[0] + "  ";
    const props = {};
    for (let i = start + 1; lines[i] !== indent.slice(2) + "}"; i++) {
      const m = lines[i].match(/^(\s*)(\w+): (.+)$/);
      if (m && m[1] === indent) props[m[2]] = m[3];
    }
    return props;
  };
  const note = textElement("text: Kub0.policyRefreshText(root.kub0)");
  const heading = textElement('text: "Network policies"');
  const shown = (k, rules) => {
    const scope = {root: {kub0: k, kub0NetRules: rules}, Kub0: K};
    const text = vm.runInNewContext(note.text, scope);
    return {
      text: text,
      visible: vm.runInNewContext(note.visible, Object.assign({text: text}, scope)),
      heading: vm.runInNewContext(heading.visible, Object.assign({text: "Network policies"}, scope)),
    };
  };
  const policies = [{id: "p1", name: "C2", mode: "block", rules: [{id: "r1", kind: "ip", label: "C2"}]}];
  const fleet = (ev) => K.applyFleet(K.emptyKub0(), Object.assign({type: "fleet", connected: true}, ev));
  assert.deepStrictEqual(shown(fleet({netpolicyRefreshOk: false, netpolicies: policies}), policies[0].rules),
    {text: "Policy refresh failed. Showing the last policies received.", visible: true, heading: true});
  assert.deepStrictEqual(shown(fleet({netpolicyRefreshOk: false}), []),
    {text: "Policy refresh failed. No policies to show.", visible: true, heading: true}, "the first fetch failed");
  assert.deepStrictEqual(shown(fleet({netpolicyRefreshOk: true, netpolicies: policies}), policies[0].rules),
    {text: "", visible: false, heading: true});
  assert.deepStrictEqual(shown(fleet({netpolicyRefreshOk: true}), []), {text: "", visible: false, heading: true});
  assert.deepStrictEqual(shown(K.emptyKub0(), []), {text: "", visible: false, heading: true}, "disconnected");
}
console.log("test_kub0.js ok");

// Evidence states use the actual model functions, with no kernel/tenant access.
{
  const plan = {state:"enforcing", enforcing:true, entries:2, appliedTs:1234};
  let k = K.applyHelloAccount(K.emptyKub0(), {connected:true, github_username:"alice"});
  k = K.applyFleet(k, {connected:true, netpolicyRefreshOk:true, netpolicies:[{id:"p",rules:[]}], netpolicyEnforcement:plan});
  k = K.applyFleet(k, {connected:true, netpolicyRefreshOk:false});
  assert.match(K.policyRefreshText(k), /Retaining the known applied plan/);
  assert.strictEqual(k.netpolicyEnforcement.appliedTs, 1234);
  const changed = K.applyHelloAccount(k, {connected:true, github_username:"bob"});
  assert.deepStrictEqual(changed.netpolicies, []);
  assert.strictEqual(changed.netpolicyRefreshOk, null);
  assert.strictEqual(changed.netpolicyEnforcement.appliedTs, 0);
  assert.match(K.policyEnforcementText(changed.netpolicyEnforcement), /unknown/);
  assert.strictEqual(K.applyConnectToKub0(k, '{"event":"connected","github_username":"alice"}').netpolicyEnforcement.enforcing, false);
  assert.strictEqual(K.clearPolicyEvidence(K.copyKub0(k)).netpolicyEnforcement.enforcing, false);
  const unanswered = K.applyFleet(changed, {connected:true, netpolicies:[], netpolicyRefreshOk:false,
    netpolicyEnforcement:{state:"error",enforcing:false,reason:"<b>rules left in place</b>"}});
  assert.match(K.policyEnforcementText(unanswered.netpolicyEnforcement), /Policy error:.*left in place.*unverified/);
  assert.doesNotMatch(K.policyEnforcementText(unanswered.netpolicyEnforcement), /not applied|no protection/);
  const empty = K.applyFleet(unanswered, {connected:true, netpolicies:[], netpolicyRefreshOk:true, netpolicyEnforcement:{state:"none"}});
  assert.strictEqual(K.policyRefreshText(empty), "");
  assert.match(K.policyEnforcementText(empty.netpolicyEnforcement), /no current block plan/);
  for (const mode of [undefined, null, "", "root", "legacy"])
    assert.match(K.policyDaemonModeText(mode), /unknown/);
  assert.match(K.policyDaemonModeText("user"), /User daemon.*unavailable/);
  assert.match(K.policyDaemonModeText("system"), /System daemon reported/);
  assert.match(K.policyEnforcementText(K.normalizeEnforcement({state:"future",enforcing:true})), /unknown/);
  assert.match(K.policyEnforcementText({state:"enforcing",enforcing:false,reason:"paused"}), /paused/);
  assert.doesNotMatch(K.policyEnforcementText({state:"enforcing",enforcing:true,entries:2}), /Applied at/);
}

{
  const disconnected = K.applyFleet(K.emptyKub0(), {connected:false,
    netpolicyEnforcement:{state:"error", enforcing:false, reason:"clear failed; rules may still be in the kernel"}});
  assert.match(K.policyEnforcementText(K.copyKub0(disconnected).netpolicyEnforcement), /clear failed/);
  assert.strictEqual(disconnected.netpolicyEnforcement.enforcing, false);
  assert.strictEqual(K.normalizeEnforcement({state:"future",enforcing:true}).enforcing, false);
}
console.log("policy evidence tests ok");
// A failed refresh carrying replacement bytes must still preserve last-good data.
{
  let k = K.applyFleet(K.emptyKub0(), {connected:true, endpoints:[{nodeName:'retained', blocksActive:0}], endpointsUpdatedAt:42, endpointsRefreshOk:true});
  k = K.applyFleet(k, {connected:true, endpoints:[], endpointsUpdatedAt:99, endpointsRefreshOk:false});
  assert.strictEqual(k.endpoints[0].nodeName, 'retained');
  assert.strictEqual(k.endpointsUpdatedAt, 42);
  k = K.applyFleet(k, {connected:true, endpoints:[], endpointsUpdatedAt:100, endpointsRefreshOk:true});
  assert.deepStrictEqual(k.endpoints, []);
  assert.strictEqual(k.endpointsUpdatedAt, 100);
}

// Org prevalence: parsed from the fleet frame, phrased by prevalenceText, and
// never a count the server did not give.
{
  const base = K.emptyKub0();
  assert.deepStrictEqual(base.prevalence, {});
  assert.strictEqual(base.prevalenceSupported, null);
  assert.strictEqual(base.sharingDestinations, false);
  const off = K.applyFleet(base, { connected: true, prevalence: [{ networkKey: "203.0.113.0/24", nodes: 3, firstSeen: 5 }], prevalenceSupported: true, sharingDestinations: false });
  assert.strictEqual(K.prevalenceText(off, "203.0.113.0/24"), "", "not sharing: nothing is claimed about the org");
  const on = K.applyFleet(base, { connected: true, sharingDestinations: true, prevalenceSupported: true,
    prevalence: [{ networkKey: "203.0.113.0/24", nodes: 3, firstSeen: 5 }, { networkKey: "198.51.100.0/24", nodes: 0 }, { networkKey: "", nodes: 1 }, { networkKey: "x", nodes: "many" }, "junk"] });
  assert.deepStrictEqual(on.prevalence, { "203.0.113.0/24": { nodes: 3, firstSeen: 5 }, "198.51.100.0/24": { nodes: 0, firstSeen: 0 } });
  assert.strictEqual(K.prevalenceText(on, "203.0.113.0/24"), "Seen on 3 other endpoints in your org");
  assert.strictEqual(K.prevalenceText(on, "198.51.100.0/24"), "First in your org: no other endpoint has reported this network");
  assert.strictEqual(K.prevalenceText(on, "1.2.3.0/24"), "Org prevalence: no answer yet for this network");
  const unsupported = K.applyFleet(on, { connected: true, sharingDestinations: true, prevalenceSupported: false });
  assert.strictEqual(K.prevalenceText(unsupported, "203.0.113.0/24"), "Org prevalence: not answered by this server");
  assert.deepStrictEqual(unsupported.prevalence, on.prevalence, "what was learned is kept");
  const waiting = K.applyFleet(base, { connected: true, sharingDestinations: true });
  assert.strictEqual(K.prevalenceText(waiting, "203.0.113.0/24"), "Org prevalence: waiting for a heartbeat");
  const gone = K.applyFleet(on, { connected: false });
  assert.deepStrictEqual(gone.prevalence, {});
  assert.strictEqual(gone.prevalenceSupported, null);
  assert.strictEqual(K.prevalenceText(gone, "203.0.113.0/24"), "");
  assert.deepStrictEqual(K.copyKub0(on).prevalence, on.prevalence);
  console.log("prevalence tests ok");
}

// The deny-list action is labelled by its real value. The kub0 API accepts
// `block` and `monitor`; the gate keys on `block` only, so an empty action is
// "Unset", and `deny` (which the fixtures used to carry) is echoed, not folded.
{
  assert.strictEqual(K.denylistActionText("block"), "Block");
  assert.strictEqual(K.denylistActionText("monitor"), "Monitor");
  assert.strictEqual(K.denylistActionText(""), "Unset");
  assert.strictEqual(K.denylistActionText(undefined), "Unset");
  assert.strictEqual(K.denylistActionText("deny"), "Deny");
  const k = K.applyFleet(K.emptyKub0(), { connected: true, denylist: [
    { name: "n", comm: "x", path: "", action: "block", reason: "r", promoted_by: "vigiles-auto", created_at: "2026-10-20T01:02:03Z" }] });
  assert.strictEqual(k.denylist[0].promoted_by, "vigiles-auto");
  assert.strictEqual(k.denylist[0].created_at, "2026-10-20T01:02:03Z");
  assert.strictEqual(K.denylistLiveText(K.applyFleet(K.emptyKub0(), { connected: true, denylistLive: true })),
    "Deny list: live stream connected, poll every 60 s as backup.");
  assert.strictEqual(K.denylistLiveText(K.applyFleet(K.emptyKub0(), { connected: true, denylistLive: false })),
    "Deny list: live stream down, polling every 60 s.");
  assert.strictEqual(K.denylistLiveText(K.applyFleet(K.emptyKub0(), { connected: true })), "Deny list: polled every 60 s.");
  assert.strictEqual(K.denylistLiveText(K.emptyKub0()), "");
  console.log("deny-list action tests ok");
}

// `pkexec kub0 --json login` (#61 step 1b): partial replies one compact line
// each, the final reply pretty-printed at exit, read as the old connect events.
{
  const K = require("../js/Kub0.js");
  const code = K.kub0LoginPartial(JSON.stringify({ code: "ABCD-EFGH", url: "https://kub0.ai/connect", expiresIn: 900, interval: 5, minted: 1, max: 4 }));
  assert.deepStrictEqual(JSON.parse(code), { event: "code", user_code: "ABCD-EFGH", connect_url: "https://kub0.ai/connect", expires_in: 900, interval: 5 });
  let c = K.applyConnectLine(K.beginConnect(K.emptyConnect()), code, 1000);
  assert.strictEqual(c.connectState, "waiting");
  assert.strictEqual(c.connectCode, "ABCD-EFGH");
  assert.strictEqual(c.connectExpiresAt, 1000 + 900000);
  assert.strictEqual(K.kub0LoginPartial(JSON.stringify({ expired: "ABCD-EFGH", minted: 1, max: 4 })), "", "an expiry is followed by a fresh code");
  for (const line of ["{", '  "githubUsername": "octo",', "}", "", "not json", null, undefined, "[1]"])
    assert.strictEqual(K.kub0LoginPartial(line), "", String(line));
  const out = [code ? JSON.stringify({ code: "A" }) : "", "{", '  "account": "/var/lib/kub0/account.json",', '  "githubUsername": "octo",', '  "serverUrl": "https://kub0.ai"', "}", ""].join("\n");
  const done = K.kub0LoginFinish(out, "", 0);
  assert.deepStrictEqual(JSON.parse(done), { event: "connected", github_username: "octo" });
  assert.strictEqual(K.applyConnectLine(c, done, 2000).connectState, "connected");
  assert.strictEqual(K.applyConnectToKub0(K.emptyKub0(), done).githubUsername, "octo");
  assert.deepStrictEqual(JSON.parse(K.kub0LoginFinish("", "kub0 login: login: chooses the org whose rules this host enforces; needs root: sudo kub0 login\n", 1)),
    { event: "error", message: "login: chooses the org whose rules this host enforces; needs root: sudo kub0 login" });
  assert.deepStrictEqual(JSON.parse(K.kub0LoginFinish("", "", 126)), { event: "error", message: "authorization was refused or cancelled" });
  assert.deepStrictEqual(JSON.parse(K.kub0LoginFinish("", "", 0)), { event: "error", message: "kub0 login printed no account" });
  assert.deepStrictEqual(JSON.parse(K.kub0LoginFinish("{\n  \"githubUsername\": \"octo\"\n}", "", 1)).event, "error", "a non-zero exit is no login");
  assert.strictEqual(JSON.parse(K.kub0LoginFinish("", "", 5)).message, "kub0 login exited 5");
  console.log("kub0 login output tests ok");
}
