"use strict";
// The naming rules decide how confident the UI SOUNDS, which is the part of this
// feature that can be wrong without looking wrong. Every assertion below is
// about honesty, not layout.
const assert = require("assert");
const P = require("../js/Peers.js");
const CM = require("../ConnectionModel.js");

function conn(o) {
  return Object.assign({
    networkKey: "", hostname: "", remote: { ip: "203.0.113.9", port: 443 }
  }, o);
}

function testAHumanNameBeatsEveryMachineGuess() {
  const c = conn({
    tag: { label: "Work VPN", source: "user" },
    clue: { label: "Cloud provider", basis: "AS13335", confidence: "certain" },
    hostname: "edge.example.net"
  });
  assert.strictEqual(P.peerName(c), "Work VPN");
}

function testAStrongClueSpeaksButAWeakOneDoesNot() {
  // The whole precedence ladder in one place. A weak clue must fall through to
  // the hostname and then to the address -- if it ever reaches the summary
  // line, a guess is being printed in the same typeface as a fact.
  const strong = conn({ clue: { label: "Cloudflare", basis: "PTR", confidence: "strong" } });
  assert.strictEqual(P.peerName(strong), "Cloudflare");

  const weak = conn({
    clue: { label: "Maybe a mail server", basis: "port 25", confidence: "weak" },
    hostname: "mx.example.net"
  });
  assert.strictEqual(P.peerName(weak), "mx.example.net");

  const weakNoHost = conn({
    clue: { label: "Maybe a mail server", basis: "port 25", confidence: "weak" }
  });
  assert.strictEqual(P.peerName(weakNoHost), "203.0.113.9:443");
}

function testIdenticalPeersCollapseWithACount() {
  const app = { connections: [
    conn({ networkKey: "k1", clue: { label: "Tailscale relay", basis: "PTR", confidence: "strong" } }),
    conn({ networkKey: "k1", clue: { label: "Tailscale relay", basis: "PTR", confidence: "strong" } }),
    conn({ networkKey: "k2", hostname: "api.example.com" })
  ]};
  assert.strictEqual(P.summary(app), "Tailscale relay ×2, api.example.com");
}

function testTheSummaryCapsAndSaysItCapped() {
  const cs = [];
  for (let i = 0; i < 7; i++)
    cs.push(conn({ networkKey: "k" + i, hostname: "h" + i + ".example.com" }));
  const out = P.summary({ connections: cs });
  assert.ok(out.endsWith("+3 more"), out);
  // A truncation that does not announce itself reads as a complete list.
  assert.strictEqual(out.split(", ").length, 5);
}

function testPeersGroupByNetworkKeyNotByName() {
  // Two different keys that happen to resolve to the same display name must
  // stay separate rows: naming one must not silently claim to name the other.
  const app = { connections: [
    conn({ networkKey: "k1", remote: { ip: "203.0.113.1", port: 443 } }),
    conn({ networkKey: "k2", remote: { ip: "203.0.113.1", port: 443 } })
  ]};
  const ps = P.peers(app);
  assert.strictEqual(ps.length, 2);
  assert.deepStrictEqual(ps.map(p => p.networkKey), ["k1", "k2"]);
}

function testAKeylessRowSurvivesButCannotBeNamed() {
  // It must still be VISIBLE -- dropping it would hide a real connection --
  // and an empty networkKey is what the panel keys the action off.
  const ps = P.peers({ connections: [conn({ hostname: "nokey.example.com" })] });
  assert.strictEqual(ps.length, 1);
  assert.strictEqual(ps[0].networkKey, "");
}

function testEvidenceNeverClaimsMoreThanItKnows() {
  assert.strictEqual(
    P.peerEvidence({ tagLabel: "Work VPN", tagSource: "user" }), "named by you");
  // Saying whose it is, is what makes a fleet name overridable rather than
  // authoritative.
  assert.strictEqual(
    P.peerEvidence({ tagLabel: "Work VPN", tagSource: "fleet" }), "named by your org");
  // A weak guess is introduced AS a guess, in words.
  assert.strictEqual(
    P.peerEvidence({ clueLabel: "a mail server", clueBasis: "port 25", clueConfidence: "weak" }),
    "probably a mail server—port 25");
  // A strong one states its basis flatly, with no hedge.
  assert.strictEqual(
    P.peerEvidence({ clueLabel: "Your router", clueBasis: "default gateway via wlp1s0",
                     clueConfidence: "certain" }),
    "default gateway via wlp1s0");
  // No evidence means silence, never an invented reason.
  assert.strictEqual(P.peerEvidence({ name: "203.0.113.9:443" }), "");
  assert.strictEqual(P.peerEvidence(null), "");
}

function testTheVerbMatchesWhatTheRowActuallyIs() {
  assert.strictEqual(P.peerActionLabel({ clueConfidence: "weak" }), "Name this");
  assert.strictEqual(P.peerActionLabel({}), "Name this");
  assert.strictEqual(P.peerActionLabel({ clueConfidence: "certain" }), "Rename");
  assert.strictEqual(P.peerActionLabel({ tagLabel: "x", tagSource: "user" }), "Rename");
  // Overriding the org is named as an override, because it is one.
  assert.strictEqual(P.peerActionLabel({ tagLabel: "x", tagSource: "fleet" }), "Override");
}

function testNamingSeedsFromWhatIsAlreadyThere() {
  // Correcting a near-miss must be an edit, not a retype: the machine did most
  // of the work and making the human redo it throws that away.
  assert.strictEqual(P.namingSeed({ tagLabel: "Work VPN", clueLabel: "Cloud" }), "Work VPN");
  assert.strictEqual(P.namingSeed({ clueLabel: "Cloud provider" }), "Cloud provider");
  assert.strictEqual(P.namingSeed({}), "");
}

function testEvidenceSurvivesTheModelAndNotJustThisFile() {
  // THE regression test for this feature, and the one whose absence let it
  // ship inert. Every other case here hands Peers.js a hand-built object, so
  // they all pass even when nothing real ever reaches it: normalizeConn is an
  // ALLOW-LIST, and it was silently dropping clue and tag, so the panel drew
  // every peer as a bare address while the daemon was emitting both.
  //
  // Unit-testing the presentation rules proves the rules. It does not prove
  // the rules are ever given anything to present. This runs the daemon's own
  // wire shape through the model the panel actually reads.
  let st = CM.emptyState();
  st = CM.applyEvent(st, { type: "snapshot", apps: [], connections: [{
    id: "c1", proto: "tcp", inode: 5,
    app: { id: "curl", name: "curl", pid: 10 },
    local: { ip: "192.0.2.5", port: 5000 },
    remote: { ip: "203.0.113.9", port: 443 },
    state: "ESTABLISHED", networkKey: "k1",
    clue: { label: "Your router", basis: "default gateway via wlp1s0",
            confidence: "certain", kind: "infra" },
    tag: { label: "Work VPN", source: "user", kind: "service" }
  }]});

  const stored = st.connections[Object.keys(st.connections)[0]];
  assert.ok(stored.clue, "clue must survive normalizeConn");
  assert.ok(stored.tag, "tag must survive normalizeConn");

  const p = P.peers({ connections: [stored] })[0];
  assert.strictEqual(p.name, "Work VPN");
  assert.strictEqual(P.peerEvidence(p), "named by you");
  assert.strictEqual(P.peerActionLabel(p), "Rename");
  assert.strictEqual(P.namingSeed(p), "Work VPN");

  // And with no human name, the clue must still be the thing that speaks.
  let st2 = CM.emptyState();
  st2 = CM.applyEvent(st2, { type: "snapshot", apps: [], connections: [{
    id: "c2", proto: "tcp", inode: 6,
    app: { id: "curl", name: "curl", pid: 10 },
    local: { ip: "192.0.2.5", port: 5001 },
    remote: { ip: "203.0.113.10", port: 443 },
    state: "ESTABLISHED", networkKey: "k2",
    clue: { label: "Your router", basis: "default gateway via wlp1s0",
            confidence: "certain" }
  }]});
  const q = P.peers({ connections: [st2.connections[Object.keys(st2.connections)[0]]] })[0];
  assert.strictEqual(q.name, "Your router");
  assert.strictEqual(P.peerEvidence(q), "default gateway via wlp1s0");
}

function testAConnectionWithNoEvidenceNormalizesToNoEvidence() {
  // The other direction, so the fix cannot be "always fabricate an object".
  let st = CM.emptyState();
  st = CM.applyEvent(st, { type: "snapshot", apps: [], connections: [{
    id: "c3", proto: "tcp", inode: 7,
    app: { id: "curl", name: "curl", pid: 10 },
    local: { ip: "192.0.2.5", port: 5002 },
    remote: { ip: "203.0.113.11", port: 443 },
    state: "ESTABLISHED", networkKey: "k3"
  }]});
  const stored = st.connections[Object.keys(st.connections)[0]];
  assert.strictEqual(stored.clue, null);
  assert.strictEqual(stored.tag, null);
  const p = P.peers({ connections: [stored] })[0];
  assert.strictEqual(p.name, "203.0.113.11:443");
  assert.strictEqual(P.peerEvidence(p), "");
  assert.strictEqual(P.peerActionLabel(p), "Name this");
}

testAHumanNameBeatsEveryMachineGuess();
testAStrongClueSpeaksButAWeakOneDoesNot();
testIdenticalPeersCollapseWithACount();
testTheSummaryCapsAndSaysItCapped();
testPeersGroupByNetworkKeyNotByName();
testAKeylessRowSurvivesButCannotBeNamed();
testEvidenceNeverClaimsMoreThanItKnows();
testTheVerbMatchesWhatTheRowActuallyIs();
testNamingSeedsFromWhatIsAlreadyThere();
testEvidenceSurvivesTheModelAndNotJustThisFile();
testAConnectionWithNoEvidenceNormalizesToNoEvidence();
console.log("test_peers.js ok");
