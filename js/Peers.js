// Naming an unknown peer: who a connection is, how confident we are, and how
// honestly to say so.
//
// This lives in a JS module rather than in Panel.qml because the rules here are
// the whole feature. "Show a weak guess in the summary line" and "show a weak
// guess with its basis in an expandable row" are two different products, and the
// difference between them is one boolean nobody can see in a screenshot. Rules
// that decide how confident the UI sounds have to be assertable.

/// The one name to show for a connection, in a place with no room to explain.
///
/// Precedence: a name a human gave beats a machine guess; a machine guess only
/// speaks up when it is CERTAIN or STRONG. A weak clue is deliberately dropped
/// here and shown by `peerEvidence` instead -- a summary line has no room to say
/// "probably", and a hunch printed in the same typeface as a fact is how a
/// naming feature starts lying.
function peerName(c) {
  if (!c)
    return "?";
  if (c.tag && c.tag.label)
    return c.tag.label;
  if (c.clue && c.clue.label && (c.clue.confidence === "certain" || c.clue.confidence === "strong"))
    return c.clue.label;
  if (c.hostname)
    return c.hostname;
  var ip = c.remote && c.remote.ip ? c.remote.ip : "?";
  var port = c.remote && c.remote.port ? ":" + c.remote.port : "";
  return ip + port;
}

/// One line naming who an app is actually talking to.
///
/// Identical answers collapse with a count: tailscaled probing the DERP mesh is
/// one fact ("Tailscale relay x12"), not twelve unrelated addresses. Comma-
/// joined, not middot-joined -- this is a list of peers, and a middot run reads
/// as a status line where every item carries equal weight.
function summary(app, cap) {
  var cs = (app && app.connections) || [];
  var order = [];
  var counts = {};
  var i;
  for (i = 0; i < cs.length; i++) {
    var nm = peerName(cs[i]);
    if (counts[nm] === undefined) {
      counts[nm] = 0;
      order.push(nm);
    }
    counts[nm] += 1;
  }
  var limit = Math.min(order.length, cap === undefined ? 4 : cap);
  var parts = [];
  for (i = 0; i < limit; i++) {
    var n = counts[order[i]];
    parts.push(n > 1 ? order[i] + " ×" + n : order[i]);
  }
  if (order.length > limit)
    parts.push("+" + (order.length - limit) + " more");
  return parts.join(", ");
}

/// The app's peers, collapsed by the name they resolve to, each carrying the
/// evidence behind that name.
///
/// Grouped by `networkKey`, because that is the unit the daemon tags: a row that
/// offers to name something must be the same thing the name will apply to.
/// Connections with no key still appear -- they simply cannot be named, and the
/// UI says so by omitting the action rather than by offering one that fails.
function peers(app) {
  var cs = (app && app.connections) || [];
  var order = [];
  var byId = {};
  for (var i = 0; i < cs.length; i++) {
    var c = cs[i];
    var key = c.networkKey || "";
    var name = peerName(c);
    var id = key || ("name:" + name);
    if (byId[id] === undefined) {
      byId[id] = {
        id: id,
        networkKey: key,
        name: name,
        count: 0,
        ip: c.remote && c.remote.ip ? c.remote.ip : "",
        hostname: c.hostname || "",
        tagLabel: c.tag && c.tag.label ? c.tag.label : "",
        tagSource: c.tag && c.tag.source ? c.tag.source : "",
        kind: (c.tag && c.tag.kind) || (c.clue && c.clue.kind) || "service",
        clueLabel: c.clue && c.clue.label ? c.clue.label : "",
        clueBasis: c.clue && c.clue.basis ? c.clue.basis : "",
        clueConfidence: c.clue && c.clue.confidence ? c.clue.confidence : ""
      };
      order.push(id);
    }
    byId[id].count += 1;
  }
  var out = [];
  for (var j = 0; j < order.length; j++)
    out.push(byId[order[j]]);
  return out;
}

/// Why this row is named what it is.
///
/// Never asserts more than it knows. A user's own name needs no defence; a fleet
/// name says whose it is, because "named by your org" is the fact that makes it
/// overridable rather than authoritative. A weak clue is introduced as a guess,
/// in words -- this is the row that CAN afford to say "probably", which is
/// exactly why the weak guess is allowed to surface here and nowhere else. A row
/// with no evidence says nothing rather than inventing a reason.
function peerEvidence(p) {
  if (!p)
    return "";
  if (p.tagLabel)
    return p.tagSource === "fleet" ? "named by your org" : "named by you";
  if (!p.clueBasis)
    return "";
  if (p.clueConfidence === "weak")
    return "probably " + p.clueLabel + "—" + p.clueBasis;
  return p.clueBasis;
}

/// A settled name is edited; an unknown is an invitation.
///
/// The verb carries the difference, so the affordance reads as "help me" on the
/// rows that need help and as "change this" on the rows that do not. Overriding
/// the org is named as an override, because it is one.
function peerActionLabel(p) {
  if (!p)
    return "Name this";
  if (p.tagLabel)
    return p.tagSource === "fleet" ? "Override" : "Rename";
  return (p.clueConfidence === "certain" || p.clueConfidence === "strong")
    ? "Rename" : "Name this";
}

/// What to put in the field when naming starts.
///
/// Seeded with whatever is already on the row, so correcting a near-miss is an
/// edit and not a retype. The machine did most of the work; making the human
/// type it again throws that away.
function namingSeed(p) {
  if (!p)
    return "";
  return p.tagLabel || p.clueLabel || "";
}

if (typeof module !== "undefined" && module.exports)
  module.exports = { peerName: peerName, summary: summary, peers: peers,
                     peerEvidence: peerEvidence, peerActionLabel: peerActionLabel,
                     namingSeed: namingSeed };
