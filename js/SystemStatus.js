// Separate from user flow health and helper readiness. Only the protected native
// diagnostic child may feed this state; arbitrary event JSON is never accepted.
var installedCli = "/usr/lib/kub0/kub0d"
var bootstrap = "import os,stat\np='/usr/lib/kub0/kub0d'\nq=p\nwhile True:\n m=os.lstat(q)\n if m.st_uid!=0 or stat.S_ISLNK(m.st_mode) or m.st_mode&0o022: raise SystemExit(1)\n if q==p:\n  if not stat.S_ISREG(m.st_mode) or m.st_mode&0o6000 or not m.st_mode&0o111: raise SystemExit(1)\n elif not stat.S_ISDIR(m.st_mode): raise SystemExit(1)\n if q=='/': break\n q=os.path.dirname(q)\nos.execve(p,[p,'system-status'],{'LANG':'C','LC_ALL':'C'})"
function empty() { return { current: false, last: null, error: "System diagnostics unavailable" } }
function fail(state, reason) { return { current: false, last: state.last, error: reason || "System diagnostics unavailable" } }
function parse(raw, now) {
  if (!Number.isSafeInteger(now) || now <= 0) return null
  if (typeof raw !== "string" || raw.length > 4096) return null
  var v
  try { v = JSON.parse(raw) } catch (_) { return null }
  if (!v || typeof v !== "object" || Array.isArray(v)) return null
  var keys = ["mode", "producer_version", "observed_at", "policy_refresh_ok", "policy_known", "reported_last_applied_at", "current_kernel_verification"]
  if (Object.keys(v).length !== keys.length) return null
  for (var i=0; i<keys.length; i++) if (!Object.prototype.hasOwnProperty.call(v,keys[i])) return null
  if (v.mode !== "system" || typeof v.producer_version !== "string" || !v.producer_version.length || v.producer_version.length > 64
      || typeof v.policy_known !== "boolean" || (v.policy_refresh_ok !== null && typeof v.policy_refresh_ok !== "boolean")
      || v.current_kernel_verification !== "unknown"
      || !Number.isSafeInteger(v.observed_at) || v.observed_at <= 0 || v.observed_at > now+1000 || now-v.observed_at > 5000
      || !Number.isSafeInteger(v.reported_last_applied_at) || v.reported_last_applied_at < 0 || v.reported_last_applied_at > v.observed_at) return null
  return v
}
function finish(state, raw, code, timedOut, now) {
  var v = code === 0 && !timedOut ? parse(raw,now) : null
  return v ? { current: true, last: v, error: "" } : fail(state, "System diagnostics unavailable (denied, untrusted, stale or invalid)")
}
function text(state, now) {
  var v = state.last
  if (!v) return state.error
  if (!Number.isSafeInteger(now) || now <= 0) return "System unavailable; last response age unknown · current kernel policy verification unknown"
  var elapsed = now-v.observed_at
  var age = Math.max(0, Math.floor((now-v.observed_at)/1000))
  var fresh = state.current && elapsed >= -1000 && elapsed <= 5000
  return (fresh ? "System response observed " : "System unavailable; last response ") + age + "s ago · "
    + (v.policy_known ? "policy answer known" : "policy answer unknown")
    + " · last reported refresh " + (v.policy_refresh_ok === null ? "unknown" : (v.policy_refresh_ok ? "succeeded" : "failed; retained plan may still enforce"))
    + " · " + (v.reported_last_applied_at ? "reported last applied plan " + Math.max(0,Math.floor((now-v.reported_last_applied_at)/1000)) + "s ago" : "no apply acknowledgement observed")
    + " · current kernel policy verification unknown"
}

if (typeof module !== "undefined" && module.exports) module.exports = { installedCli: installedCli, bootstrap: bootstrap, empty: empty, fail: fail, parse: parse, finish: finish, text: text }
