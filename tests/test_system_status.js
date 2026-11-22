"use strict";
const assert = require('assert');
const S = require('../js/SystemStatus.js');
const now = Date.now();
const v = {mode:'system', producer_version:'0.1.0', observed_at:now, policy_refresh_ok:false, policy_known:true, reported_last_applied_at:now-10000, current_kernel_verification:'unknown'};
const raw = JSON.stringify(v);
let s = S.finish(S.empty(),raw,0,false,now);
assert(s.current);
assert(S.text(s,now).includes('retained plan may still enforce'));
assert(S.text(s,now).includes('current kernel policy verification unknown'));
for (const [input,code,timeout] of [[raw,1,false],[raw,0,true],[raw+'{}',0,false],['{',0,false],[JSON.stringify({...v,token:'x'}),0,false],[JSON.stringify({...v,observed_at:now-6000}),0,false]]) {
  const out = S.finish(s,input,code,timeout,now);
  assert(!out.current); assert.strictEqual(out.last,s.last);
}
assert(!S.parse(JSON.stringify({...v,policy_known:'true'}),now));
assert(!S.parse(JSON.stringify({...v,current_kernel_verification:'verified'}),now));
assert(S.text(s,now+6000).includes('System unavailable'));
// User service state and helper readiness cannot feed the system reducer.
assert(!S.parse(JSON.stringify({type:'hello',mode:'system',kernel:{enforcing:true}}),now));
const fs = require('fs');
const service = fs.readFileSync('Service.qml','utf8');
assert(service.includes('clearEnvironment: true'));
assert(service.includes('systemStatusActiveGeneration !== root.systemStatusGeneration'));
assert.strictEqual(S.installedCli,'/usr/lib/kub0/kub0d');
// 0.4.5 and 0.4.6 fell back to a 0.4.x system install's daemon here.
assert.strictEqual(S.oldInstalledCli, undefined, 'one daemon path, and no fallback to a 0.4.x one');
assert(!S.bootstrap.includes('vallum'), 'the bootstrap runs /usr/lib/kub0/kub0d or nothing');
console.log('system status freshness and separation passed');
assert(S.text(s,now+5000).startsWith('System response observed'));
assert(S.text(s,now+5001).startsWith('System unavailable'));
for (const invalid of [NaN,Infinity,-Infinity,undefined,'123',0]) {
  assert.strictEqual(S.parse(raw,invalid),null);
  assert(S.text(s,invalid).startsWith('System unavailable'));
}
