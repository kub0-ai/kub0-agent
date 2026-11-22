"use strict";
const assert = require("assert");
const fs = require("fs");
const vm = require("vm");
const CM = require("../ConnectionModel.js");
const Health = require("../js/Health.js");
const Traffic = require("../js/Traffic.js");
const History = require("../js/History.js");
const Prefs = require("../js/Prefs.js");

const conn = { id:"probe", proto:"tcp", inode:42, exe:"/usr/bin/probe",
  app:{ id:"probe", name:"Probe", icon:"", desktop:"", pid:4321 },
  local:{ip:"127.0.0.1",port:40000}, remote:{ip:"127.0.0.1",port:443},
  state:"ESTABLISHED", hostname:"probe.example", country:"DE" };
let model=CM.applyLine(CM.emptyState(),JSON.stringify({type:"snapshot",ts:1000,connections:[conn]}),1000);
const before=JSON.stringify(model);
const frame={ type:"bandwidth", ts:2000, apps:[{id:"probe",txBytes:1024,rxBytes:2048,txRate:512,rxRate:1024,measured:1,tcp:1}] };
assert.strictEqual(Health.classifyLine(JSON.stringify(frame)).ok,true);
model=CM.applyLine(model,JSON.stringify(frame),2000);
assert.strictEqual(model.count,1);
assert.strictEqual(model.apps.probe.traffic.rxRate,1024);
assert.strictEqual(JSON.stringify(CM.applyLine(CM.emptyState(),JSON.stringify({type:"snapshot",ts:1000,connections:[conn]}),1000)),before);
assert.ok(Traffic.summary(model.apps.probe,true).includes("1.0 KiB/s"));
assert.ok(Traffic.summary(model.apps.probe,false).includes("stale"));
assert.strictEqual(Traffic.bytes(null),"unknown");
assert.strictEqual(Traffic.bytes(0),"0 B");
for (const rate of [-1,"1024"]) {
  const bad=JSON.parse(JSON.stringify(frame)); bad.apps[0].rxRate=rate;
  assert.strictEqual(Health.classifyLine(JSON.stringify(bad)).ok,false);
}
const unknown={id:"unknown",name:"AAA",traffic:null,lastActivity:0};
assert.strictEqual(CM.orderRows({unknown,probe:model.apps.probe},"bandwidth")[0].id,"probe");
const restarted=CM.applyLine(model,JSON.stringify({type:"hello",version:"0.1",pid:1,coverage:"tcp+connected-udp",rdns:false}),3000);
assert.strictEqual(Object.keys(restarted.traffic).length,0);
const h=Health.markSocketUp(Health.markDaemonAvailable(Health.emptyHealth(),true),1000);
assert.strictEqual(Health.ingestDecision(h,JSON.stringify(frame)).applyModel,false);
assert.strictEqual(Health.ingestDecision(h,JSON.stringify(frame)).noteFresh,false);
assert.strictEqual(Prefs.openingView({startupView:"history"}),"history");
assert.strictEqual(Prefs.sanitize({sortKey:"bandwidth"}).sortKey,"bandwidth");

const csv=History.csv([{firstObserved:1000,lastObserved:2000,active:false,bytes:null,
  connection:{...conn,app:{...conn.app,name:'=1+1,"name"'}}}]);
assert.ok(csv.includes('"\'=1+1,""name"""'));
assert.ok(csv.includes(',"","","false"'));
assert.ok(csv.includes('"/usr/bin/probe"'));
assert.strictEqual(History.endpoint({remote:{ip:"::1",port:443}}),"[::1]:443");

const source=fs.readFileSync("Service.qml","utf8");
const functions=Array.from(source.matchAll(/^  function (\w+)\([^\n]*\) \{[\s\S]*?^  \}/gm));
const sent=[];
const context={eventSock:{connected:true},usingFallback:false,historySerial:0,historyEntries:[],historyTimeout:{restart(){},stop(){}},
  writeSock(line){sent.push(JSON.parse(line));}};
vm.createContext(context);
vm.runInContext(functions.find(f=>f[1]==="requestHistory")[0],context);
context.requestHistory("probe",24);
assert.strictEqual(sent.length,1); assert.strictEqual(sent[0].cmd,"history");
assert.strictEqual(sent[0].query,"probe"); assert.strictEqual(context.historyBusy,true);
context.eventSock.connected=false;
context.requestHistory("probe",24);
assert.strictEqual(sent.length,1); assert.strictEqual(context.historyBusy,false);
assert.ok(context.historyError.includes("live daemon"));
console.log("test_traffic_history.js ok");
