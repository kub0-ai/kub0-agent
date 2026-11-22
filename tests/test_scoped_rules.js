"use strict";
const assert=require("assert"),fs=require("fs"),vm=require("vm"),Rules=require("../js/Rules.js");
const app={id:"probe",pids:[123],connections:[{remote:{ip:"127.0.0.1"},state:"ESTABLISHED"},{remote:{ip:"127.0.0.1"}},{remote:{ip:"0.0.0.0"},unresolved:true},{remote:{ip:"192.0.2.1"},state:"closed"}]};
assert.deepStrictEqual(Rules.destinations(app),["127.0.0.1"]);
assert.strictEqual(Rules.active([{app:"probe",expiresAt:1000},{app:"other",expiresAt:3000}],"probe",2000).length,0);
const source=fs.readFileSync("Service.qml","utf8");
const functions=Array.from(source.matchAll(/^  function (\w+)\([^\n]*\) \{[\s\S]*?^  \}/gm));
const sent=[],ctx={appById:()=>app,blockingReady:true,helperBusy:false,helperInstalled:true,health:{},model:{blocked:{}},Health:{canDispatchNewBlock:()=>true},ConnectionModel:{isBlockable:()=>true,pidsOf:a=>a.pids},submitChange:a=>sent.push(a),eventSource:"user",sessionUid:-1,otherAccountsApp:"another account's"};
vm.createContext(ctx);
for(const name of ["requestDestinationBlock","cancelDestinationBlock","ownPids"])vm.runInContext(functions.find(f=>f[1]===name)[0],ctx);
ctx.requestDestinationBlock("probe","127.0.0.1",900);
assert.deepStrictEqual(Array.from(sent[0]),["block-scoped","probe","127.0.0.1","900","123"]);
ctx.Health.canDispatchNewBlock=()=>false;ctx.requestDestinationBlock("probe","127.0.0.1",900);assert.strictEqual(sent.length,1);
ctx.cancelDestinationBlock("probe","127.0.0.1");assert.deepStrictEqual(Array.from(sent[1]),["unblock-scoped","probe","127.0.0.1"]);
console.log("test_scoped_rules.js ok");

// Exercise the actual QML binding with a mixed-case desktop id.
const CM = require("../ConnectionModel.js");
const destinationQml = fs.readFileSync("DestinationRules.qml", "utf8");
const binding = destinationQml.match(/readonly property var activeRules: \{([\s\S]*?)\n  \}/)[1];
const mixed = "com.discordapp.Discord";
const rules = [{app:CM.helperId(mixed),ip:"127.0.0.1",expiresAt:99999999}];
const bound = {Rules,ConnectionModel:CM,service:{temporaryRules:rules,healthTick:1000},app:{id:mixed}};
vm.createContext(bound);
assert.strictEqual(vm.runInContext("(function(){"+binding+"})()",bound).length,1);
let model = CM.applyLine(CM.emptyState(),JSON.stringify({type:"snapshot",ts:1000,connections:[
  {id:"c",app:{id:mixed,name:"Discord",pid:123},state:"ESTABLISHED",remote:{ip:"127.0.0.1",port:443}}
]}),1000);
const service = {model,ConnectionModel:CM,temporaryRules:[],blockProc:{command:["pkexec","helper","block-scoped",mixed]},syncFromModel(){}};
vm.createContext(service);
vm.runInContext(functions.find(f=>f[1]==="onBlockOutput")[0],service);
vm.runInContext(functions.find(f=>f[1]==="applyChangeOutcome")[0],service);
service.onBlockOutput(JSON.stringify({ok:true,verified:false,ruleVerified:true,warning:"existing sockets not reverified",temporaryRules:rules}));
service.model = CM.applyLine(service.model,JSON.stringify({type:"snapshot",ts:2000,connections:[]}),2000);
assert.strictEqual(service.model.count,0);
assert.strictEqual(service.model.apps[mixed].name,"Discord");
assert.strictEqual(service.model.apps[mixed].hasTemporaryRule,true);
assert.strictEqual(service.model.apps[mixed].blocked,false);
assert.strictEqual(service.model.apps[mixed].pids.length,0);
assert.strictEqual(service.lastBlockError,"existing sockets not reverified");
assert(destinationQml.includes('root.service.helperInstalled'),"cancellation independent of fresh sampled PIDs");
service.onBlockOutput(JSON.stringify({ok:true,verified:true,teardown:true}));
assert.strictEqual(service.temporaryRules.length,0);
assert.strictEqual(service.model.ordered.length,0);
console.log("mixed-case cancellation, dormant scoped row, retry warning and teardown reconciliation passed");

// A status can be the only input while the daemon is unavailable. Publish the
// revised model on both appearance and removal, without a whole-app change.
const status = {model:CM.emptyState(),ConnectionModel:CM,Health:require("../js/Health.js"),
  statusRequestGeneration:0,helperMutationGeneration:0,blockProc:{running:false},changeRunning:()=>false,
  modelRevision:0,temporaryRules:[],syncCalls:0,
  syncFromModel:()=>{status.modelRevision=status.model.revision;status.syncCalls++;}};
vm.createContext(status);
vm.runInContext(functions.find(f=>f[1]==="applyHelperStatus")[0],status);
const update = rows => status.applyHelperStatus(JSON.stringify({ok:true,table:true,blockingReady:true,
  cgroupBlocks:[],owners:{},temporaryRulesKnown:true,temporaryRules:rows}));
update(rules);
assert.strictEqual(status.model.ordered.length,1);
assert.strictEqual(status.modelRevision,status.model.revision);
assert.strictEqual(status.syncCalls,1);
update([]);
assert.strictEqual(status.model.ordered.length,0);
assert.strictEqual(status.modelRevision,status.model.revision);
assert.strictEqual(status.syncCalls,2);
update(rules);
status.applyHelperStatus(JSON.stringify({ok:true,table:true,blockingReady:true,cgroupBlocks:[],owners:{},temporaryRulesKnown:false,temporaryRulesError:"permission denied",temporaryRules:[]}));
assert.strictEqual(status.model.ordered.length,1,"unknown state must preserve known cancellation");
assert.strictEqual(status.temporaryRulesError,"permission denied");
console.log("status-only scoped appearance/removal publishes the model; unknown state preserves cancellation");
