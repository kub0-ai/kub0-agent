"use strict";
const assert=require("assert"),CM=require("../ConnectionModel.js"),E=require("../js/Evidence.js");
const raw={id:"one",proto:"tcp",exe:"/usr/bin/probe",uid:1000,app:{id:"probe",name:"Probe",pid:4321},local:{ip:"::1",port:40000},remote:{ip:"2001:db8::1",port:443},state:"closed",evidence:{source:"opensnitch",recordedAt:1000,ownerMethod:"source-reported",verdict:{action:"deny",provenance:"external",rule_id:"external-rule"}},clue:{label:"Maybe",basis:"comm matched",confidence:"weak"},tag:{label:"Mine",source:"user"}};
const m=CM.applyLine(CM.emptyState(),JSON.stringify({type:"snapshot",ts:1000,connections:[raw]}),1000),c=m.connections.one;
assert.strictEqual(c.exe,"/usr/bin/probe");assert.strictEqual(c.evidence.verdict.rule_id,"external-rule");
const rows=E.describe(c),get=label=>rows.find(r=>r.label===label).value;
assert.strictEqual(get("Reported verdict"),"deny");assert.strictEqual(get("Decision maker"),"External enforcement engine");
assert.strictEqual(get("User annotation"),"Mine");assert.ok(get("Inferred owner").includes("weak"));
assert.strictEqual(get("Destination"),"[2001:db8::1]:443");
const old=E.describe({app:{pid:0},remote:{ip:"127.0.0.1",port:443}});
assert.ok(old.some(r=>r.label==="Reported verdict" && r.value.includes("No enforcement decision")));
assert.ok(old.some(r=>r.label==="Observation source" && r.value.includes("Unknown")));
// The daemon's per-connection policy matches survive normalizeConn (an allow-list) and
// render as one evidence row; a row without matches has no such row.
const praw=Object.assign({},raw,{id:"two",policy:[{ruleId:"r1",label:"Known C2: kub0 threat intel addresses",extra:1},{label:""},{ruleId:"x"}]});
const pm=CM.applyLine(CM.emptyState(),JSON.stringify({type:"snapshot",ts:1000,connections:[praw]}),1000).connections.two;
assert.deepStrictEqual(pm.policy,[{ruleId:"r1",label:"Known C2: kub0 threat intel addresses"}]);
const prow=E.describe(pm).find(r=>r.label==="Org network policy");
assert.ok(prow && prow.value.startsWith("Known C2: kub0 threat intel addresses\n") && prow.value.includes("monitor only"));
assert.ok(!rows.some(r=>r.label==="Org network policy"));
assert.deepStrictEqual(c.policy,[]);
console.log("test_evidence.js ok");
