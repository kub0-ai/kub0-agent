"use strict";
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const cp = require('child_process');
const S = require('../js/SystemStatus.js');
const dir = fs.mkdtempSync(path.join(os.tmpdir(),'kub0-provenance-'));
// The one fixed path goes to a private one, so a test never reaches a real install.
const sub = (text, fake) => text.replaceAll(S.installedCli,fake);
try {
  const fake = path.join(dir,'kub0d');
  const marker = path.join(dir,'executed');
  fs.writeFileSync(fake,'#!/usr/bin/python3\nopen('+JSON.stringify(marker)+',"w").write("bad")\n');
  fs.chmodSync(fake,0o755);
  if (process.getuid() === 0) {
    // Namespace-only positive control with a private ancestry boundary. This
    // source substitution is confined to this test; production checks to '/'.
    const privateBootstrap = sub(S.bootstrap,fake).replace("if q=='/': break", "if q=="+JSON.stringify(dir)+": break");
    const privateRun = () => cp.spawnSync('/usr/bin/python3',['-I','-S','-c',privateBootstrap],{env:{LANG:'C',LC_ALL:'C'},encoding:'utf8'});
    assert.strictEqual(privateRun().status,0); assert(fs.existsSync(marker)); fs.unlinkSync(marker);
    fs.chmodSync(fake,0o777); assert.notStrictEqual(privateRun().status,0); assert(!fs.existsSync(marker)); fs.chmodSync(fake,0o755);
    fs.chmodSync(dir,0o770); assert.notStrictEqual(privateRun().status,0); fs.chmodSync(dir,0o700);
    const real = fake+'.real'; fs.renameSync(fake,real); fs.symlinkSync(real,fake);
    assert.notStrictEqual(privateRun().status,0); fs.unlinkSync(fake); fs.renameSync(real,fake);
    console.log('namespace protected CLI positive control and isolated metadata failures passed');
  }
  // Test-only substitution of fixed path. Production has no override.
  const run = () => cp.spawnSync('/usr/bin/python3',['-I','-S','-c',sub(S.bootstrap,fake)],{env:{LANG:'C',LC_ALL:'C'},encoding:'utf8'});
  assert.notStrictEqual(run().status,0); assert(!fs.existsSync(marker));
  fs.chmodSync(fake,0o777); assert.notStrictEqual(run().status,0);
  fs.unlinkSync(fake); fs.symlinkSync('/usr/bin/true',fake); assert.notStrictEqual(run().status,0);
  fs.unlinkSync(fake); assert.notStrictEqual(run().status,0);
  // PATH discovery is absent even when a fake executable is present.
  assert(!S.bootstrap.includes('which')); assert(S.bootstrap.includes('os.lstat(q)'));
  assert(S.bootstrap.includes("os.execve(p,[p,'system-status'],{'LANG':'C','LC_ALL':'C'})"));
  // One path, chosen before any check and never swapped for another: 0.4.5
  // and 0.4.6 fell back to a 0.4.x daemon when nothing was at this one.
  assert(!S.bootstrap.includes('os.path.lexists'), 'no second path to fall back to');
  assert.strictEqual(S.bootstrap.split("\nq=p\n")[0], "import os,stat\np='/usr/lib/kub0/kub0d'");
} finally { fs.rmSync(dir,{recursive:true,force:true}); }
console.log('installed executable provenance rejects private fake, writable, symlink and missing paths');
