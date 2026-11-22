#!/usr/bin/env python3
"""Org network-policy blocks through a real kernel, in a throwaway namespace.

`kub0-block fleet-render` prints the exact nft script fleet-sync applies;
this test runs it inside `unshare -Urn`, so the host ruleset is never touched.
TEST-NET addresses are bound to the namespace's loopback, so nothing leaves it.

Proves:
  block       a listed v4 and v6 address is dropped
  near miss   an unlisted neighbour still connects
  floor       a private address the org listed is still reachable (helper floor)
  keep        an address the caller asked to keep beats the same block entry
  resync      a second sync replaces the set without duplicating the rule
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

if os.environ.get("VALLUM_NETNS") != "1":
    if subprocess.call(["unshare", "-Urn", "true"], stderr=subprocess.DEVNULL) != 0:
        print("test_fleet_nft.py SKIPPED: unprivileged user namespaces are unavailable")
        sys.exit(0)
    sys.exit(subprocess.call(["unshare", "-Urn", sys.executable, __file__],
                             env=dict(os.environ, VALLUM_NETNS="1")))

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "target/debug/kub0-block"
V4 = ["198.51.100.7", "198.51.100.8", "198.51.100.9", "10.0.0.5"]
V6 = ["2001:db8::7", "2001:db8::8"]

subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
for a in V4:
    subprocess.run(["ip", "addr", "add", a + "/32", "dev", "lo"], check=True)
for a in V6:
    subprocess.run(["ip", "-6", "addr", "add", a + "/128", "dev", "lo", "nodad"], check=True)

listeners = {}
for a in V4 + V6:
    s = socket.socket(socket.AF_INET6 if ":" in a else socket.AF_INET)
    s.bind((a, 0))
    s.listen(16)
    listeners[a] = s


def reachable(addr):
    family = socket.AF_INET6 if ":" in addr else socket.AF_INET
    c = socket.socket(family)
    c.settimeout(1.0)
    try:
        c.connect(listeners[addr].getsockname()[:2])
        return True
    except (socket.timeout, OSError):
        return False
    finally:
        c.close()


def sync(spec, rules_present=False):
    args = [str(HELPER), "fleet-render"] + (["--rules-present"] if rules_present else [])
    script = subprocess.run(args, input=json.dumps(spec), text=True, capture_output=True, check=True).stdout
    p = subprocess.run(["nft", "-f", "-"], input=script, text=True, capture_output=True)
    assert p.returncode == 0, p.stderr


def fleet_rules():
    out = subprocess.run(["nft", "list", "chain", "inet", "vallum", "out"], text=True, capture_output=True).stdout
    return [l for l in out.splitlines() if 'comment "vallum-fleet"' in l]


assert all(reachable(a) for a in V4 + V6), "baseline: every fixture address answers"

sync({"block": ["198.51.100.7", "10.0.0.5", "198.51.100.9", "2001:db8::7"], "keep": ["198.51.100.9"]})
assert not reachable("198.51.100.7"), "listed v4 address still reachable"
assert not reachable("2001:db8::7"), "listed v6 address still reachable"
assert reachable("198.51.100.8"), "unlisted neighbour was blocked"
assert reachable("2001:db8::8"), "unlisted v6 neighbour was blocked"
assert reachable("10.0.0.5"), "private address in the org's list was blocked: the floor failed"
assert reachable("198.51.100.9"), "caller keep did not beat the block entry"
assert len(fleet_rules()) == 2, fleet_rules()

# Resync as fleet-sync does once its rules exist: new set contents, same two rules.
sync({"block": ["198.51.100.8"]}, rules_present=True)
assert reachable("198.51.100.7"), "a dropped entry stayed blocked after resync"
assert not reachable("198.51.100.8"), "the new entry is not blocked after resync"
assert len(fleet_rules()) == 2, fleet_rules()

# An empty resync blocks nothing.
sync({"block": []}, rules_present=True)
assert all(reachable(a) for a in V4 + V6), "an empty sync left something blocked"

print(json.dumps({"blocksV4": True, "blocksV6": True, "nearMissOpen": True, "floorHeld": True,
                  "callerKeepHeld": True, "resyncReplaces": True, "rulesNotDuplicated": True,
                  "emptySyncClears": True}))
