#!/usr/bin/env python3
"""Real helper and BPF checks; never use the desktop's firewall or rule store.

Entry is verify-root-enhancements.sh: root authentication, two private namespaces,
private /var/lib/kub0 bind mount, loopback only, and uniquely named test cgroups.
"""
import json
import ctypes
import errno
import hashlib
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
UID = int(os.environ.get("SUDO_UID", "0"))
GID = int(os.environ.get("SUDO_GID", "0"))
assert os.geteuid() == 0 and UID > 0 and GID > 0
assert os.readlink("/proc/self/ns/net") != os.environ["VALLUM_TEST_PARENT_NETNS"]
assert os.readlink("/proc/self/ns/mnt") != os.environ["VALLUM_TEST_PARENT_MNTNS"]
assert Path("/var/lib/kub0").is_dir(), "Existing helper state directory is required"
assert len(sys.argv) == 1, "Redirect stdout from the non-root shell to save the JSON report"
helper = ROOT / "target/release/kub0-block"
collector_bin = ROOT / "target/capture/kub0-capture"
assert helper.is_file() and collector_bin.is_file(), "Build release workspace and capture first"
token = "vallum-test-" + uuid.uuid4().hex[:16]
cgroup = Path(f"/sys/fs/cgroup/user.slice/user-{UID}.slice") / token
cgroup_created = False
stop = threading.Event()
listener = ipv6 = resolver = decoy = None
threads = []
def accept(server):
    while not stop.is_set():
        try:
            connection, _ = server.accept()
            connection.close()
        except socket.timeout:
            pass
def fixture_resolver(primary, wrong_server):
    # A resolver on 127.0.0.1:53 inside the private namespace. Every A query
    # gets three datagrams, in this order: a response with another transaction
    # id from the right server (unsolicited), a response with the right id from
    # 127.0.0.2:53 (the wrong server), then the real answer. The collector must
    # report exactly the last one.
    while not stop.is_set():
        try:
            data, peer = primary.recvfrom(512)
        except socket.timeout:
            continue
        if len(data) < 17:
            continue
        txid, flags, qdcount = struct.unpack("!HHH", data[:6])
        if flags & 0x8000 or qdcount != 1:
            continue
        end = 12
        while end < len(data) and data[end] != 0:
            end += data[end] + 1
        question = data[12:end + 5]
        def response(id_):
            return (struct.pack("!HHHHHH", id_, 0x8180, 1, 1, 0, 0) + question + b"\xc0\x0c"
                    + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([203, 0, 113, 7]))
        primary.sendto(response((txid + 1) & 0xFFFF or 1), peer)
        wrong_server.sendto(response(txid), peer)
        primary.sendto(response(txid), peer)
CHILD = r'''
import json, socket, sys, time
print(json.dumps({"ready": True}), flush=True)
for line in sys.stdin:
    c = json.loads(line)
    if c.get("dns"):
        # One A query from an unconnected UDP socket, then everything that
        # reaches the socket within 1.5 s, so the parent can tell which of the
        # resolver's datagrams the kernel delivered (all of them) against which
        # one the collector reported.
        import random, struct
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        sock.bind(("127.0.0.1", 0))
        txid = random.randrange(1, 65535)
        name = b"".join(bytes([len(l)]) + l for l in c["dns"].encode().split(b".")) + b"\x00"
        sock.sendto(struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + name + struct.pack("!HH", 1, 1), (c["ip"], 53))
        got = []
        deadline = time.monotonic() + 1.5
        while time.monotonic() < deadline:
            try:
                data, peer = sock.recvfrom(512)
            except socket.timeout:
                break
            got.append({"id": struct.unpack("!H", data[:2])[0], "from": peer[0], "matchesQuery": struct.unpack("!H", data[:2])[0] == txid})
        sock.close()
        print(json.dumps({"txid": txid, "received": got}), flush=True)
        continue
    started = time.process_time()
    successes = 0
    for i in range(c.get("count", 1)):
        sock = socket.socket(socket.AF_INET6 if c.get("v6") else socket.AF_INET,
                             socket.SOCK_DGRAM if c.get("udp") else socket.SOCK_STREAM)
        sock.settimeout(0.2)
        try:
            if c.get("udp"):
                sock.sendto(b"local probe", (c["ip"], c["port"]))
            else:
                sock.connect((c["ip"], c["port"]))
            successes += 1
        except OSError:
            pass
        finally:
            sock.close()
    print(json.dumps({"successes": successes, "cpuSeconds": time.process_time()-started}), flush=True)
'''

def child(uid=UID, gid=GID):
    p = subprocess.Popen([sys.executable, "-c", CHILD], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, text=True, user=uid, group=gid, extra_groups=[])
    try:
        assert select.select([p.stdout], [], [], 10)[0], "child startup stalled"
        assert json.loads(p.stdout.readline())["ready"]
    except BaseException:
        p.terminate()
        p.wait(timeout=3)
        raise
    return p

def probe(p, ip="127.0.0.1", **kwargs):
    p.stdin.write(json.dumps(dict(ip=ip, port=port, **kwargs))+"\n")
    p.stdin.flush()
    assert select.select([p.stdout], [], [], 30)[0], "probe stalled"
    return json.loads(p.stdout.readline())

def where(pid):
    return Path(f"/proc/{pid}/cgroup").read_text().strip().split("::", 1)[1]

def attached():
    lib = ctypes.CDLL("libbpf.so.1", use_errno=True)
    programs = {}
    fd = os.open(cgroup, os.O_RDONLY | os.O_DIRECTORY)
    try:
        # linux/bpf.h: INET4/6_CONNECT and UDP4/6_SENDMSG attach types.
        for kind in (10, 11, 14, 15):
            ids = (ctypes.c_uint32 * 256)()
            count, flags = ctypes.c_uint32(256), ctypes.c_uint32()
            assert lib.bpf_prog_query(fd, kind, 0, ctypes.byref(flags), ids, ctypes.byref(count)) == 0
            programs[kind] = sorted(ids[:count.value])
        return programs
    finally:
        os.close(fd)

env = dict(os.environ, PKEXEC_UID=str(UID))
processes = []
capture = None
frames = []
reader = None
reader_pause = threading.Event()
report = dict(status="running", kernel=os.uname().release,
    binaries={name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in (("helper", helper), ("collector", collector_bin))},
    isolation=dict(privateNetwork=True, privateMount=True, privateRuleState=False))
slice_existed = Path("/sys/fs/cgroup/vallum.slice").exists()
scope = Path(f"/sys/fs/cgroup/vallum.slice/vallum-__vallum_scoped_{UID}_{token.encode().hex()}")
try:
    subprocess.run(["/usr/bin/ip", "link", "set", "lo", "up"], check=True)
    cgroup.mkdir()
    cgroup_created = True
    listener = socket.create_server(("0.0.0.0", 0))
    listener.settimeout(0.1)
    port = listener.getsockname()[1]
    ipv6 = socket.socket(socket.AF_INET6)
    ipv6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    ipv6.bind(("::1", port))
    ipv6.listen(128)
    ipv6.settimeout(0.1)
    for server in (listener, ipv6):
        thread = threading.Thread(target=accept, args=(server,), daemon=True)
        thread.start()
        threads.append(thread)
    # Port 53 on loopback is free inside the private network namespace.
    resolver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    resolver.bind(("127.0.0.1", 53))
    resolver.settimeout(0.1)
    decoy = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    decoy.bind(("127.0.0.2", 53))
    thread = threading.Thread(target=fixture_resolver, args=(resolver, decoy), daemon=True)
    thread.start()
    threads.append(thread)
    with tempfile.TemporaryDirectory(prefix="vallum-root-verification-") as td:
        state = Path(td) / "state"
        state.mkdir(mode=0o755)
        # This bind is visible only in our private mount namespace. The helper
        # and its expiry path cannot read or restore the operator's real rules.
        subprocess.run(["/usr/bin/mount", "--bind", str(state), "/var/lib/kub0"], check=True)
        report["isolation"]["privateRuleState"] = True
        a = child()
        processes.append(a)
        b = child()
        processes.append(b)
        (cgroup / "cgroup.procs").write_text(str(a.pid))
        original = where(a.pid)
        assert probe(a)["successes"] == probe(b)["successes"] == 1
        def helper_call(*args):
            result = subprocess.run([str(helper), *map(str, args)], env=env,
                text=True, capture_output=True, timeout=30)
            assert result.returncode == 0, result.stderr
            value = json.loads(result.stdout)
            assert value.get("ok") is not False, value
            return value
        helper_call("block-scoped", token, "127.0.0.1", 4, a.pid)
        assert scope.is_dir() and where(a.pid) == "/" + str(scope.relative_to("/sys/fs/cgroup"))
        assert probe(a)["successes"] == 0
        assert probe(a, "127.0.0.2")["successes"] == 1
        assert probe(b)["successes"] == 1
        time.sleep(4.2)
        assert probe(a)["successes"] == 1, "kernel deadline did not restore traffic"
        helper_call("expire-scoped")
        assert where(a.pid) == original and not scope.exists()
        helper_call("block-scoped", token, "127.0.0.1", 60, a.pid)
        helper_call("unblock-scoped", token, "127.0.0.1")
        assert probe(a)["successes"] == 1 and where(a.pid) == original and not scope.exists()
        helper_call("block-scoped", token, "127.0.0.1", 60, a.pid)
        retry = helper_call("block-scoped", token, "127.0.0.1", 60, a.pid)
        assert retry["verified"] is False and retry["ruleVerified"] is True and retry["warning"]
        helper_call("unblock-scoped", token, "127.0.0.1")
        report["scoped"] = dict(targetBlocked=True, otherDestinationAllowed=True,
            otherApplicationAllowed=True, kernelExpiry=True, restoreMembership=True, cancel=True,
            retryDoesNotInventVerification=True,
            globalTeardown="not run: host cgroup tree is shared")
        baseline = probe(a, udp=True, count=10000)
        attachments_before = attached()
        capture = subprocess.Popen([str(collector_bin), "--cgroup", str(cgroup)], env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        def consume():
            for line in capture.stdout:
                while reader_pause.is_set():
                    time.sleep(0.005)
                frames.append(json.loads(line))
        reader = threading.Thread(target=consume, daemon=True)
        reader.start()
        deadline = time.monotonic()+10
        while not any(f.get("type") == "capture-status" for f in frames):
            assert capture.poll() is None, "BPF load/attach failed"
            assert time.monotonic() < deadline, "no collector readiness"
            time.sleep(0.05)
        assert all(len(attached()[kind]) == len(attachments_before[kind])+1 for kind in attachments_before)
        assert probe(a, count=100)["successes"] == 100
        assert probe(a, "::1", v6=True, count=100)["successes"] == 100
        assert probe(a, "::1", udp=True, v6=True, count=100)["successes"] == 100
        observed = probe(a, udp=True, count=10000)
        time.sleep(1.2)
        attempts = [f for f in frames if f.get("type") == "attempt"]
        assert any(f["proto"] == "tcp" and f["operation"] == "connect" for f in attempts)
        assert any(f["proto"] == "tcp" and f["ip"] == "::1" for f in attempts)
        assert any(f["proto"] == "udp" and f["operation"] == "sendmsg" and
                   f["ip"] == "::1" for f in attempts)
        assert any(f["proto"] == "udp" and f["operation"] == "sendmsg" and
                   f["ip"] == "127.0.0.1" for f in attempts)
        assert all(f["port"] == port for f in attempts), "destination port was corrupted"
        assert all(f["uid"] == UID and f["pid"] == a.pid for f in attempts)
        before = len(attempts)
        probe(b, udp=True, count=100)
        time.sleep(0.3)
        assert len([f for f in frames if f.get("type") == "attempt"]) == before, "capture escaped test cgroup"
        def next_status():
            start = len(frames)
            deadline = time.monotonic() + 5
            while True:
                statuses = [f for f in frames[start:] if f.get("type") == "capture-status"]
                if statuses:
                    return statuses[-1]
                assert capture.poll() is None, "collector stopped before reporting counters"
                assert time.monotonic() < deadline, "collector counters stalled"
                time.sleep(0.05)
        counters_before_foreign = next_status()
        # Root is deliberately a foreign UID inside the observed test cgroup.
        # Its loopback sends must not pass the kernel's target-UID filter.
        foreign = child(uid=0, gid=0)
        processes.append(foreign)
        (cgroup / "cgroup.procs").write_text(str(foreign.pid))
        assert probe(foreign, udp=True, count=100)["successes"] == 100
        counters_after_foreign = next_status()
        assert len([f for f in frames if f.get("type") == "attempt"]) == before, "capture accepted a foreign UID"
        # Checking only published attempts could pass if the kernel emitted
        # foreign events and the collector rejected them. Verify both layers.
        for counter in ("emitted", "received", "invalid", "kernelDropped"):
            assert counters_after_foreign[counter] == counters_before_foreign[counter], \
                f"foreign UID changed capture counter {counter}"
        # DNS answers (docs/CAPTURE.md, "DNS answers"): a response is reported
        # only when this socket asked, from the server it asked, and never for
        # a foreign UID. The fixture resolver sends two forgeries before the
        # real answer; the kernel delivers all three to the socket.
        if counters_after_foreign.get("dns"):
            frames_before = len(frames)
            asked = probe(a, dns="capture-test.example")
            assert len(asked["received"]) == 3, f"fixture resolver datagrams not all delivered: {asked}"
            assert asked["received"][2]["matchesQuery"] and asked["received"][2]["from"] == "127.0.0.1", asked
            time.sleep(0.5)
            dns_frames = [f for f in frames[frames_before:] if f.get("type") == "dns"]
            assert len(dns_frames) == 1, f"expected exactly the matched answer, got {dns_frames}"
            assert dns_frames[0]["name"] == "capture-test.example" and dns_frames[0]["ip"] == "203.0.113.7" \
                and dns_frames[0]["server"] == "127.0.0.1" and dns_frames[0]["uid"] == UID, dns_frames[0]
            dns_after = next_status()
            assert dns_after["dnsQueries"] >= counters_after_foreign["dnsQueries"] + 1, "the query was not recorded"
            assert dns_after["dnsUnmatched"] >= counters_after_foreign["dnsUnmatched"] + 2, "the forgeries were not refused"
            frames_before = len(frames)
            assert len(probe(foreign, dns="capture-test.example")["received"]) == 3
            time.sleep(0.5)
            foreign_dns = next_status()
            assert not [f for f in frames[frames_before:] if f.get("type") == "dns"], "a foreign UID's answer was reported"
            assert foreign_dns["dnsQueries"] == dns_after["dnsQueries"], "a foreign UID's query was recorded"
            report["dnsCapture"] = dict(matchedAnswerReported=True, unsolicitedResponseIgnored=True,
                wrongServerIgnored=True, foreignUidIgnored=True, serverReported="127.0.0.1")
        else:
            report["dnsCapture"] = "not run: the kernel refused the DNS programs"
        reader_pause.set()
        probe(a, udp=True, count=30000)
        reader_pause.clear()
        time.sleep(1.3)
        statuses = [f for f in frames if f.get("type") == "capture-status"]
        assert statuses[-1]["collectorDropped"] > 0, "backpressure loss was not reported"
        capture.stdin.close()
        assert capture.wait(timeout=3) == 0
        reader.join(timeout=3)
        assert attached() == attachments_before, "collector left cgroup attachments"
        # Compare actual cgroup attachment listings before removal. No pins or
        # links persist when the collector's owned FDs close.
        report["capture"] = dict(tcpAttempts=True, ipv4UnconnectedUdp=True, ipv6UnconnectedUdp=True,
            destinationPort=True,
            uidAndCgroupIsolation=True, backpressureLossReported=True,
            collectorExitedOnEof=True, kernelAttachmentsRemoved=True, baselineCpuSeconds=baseline["cpuSeconds"],
            capturedCpuSeconds=observed["cpuSeconds"], lastCounters=statuses[-1])
        # Kernel cgroup removal also proves no active process was left there.
        for p in processes:
            p.stdin.close()
            p.wait(timeout=3)
        processes = []
        subprocess.run(["/usr/bin/umount", "/var/lib/kub0"], check=True)
    report["status"] = "passed"
except BaseException as error:
    report["status"] = "failed"
    report["error"] = f"{type(error).__name__}: {error}"
    raise
finally:
    try:
        reader_pause.clear()
        if capture and capture.poll() is None:
            capture.terminate()
            capture.wait(timeout=3)
        for p in processes:
            p.terminate()
            p.wait(timeout=3)
        stop.set()
        for thread in threads:
            thread.join(timeout=2)
        if listener:
            listener.close()
        if ipv6:
            ipv6.close()
        for sock in (resolver, decoy):
            if sock:
                sock.close()
        if scope.exists():
            scope.rmdir()  # only the uniquely named test scope; fail if not empty
        if cgroup_created:
            cgroup.rmdir()
        if not slice_existed:
            try:
                Path("/sys/fs/cgroup/vallum.slice").rmdir()
            except OSError as error:
                # A concurrent helper may now own a child. Never remove its
                # cgroup or treat the shared parent's continued use as our leak.
                if error.errno not in (errno.ENOTEMPTY, errno.ENOENT):
                    raise
        report["cleanup"] = "passed"
    except BaseException as error:
        report["status"] = "failed"
        report["cleanupError"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        # Emit partial evidence even if loading a hook or cleaning up failed.
        # Only the non-root caller opens the redirected report path.
        print(json.dumps(report), flush=True)
