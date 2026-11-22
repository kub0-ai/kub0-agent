#!/usr/bin/env python3
"""Native SDK ABI, PID-count contract, and private libproc daemon IPC gate.

Fails on non-Darwin; never represents a Linux run as Apple evidence.
Only synthetic flow summaries and count/ABI measurements reach stdout.
"""
import ctypes
import json
import os
from pathlib import Path
import platform
import select
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
# Explicit mapping from the actual driver's Rust types/fields to Apple headers.
TYPES = {
    'InSockinfo': 'struct in_sockinfo', 'TcpSockinfo': 'struct tcp_sockinfo',
    'SocketInfo': 'struct socket_info', 'SocketFdInfo': 'struct socket_fdinfo',
    'libc::proc_fdinfo': 'struct proc_fdinfo', 'c_int': 'int',
    'SocketProto': '__typeof__(((struct socket_info*)0)->soi_proto)',
}
FIELDS = {
    'InSockinfo': ['insi_fport', 'insi_lport', 'insi_gencnt', 'insi_vflag', 'insi_faddr', 'insi_laddr'],
    'TcpSockinfo': ['tcpsi_ini', 'tcpsi_state'],
    'SocketInfo': ['soi_protocol', 'soi_family', 'soi_kind', 'soi_proto'],
    'SocketFdInfo': ['psi'], 'libc::proc_fdinfo': ['proc_fd', 'proc_fdtype'],
}
CONSTANTS = ['PROC_PIDFDSOCKETINFO', 'SOCKINFO_IN', 'SOCKINFO_TCP', 'INI_IPV4', 'INI_IPV6',
             'TSI_S_CLOSED', 'TSI_S_LISTEN', 'TSI_S_ESTABLISHED', 'TSI_S_TIME_WAIT']
LIBC_CONSTANTS = ['PROC_PIDLISTFDS', 'PROX_FDTYPE_SOCKET', 'PROC_PIDPATHINFO_MAXSIZE',
                  'AF_INET', 'AF_INET6', 'IPPROTO_UDP']


def run(cmd, **kwargs):
    return subprocess.check_output(cmd, text=True, timeout=240, **kwargs)


def abi_gate(private):
    c = ['#include <libproc.h>', '#include <sys/proc_info.h>', '#include <sys/socket.h>',
         '#include <netinet/in.h>', '#include <stddef.h>', '#include <stdio.h>',
         '#include <stdlib.h>', '#include <unistd.h>', 'int main(void) {']
    rust = ['pub fn gate() {']
    def measure(key, ce, re):
        c.append(f'printf("{key}=%zu\\n", (size_t)({ce}));')
        rust.append(f'println!("{key}={{}}", {re});')
    for rt, ct in TYPES.items():
        for label, cf, rf in [('size', 'sizeof', 'size_of'), ('align', '_Alignof', 'align_of')]:
            measure(f'{rt}.{label}', f'{cf}({ct})', f'std::mem::{rf}::<{rt}>()')
    for rt, fields in FIELDS.items():
        for field in fields:
            measure(f'{rt}.{field}', f'offsetof({TYPES[rt]}, {field})', f'std::mem::offset_of!({rt}, {field})')
            measure(f'{rt}.{field}.size', f'sizeof((({TYPES[rt]}*)0)->{field})', f'std::mem::size_of_val(&unsafe {{ std::mem::zeroed::<{rt}>() }}.{field})')
    # The flattened union view must match both UDP and TCP arms; IPv4 padding
    # and IPv6 addresses are independently checked against header members.
    measure('proto.tcp', 'offsetof(struct socket_info, soi_proto.pri_tcp)-offsetof(struct socket_info, soi_proto)', 'std::mem::offset_of!(SocketProto, tcp)')
    measure('proto.in', 'offsetof(struct socket_info, soi_proto.pri_in)-offsetof(struct socket_info, soi_proto)', 'std::mem::offset_of!(SocketProto, tcp) + std::mem::offset_of!(TcpSockinfo, tcpsi_ini)')
    measure('ipv4.padding', 'offsetof(struct in4in6_addr, i46a_addr4)', '12usize')
    measure('address.size', 'sizeof(((struct in_sockinfo*)0)->insi_faddr)', 'std::mem::size_of::<[u8;16]>()')
    measure('ipv6.size', 'sizeof(struct in6_addr)', 'std::mem::size_of::<[u8;16]>()')
    # Opaque process metadata prefix: its size is the psi offset in Rust.
    measure('pfi.size', 'sizeof(struct proc_fileinfo)', 'std::mem::offset_of!(SocketFdInfo, psi)')
    for name in CONSTANTS + LIBC_CONSTANTS:
        measure(name, name, ('libc::' if name in LIBC_CONSTANTS else '') + name)
    c += [r'''
    int hint = proc_listallpids(NULL, 0);
    if (hint <= 0) return 2;
    int cap = hint < 5120 ? hint + 1024 : 6144;
    int *pids = malloc((size_t)cap * sizeof(int));
    if (!pids) return 3;
    for (int i=0; i<cap; i++) pids[i] = -1234567;
    int got = proc_listallpids(pids, cap * sizeof(int));
    int written=0, positive=0, own=0;
    for (int i=0; i<cap; i++) {
        if (pids[i] != -1234567) written++;
        if (pids[i] > 0) positive++;
        if (pids[i] == getpid()) own++;
    }
    if (got <= 0 || got != written || own != 1) return 4;
    printf("counts=%d,%d,%d\n", got, written, positive);
    free(pids);
    return 0;
}''']
    rust += [r'''
    assert_eq!(pid_capacity(800), 864, "PID entry-count capacity");
    assert_eq!(pid_capacity(c_int::MAX), MAX_PIDS);
    assert_eq!(pid_capacity(-1), 64);
    let mut p = vec![1; 800]; p[0] = 0; p[1] = -1;
    retain_pids(&mut p, 800); assert_eq!(p.len(), 798);
    let mut p = vec![1, 2, 3]; retain_pids(&mut p, c_int::MAX); assert_eq!(p.len(), 3);
    retain_pids(&mut p, -1); assert!(p.is_empty());
    // Exercise the actual delivered API walk, without disclosing any PID list.
    let pids = LibprocSource::list_pids().unwrap();
    assert!(pids.contains(&(std::process::id() as c_int)));
    assert!(pids.len() <= MAX_PIDS);
    // A direct independent API call should cover approximately the same fleet;
    // tolerate process churn, but reject the baseline quarter-count retention.
    let mut direct = vec![0 as c_int; MAX_PIDS];
    let n = unsafe { libc::proc_listallpids(direct.as_mut_ptr().cast(),
        (direct.len()*std::mem::size_of::<c_int>()) as c_int) };
    assert!(n > 0);
    direct.truncate((n as usize).min(MAX_PIDS)); direct.retain(|p| *p > 0);
    assert!(pids.len() + 32 >= direct.len(), "PID coverage truncated");
    println!("rust_counts={},{}", pids.len(), direct.len());
}''']
    (private / 'probe.c').write_text('\n'.join(c))
    run(['xcrun', 'clang', '-std=gnu11', '-Wall', '-Werror', str(private / 'probe.c'), '-o', str(private / 'probe')])
    cout = run([str(private / 'probe')])
    crate = private / 'rust-probe'
    (crate / 'src').mkdir(parents=True)
    (crate / 'Cargo.toml').write_text('[package]\nname="darwin-abi-probe"\nversion="0.0.0"\nedition="2021"\n[dependencies]\nlibc="0.2"\nvallumd={path=' + json.dumps(str(ROOT / 'daemon')) + '}\n')
    # Preserve source-pinned dependencies, including yanked releases, offline.
    # Cargo may update this temporary lock to register the probe root package.
    (crate / 'Cargo.lock').write_bytes((ROOT / 'Cargo.lock').read_bytes())
    driver = (ROOT / 'daemon/src/source/libproc.rs').read_text()
    (crate / 'src/driver.rs').write_text(driver + '\n' + '\n'.join(rust))
    (crate / 'src/main.rs').write_text('mod flow { pub use vallumd::flow::*; }\nmod source { pub use vallumd::source::*; }\nmod driver;\nfn main() { driver::gate(); }\n')
    env = dict(os.environ, CARGO_TARGET_DIR=str(ROOT / 'target'))
    rout = run(['cargo', 'run', '--offline', '--quiet', '--manifest-path', str(crate / 'Cargo.toml')], env=env)
    def values(output):
        return dict(line.split('=', 1) for line in output.splitlines() if '=' in line)
    cv, rv = values(cout), values(rout)
    counts = cv.pop('counts'); rust_counts = rv.pop('rust_counts')
    assert cv == rv, 'SDK/Rust ABI mismatch: ' + repr({k: (v, rv.get(k)) for k, v in cv.items() if rv.get(k) != v})
    # Mutation check: the gate must reject the exact baseline count conversion.
    baseline = (crate / 'src/driver.rs').read_text().replace('(need.max(0) as usize).saturating_add(64)', '(need.max(0) as usize / std::mem::size_of::<c_int>()).saturating_add(64)').replace('(got.max(0) as usize).min(pids.len())', '(got.max(0) as usize / std::mem::size_of::<c_int>()).min(pids.len())')
    (crate / 'src/driver.rs').write_text(baseline)
    result = subprocess.run(['cargo', 'run', '--offline', '--quiet', '--manifest-path', str(crate / 'Cargo.toml')], env=env, capture_output=True, text=True, timeout=240)
    assert result.returncode != 0, 'gate accepted baseline PID count conversion'
    assert 'panicked' in result.stderr and 'PID entry-count capacity' in result.stderr, 'baseline must fail the executable PID-count contract, not compilation'
    print(f'ABI: {len(cv)} SDK/Rust measurements matched; C counts={counts}; Rust counts={rust_counts}; baseline rejected')
    return int(cv['PROC_PIDPATHINFO_MAXSIZE'])


SOCKET_TIMEOUT = 3


def matches(flow, spec):
    proto, ip, local_port, remote_port = spec
    local, remote = flow.get('local'), flow.get('remote')
    return (isinstance(local, dict) and isinstance(remote, dict)
            and flow.get('proto') == proto
            and local.get('ip') == ip and local.get('port') == local_port
            and remote.get('ip') == ip and remote.get('port') == remote_port)


def endpoint_self_test():
    spec = ('tcp', '127.0.0.1', 1234, 5678)
    good = {'proto': 'tcp', 'local': {'ip': spec[1], 'port': spec[2]},
            'remote': {'ip': spec[1], 'port': spec[3]}}
    assert matches(good, spec)
    for endpoint in ('local', 'remote'):
        absent = dict(good); del absent[endpoint]
        assert not matches(absent, spec)
        for value in (None, {}, {'ip': '::1', 'port': 1234}):
            assert not matches(dict(good, **{endpoint: value}), spec)
    assert not matches(dict(good, proto='udp'), spec)
    assert not matches(dict(good, remote={'ip': spec[1], 'port': 9999}), spec)
    print('self-test: absent/null/nonmatching/matching endpoints passed (no Apple evidence)')


def own_process_image(buffer_size):
    # SDK-measured size; signature independently taken from Apple's libproc API.
    assert 1 < buffer_size <= 1024 * 1024
    libproc = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
    proc_pidpath = libproc.proc_pidpath
    proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    proc_pidpath.restype = ctypes.c_int
    buf = ctypes.create_string_buffer(b'\xff' * buffer_size, buffer_size)
    ctypes.set_errno(0)
    count = proc_pidpath(os.getpid(), buf, buffer_size)
    error = ctypes.get_errno()
    assert count > 0 and error == 0, 'own proc_pidpath failed'
    assert count < buffer_size, 'own proc_pidpath out of bounds/truncated'
    raw = buf.raw
    nul = raw.find(b'\0')
    assert nul > 0 and nul in (count - 1, count), 'own proc_pidpath invalid NUL/length'
    path = Path(os.fsdecode(raw[:nul]))
    assert path.is_absolute() and path.is_file(), 'own proc_pidpath invalid image'
    return path.resolve(strict=True)


class Client:
    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(SOCKET_TIMEOUT)
        try:
            self.sock.connect(str(path))
        except BaseException:
            self.sock.close()
            raise
        self.buf = b''
    def read(self, seconds):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if not select.select([self.sock], [], [], max(0, end-time.monotonic()))[0]:
                return
            chunk = self.sock.recv(65536)
            assert chunk, 'daemon IPC closed'
            self.buf += chunk
            while b'\n' in self.buf:
                line, self.buf = self.buf.split(b'\n', 1)
                yield json.loads(line)
    def close(self):
        self.sock.close()


def live_gate(private, image_buffer_size):
    expected_image = own_process_image(image_buffer_size)
    env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'LC_ALL': 'C'}
    for key, folder in [('HOME', 'home'), ('XDG_CONFIG_HOME', 'config'), ('XDG_STATE_HOME', 'state'), ('XDG_RUNTIME_DIR', 'runtime'), ('XDG_DATA_HOME', 'data')]:
        path = private / folder; path.mkdir(mode=0o700); env[key] = str(path)
    sockpath = private / 'daemon.sock'
    daemon = subprocess.Popen([str(ROOT / 'target/debug/kub0d'), '--socket', str(sockpath), '--data-dir', env['XDG_DATA_HOME'], '--interval-ms', '200', '--emit-flows'], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    sockets, clients = [], []
    try:
        deadline = time.monotonic()+10
        while not sockpath.exists():
            assert daemon.poll() is None and time.monotonic() < deadline, 'private daemon startup failed'
            time.sleep(.05)
        first = Client(sockpath); clients.append(first)
        list(first.read(.5))  # join before creating sockets, to capture raw emissions
        fixtures = []
        duplicate_pairs = []
        def owned_socket(family, kind):
            sock = socket.socket(family, kind)
            sockets.append(sock)
            sock.settimeout(SOCKET_TIMEOUT)
            return sock
        for family, ip in [(socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')]:
            server = owned_socket(family, socket.SOCK_STREAM)
            server.bind((ip, 0)); server.listen()
            tcp = owned_socket(family, socket.SOCK_STREAM)
            tcp.connect(server.getsockname()); accepted, _ = server.accept(); sockets.append(accepted)
            accepted.settimeout(SOCKET_TIMEOUT)
            udp_server = owned_socket(family, socket.SOCK_DGRAM)
            udp_server.bind((ip, 0))
            udp = owned_socket(family, socket.SOCK_DGRAM)
            udp.connect(udp_server.getsockname())
            for proto, s in [('tcp', tcp), ('udp', udp)]:
                duplicate = s.dup(); sockets.append(duplicate)
                duplicate.settimeout(SOCKET_TIMEOUT)
                assert duplicate.fileno() != s.fileno()
                assert os.fstat(duplicate.fileno()) == os.fstat(s.fileno())
                assert duplicate.getsockname() == s.getsockname()
                assert duplicate.getpeername() == s.getpeername()
                duplicate_pairs.append((s, duplicate))
                fixtures.append((proto, ip, s.getsockname()[1], s.getpeername()[1]))
        flows = []
        for msg in first.read(5):
            if msg.get('kind') == 'flow' and any(matches(msg, spec) for spec in fixtures):
                flows.append(msg)
        assert len(flows) == len(fixtures), 'missing or duplicate fixture live emissions'
        for spec in fixtures:
            found = [f for f in flows if matches(f, spec)]; assert len(found) == 1
            f = found[0]
            assert f['source'] == 'libproc' and f['state'] == 'live'
            assert f['verdict']['action'] == 'observed' and f['verdict']['provenance'] == 'observation'
            assert f.get('bytes') is None and f['app']['pid'] == os.getpid()
            assert Path(f['app']['key']).is_absolute()
            assert Path(f['app']['key']).resolve(strict=True) == expected_image
            assert f['id'].startswith('lp:')
        # Snapshots are sent on join, not by a snapshot request command.
        def snapshot():
            client = Client(sockpath); clients.append(client)
            snapshots = [m for m in client.read(1) if m.get('type') == 'snapshot']
            assert snapshots, 'new IPC client received no snapshot'
            rows = snapshots[-1]['connections']
            assert len(rows) <= 500
            return rows
        rows = snapshot()
        for f in flows:
            projected = [r for r in rows if r['id'] == f['id']]; assert len(projected) == 1
            r = projected[0]
            assert r['evidence']['recordedAt'] == f['ts']
            assert r['exe'] == f['app']['key']
            assert r['evidence']['source'] == 'libproc' and r['evidence']['verdict'] == f['verdict']
            assert r.get('bytes') is None and r['app']['pid'] == os.getpid()
            assert r['local'] == {k: f['local'][k] for k in ('ip', 'port')}
            assert r['remote'] == {k: f['remote'][k] for k in ('ip', 'port')}
        assert not [m for m in first.read(2) if m.get('kind') == 'flow' and any(matches(m, spec) for spec in fixtures)], 'repeated live flow emission'
        # Duplicates remain open across several polls and a second snapshot.
        again = snapshot()
        for f in flows:
            assert [r for r in again if r['id'] == f['id']] == [r for r in rows if r['id'] == f['id']]
        assert len(duplicate_pairs) == 4
        for original, duplicate in duplicate_pairs:
            assert 0 <= original.fileno() != duplicate.fileno() >= 0
            assert os.fstat(original.fileno()) == os.fstat(duplicate.fileno())
        for s in sockets:
            s.close()
        # libproc emits no disappearance event: this is observation history.
        list(first.read(1))
        retained = snapshot()
        for f in flows:
            assert [r for r in retained if r['id'] == f['id']] == [r for r in rows if r['id'] == f['id']]
        print('live: four private IPv4/IPv6 TCP/connected-UDP flows; four distinct duplicate FDs; stable raw/snapshot IDs and retained close-history evidence matched')
    finally:
        for client in clients: client.close()
        for s in sockets: s.close()
        daemon.terminate()
        try: daemon.wait(timeout=5)
        except subprocess.TimeoutExpired:
            daemon.kill(); daemon.wait(timeout=5)


def main():
    if sys.argv[1:] == ['--self-test']:
        endpoint_self_test()
        return
    assert not sys.argv[1:], 'unknown arguments'
    if platform.system() != 'Darwin':
        raise SystemExit('Darwin required: native gate PENDING (no Apple result)')
    with tempfile.TemporaryDirectory(prefix='vallum-darwin-') as td:
        private = Path(td)
        image_buffer_size = abi_gate(private)
        live_gate(private, image_buffer_size)


if __name__ == '__main__':
    main()
