#!/usr/bin/env python3
"""Real nft expiry in an isolated user/network namespace; never the host ruleset.

VALLUM_TEST_PARENT_NETNS must identify the invoking process's network namespace.
Run through unshare -Urn. No root-owned files or host cgroups are modified.
"""
import json, os, socket, subprocess, time
from pathlib import Path

parent=os.environ.get("VALLUM_TEST_PARENT_NETNS")
assert parent and os.readlink("/proc/self/ns/net") != parent, "private network namespace required"
assert os.geteuid()==0 and Path("/proc/self/uid_map").read_text().split()[1] != "0", "private user namespace required"
subprocess.run(["ip","link","set","lo","up"],check=True)
group=Path("/proc/self/cgroup").read_text().strip().split("0::",1)[1].strip("/")
assert group, "test needs a non-root cgroup"
level=len(group.split("/"))
table="vallum_scoped_test"
def nft(text):
    p=subprocess.run(["nft","-f","-"],input=text,text=True,capture_output=True)
    assert p.returncode==0,p.stderr
def connect(ip,port):
    s=socket.socket();s.settimeout(0.2)
    try:s.connect((ip,port));return True
    except (TimeoutError,OSError):return False
    finally:s.close()
listeners=[]
try:
    for ip in ["127.0.0.1","127.0.0.2"]:
        s=socket.socket();s.bind((ip,0));s.listen();listeners.append(s)
    assert all(connect(ip,s.getsockname()[1]) for ip,s in zip(["127.0.0.1","127.0.0.2"],listeners))
    nft(f'''add table inet {table}
add chain inet {table} out {{ type filter hook output priority 0; policy accept; }}
add set inet {table} t4 {{ type ipv4_addr; flags timeout; }}
add element inet {table} t4 {{ 127.0.0.1 timeout 2s }}
add rule inet {table} out socket cgroupv2 level {level} "{group}" ip daddr @t4 drop comment "vallum-scoped"
add set inet {table} t6 {{ type ipv6_addr; flags timeout; }}
add element inet {table} t6 {{ 2001:db8::1 timeout 2s }}
''')
    assert not connect("127.0.0.1",listeners[0].getsockname()[1]), "target IP was not blocked"
    assert connect("127.0.0.2",listeners[1].getsockname()[1]), "another destination was blocked"
    time.sleep(2.1)
    assert connect("127.0.0.1",listeners[0].getsockname()[1]), "kernel expiry did not restore connectivity"
    for name in ["t4","t6"]:
        state=json.loads(subprocess.check_output(["nft","-j","list","set","inet",table,name],text=True))
        assert not next(x["set"] for x in state["nftables"] if "set" in x).get("elem"),"expired element retained"
    print(json.dumps({"target_blocked":True,"other_destination_allowed":True,"kernel_expiry_restored_tcp":True,"ipv4_ipv6_timeout_verified":True,"private_network_namespace":True}))
finally:
    for s in listeners:s.close()
    subprocess.run(["nft","delete","table","inet",table],capture_output=True)
