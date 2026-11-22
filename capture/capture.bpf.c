// SPDX-License-Identifier: MIT OR GPL-2.0-only
#include "event.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 4 * 1024 * 1024);
} events SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u32);
} owner SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct capture_counts);
} counts SEC(".maps");

static __always_inline int observe(struct bpf_sock_addr *ctx, __u32 operation,
                                   __u32 family) {
  __u32 zero = 0, uid = (__u32)bpf_get_current_uid_gid();
  __u32 *target = bpf_map_lookup_elem(&owner, &zero);
  if (!target || !*target || uid != *target ||
      ctx->user_family != family ||
      (ctx->protocol != 6 && ctx->protocol != 17))
    return 1;
  struct capture_counts *stats = bpf_map_lookup_elem(&counts, &zero);
  struct capture_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (!event) {
    if (stats)
      __sync_fetch_and_add(&stats->dropped, 1);
    return 1;
  }
  __builtin_memset(event, 0, sizeof(*event));
  event->mono_ns = bpf_ktime_get_ns();
  event->pid = bpf_get_current_pid_tgid() >> 32;
  event->uid = uid;
  event->family = family;
  event->protocol = ctx->protocol;
  event->operation = operation;
  // Each hook passes a constant family, so inlining removes the other family's
  // reads. The verifier forbids IPv6 context fields in IPv4 hooks even behind
  // a runtime user_family check (and conversely for user_ip4 in IPv6 hooks).
  if (family == 2)
    event->address[0] = ctx->user_ip4;
  else
    __builtin_memcpy(event->address, ctx->user_ip6, sizeof(event->address));
  event->port = ctx->user_port;
  bpf_get_current_comm(event->comm, sizeof(event->comm));
  bpf_ringbuf_submit(event, 0);
  if (stats)
    __sync_fetch_and_add(&stats->emitted, 1);
  // Observation only: never change the address, port, return verdict or policy.
  return 1;
}
SEC("cgroup/connect4") int connect4(struct bpf_sock_addr *ctx) {
  return observe(ctx, 1, 2);
}
SEC("cgroup/connect6") int connect6(struct bpf_sock_addr *ctx) {
  return observe(ctx, 1, 10);
}
SEC("cgroup/sendmsg4") int sendmsg4(struct bpf_sock_addr *ctx) {
  return observe(ctx, 2, 2);
}
SEC("cgroup/sendmsg6") int sendmsg6(struct bpf_sock_addr *ctx) {
  return observe(ctx, 2, 10);
}

/* DNS answers, correlated with the query that asked for them.
 *
 * cgroup_skb programs see the packet from the network header on, in both
 * directions, for every socket in the slice. A response is believed only when
 * this socket sent the matching query: the egress program records
 * (socket cookie, transaction id) -> (question-name hash, server) for every
 * UDP query to port 53 from the owner's sockets, and the ingress program
 * reports a response from port 53 only when that key is present, the question
 * name hashes the same, and the response comes from the server the query went
 * to. A datagram from port 53 that nobody asked for, from another address, or
 * with another id is counted (`dns_unmatched`) and otherwise ignored, so an
 * off-path sender has to guess the id, the port and the name, the same bar the
 * resolver applies. A response is recognised structurally: UDP from port 53,
 * QR set, not truncated, rcode 0, exactly one question, at least one answer.
 * Only A and AAAA records are reported, each tagged with the *question* name,
 * which is what the app asked for; a CNAME chain in between is walked past,
 * not reported. Nothing is rewritten and the packet is always allowed (return
 * 1). TCP, DoT and DoH are not seen. */
#define DNS_MAX_LABELS 64
#define DNS_MAX_ANSWERS 8
struct dnshdr {
  __u16 id, flags, qdcount, ancount, nscount, arcount;
};
struct rrfixed {
  __u16 type, class;
  __u32 ttl;
  __u16 rdlength;
} __attribute__((packed));
struct dns_qkey {
  __u64 cookie;
  __u32 txid, pad;
};
struct dns_qval {
  __u32 qhash, family;
  __u32 server[4];
};
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 4096);
  __type(key, struct dns_qkey);
  __type(value, struct dns_qval);
} queries SEC(".maps");

/* UDP header offset and address family of an unfragmented IPv4 datagram or
 * an IPv6 datagram whose next header is UDP itself; -1 for anything else. */
static __always_inline int dns_udp(struct __sk_buff *skb, __u32 *udp,
                                   __u32 *family) {
  __u8 b;
  if (skb->protocol == bpf_htons(0x0800)) {
    if (bpf_skb_load_bytes(skb, 0, &b, 1) || (b >> 4) != 4)
      return -1;
    *udp = (b & 0x0F) * 4;
    if (*udp < 20 || bpf_skb_load_bytes(skb, 9, &b, 1) || b != 17)
      return -1;
    // A later fragment carries no UDP header; reading one there would parse
    // payload bytes as a response. Only an unfragmented or first fragment.
    __u16 frag;
    if (bpf_skb_load_bytes(skb, 6, &frag, 2) || (bpf_ntohs(frag) & 0x1FFF))
      return -1;
    *family = 2;
    return 0;
  }
  if (skb->protocol == bpf_htons(0x86DD)) {
    // Extension headers are not walked: a datagram behind one is missed,
    // never misread.
    if (bpf_skb_load_bytes(skb, 6, &b, 1) || b != 17)
      return -1;
    *udp = 40;
    *family = 10;
    return 0;
  }
  return -1;
}

/* The question name at `off`, byte by byte into `qname`, label-checked, with
 * its wire length and a case-folded FNV-1a hash so a query and its response
 * compare equal whatever case the resolver echoes. Compression in a question
 * is refused: a question is never compressed in practice and a pointer here
 * would be a pointer into bytes this program has not checked. */
static __always_inline int dns_qname(struct __sk_buff *skb, __u32 off,
                                     __u8 *qname, __u32 *qlen, __u32 *qhash) {
  __u32 left = 0, hash = 2166136261u, len = 0;
  for (int i = 0; i < KUB0_DNS_QNAME_MAX - 1; i++) {
    __u8 c;
    if (bpf_skb_load_bytes(skb, off + i, &c, 1))
      return -1;
    qname[i] = c;
    __u8 folded = (c >= 'A' && c <= 'Z') ? (__u8)(c + 32) : c;
    hash = (hash ^ folded) * 16777619u;
    if (left == 0) {
      if (c == 0) {
        len = i + 1;
        break;
      }
      if (c > 63)
        return -1;
      left = c;
    } else {
      left--;
    }
  }
  if (len == 0)
    return -1;
  *qlen = len;
  *qhash = hash;
  return 0;
}

static __always_inline int dns_skip_name(struct __sk_buff *skb, __u32 *offset) {
  __u32 off = *offset;
  for (int i = 0; i < DNS_MAX_LABELS; i++) {
    __u8 len;
    if (bpf_skb_load_bytes(skb, off, &len, 1))
      return -1;
    if (len == 0) {
      *offset = off + 1;
      return 0;
    }
    if ((len & 0xC0) == 0xC0) {
      *offset = off + 2;
      return 0;
    }
    if (len > 63)
      return -1;
    off += 1 + len;
  }
  return -1;
}

static __always_inline void dns_emit(struct __sk_buff *skb, __u32 rdata,
                                     __u32 family, __u32 ttl, __u32 uid,
                                     const __u8 *qname, __u32 qname_len,
                                     const __u32 *server,
                                     struct capture_counts *stats) {
  struct capture_dns *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (!event) {
    if (stats)
      __sync_fetch_and_add(&stats->dns_dropped, 1);
    return;
  }
  __builtin_memset(event, 0, sizeof(*event));
  if (bpf_skb_load_bytes(skb, rdata, event->address, family == 2 ? 4 : 16)) {
    bpf_ringbuf_discard(event, 0);
    return;
  }
  event->mono_ns = bpf_ktime_get_ns();
  event->uid = uid;
  event->family = family;
  event->ttl = ttl;
  event->qname_len = qname_len;
  __builtin_memcpy(event->server, server, sizeof(event->server));
  __builtin_memcpy(event->qname, qname, KUB0_DNS_QNAME_MAX);
  bpf_ringbuf_submit(event, 0);
  if (stats)
    __sync_fetch_and_add(&stats->dns_emitted, 1);
}

/* Every UDP query to port 53 from the owner's sockets is remembered by
 * (socket cookie, transaction id), with the question-name hash and the server
 * it went to, so the response can be tied to the socket that asked. */
SEC("cgroup_skb/egress") int dns_egress(struct __sk_buff *skb) {
  __u32 zero = 0, uid = bpf_get_socket_uid(skb);
  __u32 *target = bpf_map_lookup_elem(&owner, &zero);
  if (!target || !*target || uid != *target)
    return 1;
  __u32 udp, family;
  if (dns_udp(skb, &udp, &family))
    return 1;
  __u16 dport;
  if (bpf_skb_load_bytes(skb, udp + 2, &dport, 2) || dport != bpf_htons(53))
    return 1;
  __u32 off = udp + 8;
  struct dnshdr h;
  if (bpf_skb_load_bytes(skb, off, &h, sizeof(h)))
    return 1;
  // A query (QR clear) with exactly one question.
  if ((bpf_ntohs(h.flags) & 0x8000) || bpf_ntohs(h.qdcount) != 1)
    return 1;
  __u8 qname[KUB0_DNS_QNAME_MAX] = {0};
  __u32 qlen = 0, qhash = 0;
  if (dns_qname(skb, off + sizeof(h), qname, &qlen, &qhash))
    return 1;
  struct dns_qkey key = {.cookie = bpf_get_socket_cookie(skb),
                         .txid = bpf_ntohs(h.id),
                         .pad = 0};
  struct dns_qval val = {.qhash = qhash, .family = family, .server = {0}};
  if (bpf_skb_load_bytes(skb, family == 2 ? 16 : 24, val.server,
                         family == 2 ? 4 : 16))
    return 1;
  bpf_map_update_elem(&queries, &key, &val, BPF_ANY);
  struct capture_counts *stats = bpf_map_lookup_elem(&counts, &zero);
  if (stats)
    __sync_fetch_and_add(&stats->dns_queries, 1);
  // Observation only: the query goes out unchanged.
  return 1;
}

SEC("cgroup_skb/ingress") int dns_ingress(struct __sk_buff *skb) {
  __u32 zero = 0, uid = bpf_get_socket_uid(skb);
  __u32 *target = bpf_map_lookup_elem(&owner, &zero);
  if (!target || !*target || uid != *target)
    return 1;
  __u32 udp, family;
  if (dns_udp(skb, &udp, &family))
    return 1;
  __u16 sport;
  if (bpf_skb_load_bytes(skb, udp, &sport, 2) || sport != bpf_htons(53))
    return 1;
  __u32 off = udp + 8;
  struct dnshdr h;
  if (bpf_skb_load_bytes(skb, off, &h, sizeof(h)))
    return 1;
  __u16 flags = bpf_ntohs(h.flags);
  // A response (QR), not truncated, rcode 0, exactly one question.
  if (!(flags & 0x8000) || (flags & 0x0200) || (flags & 0x000F) ||
      bpf_ntohs(h.qdcount) != 1 || bpf_ntohs(h.ancount) == 0)
    return 1;
  off += sizeof(h);
  __u8 qname[KUB0_DNS_QNAME_MAX] = {0};
  __u32 qlen = 0, qhash = 0;
  if (dns_qname(skb, off, qname, &qlen, &qhash))
    return 1;
  off += qlen + 4; // qtype, qclass
  struct capture_counts *stats = bpf_map_lookup_elem(&counts, &zero);
  // Only a response to a query this socket sent, from the server it asked.
  struct dns_qkey key = {.cookie = bpf_get_socket_cookie(skb),
                         .txid = bpf_ntohs(h.id),
                         .pad = 0};
  __u32 server[4] = {0};
  if (bpf_skb_load_bytes(skb, family == 2 ? 12 : 8, server,
                         family == 2 ? 4 : 16))
    return 1;
  struct dns_qval *asked = bpf_map_lookup_elem(&queries, &key);
  if (!asked || asked->qhash != qhash || asked->family != family ||
      asked->server[0] != server[0] || asked->server[1] != server[1] ||
      asked->server[2] != server[2] || asked->server[3] != server[3]) {
    if (stats)
      __sync_fetch_and_add(&stats->dns_unmatched, 1);
    return 1;
  }
  bpf_map_delete_elem(&queries, &key);
  __u16 answers = bpf_ntohs(h.ancount);
  for (int i = 0; i < DNS_MAX_ANSWERS; i++) {
    if (i >= answers)
      break;
    if (dns_skip_name(skb, &off))
      return 1;
    struct rrfixed rr;
    if (bpf_skb_load_bytes(skb, off, &rr, sizeof(rr)))
      return 1;
    off += sizeof(rr);
    __u16 type = bpf_ntohs(rr.type), rdlength = bpf_ntohs(rr.rdlength);
    if (type == 1 && rdlength == 4)
      dns_emit(skb, off, 2, bpf_ntohl(rr.ttl), uid, qname, qlen, server, stats);
    else if (type == 28 && rdlength == 16)
      dns_emit(skb, off, 10, bpf_ntohl(rr.ttl), uid, qname, qlen, server,
               stats);
    if (rdlength > 1024)
      return 1;
    off += rdlength;
  }
  return 1;
}
char LICENSE[] SEC("license") = "Dual MIT/GPL";
