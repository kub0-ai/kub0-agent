#ifndef KUB0_CAPTURE_EVENT_H
#define KUB0_CAPTURE_EVENT_H
#include <linux/types.h>
struct capture_event {
  __u64 mono_ns;
  __u32 pid, uid, family, protocol, operation;
  __u32 address[4];
  __u32 port;
  char comm[16];
};
/* One A or AAAA answer out of a DNS response the owning uid received over
 * UDP. qname is the question name in wire form (length-prefixed labels, no
 * compression), qname_len bytes of it valid. Distinguished from
 * capture_event by size alone, so the two must never be the same length. */
#define KUB0_DNS_QNAME_MAX 256
struct capture_dns {
  __u64 mono_ns;
  __u32 uid, family, ttl, qname_len;
  __u32 address[4];
  /* The resolver that answered: the destination the matched query was sent
   * to, which is also this response's source. */
  __u32 server[4];
  __u8 qname[KUB0_DNS_QNAME_MAX];
};
struct capture_counts {
  __u64 emitted, dropped, dns_emitted, dns_dropped;
  /* Queries recorded by the egress program, and responses the ingress
   * program refused because no recorded query from the same socket matched
   * their transaction id, question name and server. */
  __u64 dns_queries, dns_unmatched;
};
#ifndef __bpf__
_Static_assert(sizeof(struct capture_dns) != sizeof(struct capture_event),
               "ring records are told apart by size");
#endif
#endif
