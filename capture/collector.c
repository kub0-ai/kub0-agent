#define _GNU_SOURCE
#include "capture_blob.h"
#include "event.h"
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stopping = 0;
static uint32_t target_uid;
static uint64_t received = 0, invalid = 0, output_dropped = 0, dns_received = 0;
static int dns_attached = 0;
static void stop(int signal) {
  (void)signal;
  stopping = 1;
}
static int publish(const char *line, size_t n) {
  ssize_t written = write(STDOUT_FILENO, line, n);
  if (written == (ssize_t)n)
    return 1;
  if (written < 0 && (errno == EAGAIN || errno == EINTR))
    return 0;
  stopping = 1;
  return 0;
}
static uint64_t nanos(clockid_t clock) {
  struct timespec t;
  if (clock_gettime(clock, &t))
    return 0;
  return (uint64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}
/* Wire-form question name to lower-case dotted text. Labels must be
 * hostname characters; anything else makes the whole answer invalid rather
 * than letting an arbitrary byte string into a JSON line. */
static int dns_name(const uint8_t *q, uint32_t qlen, char *out, size_t cap) {
  size_t o = 0;
  uint32_t i = 0;
  if (qlen == 0 || qlen > KUB0_DNS_QNAME_MAX)
    return -1;
  while (i < qlen) {
    uint8_t len = q[i++];
    if (len == 0)
      break;
    if (len > 63 || i + len > qlen)
      return -1;
    if (o && o < cap)
      out[o++] = '.';
    for (uint8_t k = 0; k < len; k++) {
      unsigned char c = q[i + k];
      if (c >= 'A' && c <= 'Z')
        c = (unsigned char)(c + 32);
      if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' ||
            c == '_'))
        return -1;
      if (o + 1 >= cap)
        return -1;
      out[o++] = (char)c;
    }
    i += len;
  }
  if (o == 0 || o >= cap)
    return -1;
  out[o] = 0;
  return 0;
}
static int sample_dns(const struct capture_dns *e) {
  if (e->uid != target_uid || (e->family != AF_INET && e->family != AF_INET6)) {
    invalid++;
    return 0;
  }
  char ip[INET6_ADDRSTRLEN], server[INET6_ADDRSTRLEN], name[260];
  if (!inet_ntop(e->family, e->address, ip, sizeof(ip)) ||
      !inet_ntop(e->family, e->server, server, sizeof(server)) ||
      dns_name(e->qname, e->qname_len, name, sizeof(name))) {
    invalid++;
    return 0;
  }
  uint64_t monotonic = nanos(CLOCK_MONOTONIC), wall = nanos(CLOCK_REALTIME);
  uint64_t age = monotonic >= e->mono_ns ? monotonic - e->mono_ns : 0;
  uint64_t ts = (wall >= age ? wall - age : wall) / 1000000;
  char line[640];
  int n = snprintf(line, sizeof(line),
                   "{\"type\":\"dns\",\"ts\":%llu,\"uid\":%u,\"name\":\"%s\","
                   "\"ip\":\"%s\",\"ttl\":%u,\"server\":\"%s\"}\n",
                   (unsigned long long)ts, e->uid, name, ip, e->ttl, server);
  if (n < 0 || (size_t)n >= sizeof(line)) {
    invalid++;
    return 0;
  }
  if (!publish(line, (size_t)n))
    output_dropped++;
  dns_received++;
  return 0;
}
static int sample(void *ctx, void *data, size_t length) {
  (void)ctx;
  if (length == sizeof(struct capture_dns))
    return sample_dns(data);
  if (length != sizeof(struct capture_event)) {
    invalid++;
    return 0;
  }
  const struct capture_event *e = data;
  if (e->uid != target_uid || !e->pid ||
      (e->family != AF_INET && e->family != AF_INET6) ||
      (e->protocol != 6 && e->protocol != 17) ||
      (e->operation != 1 && e->operation != 2)) {
    invalid++;
    return 0;
  }
  char ip[INET6_ADDRSTRLEN], comm[33];
  if (!inet_ntop(e->family, e->address, ip, sizeof(ip))) {
    invalid++;
    return 0;
  }
  for (size_t i = 0; i < 16; i++)
    snprintf(comm + 2 * i, 3, "%02x", (unsigned char)e->comm[i]);
  uint64_t monotonic = nanos(CLOCK_MONOTONIC), wall = nanos(CLOCK_REALTIME);
  uint64_t age = monotonic >= e->mono_ns ? monotonic - e->mono_ns : 0;
  uint64_t ts = (wall >= age ? wall - age : wall) / 1000000;
  char line[512];
  int n = snprintf(line, sizeof(line),
                   "{\"type\":\"attempt\",\"ts\":%llu,\"pid\":%u,\"uid\":%u,"
                   "\"proto\":\"%s\",\"operation\":\"%s\",\"ip\":\"%s\","
                   "\"port\":%u,\"commHex\":\"%s\"}\n",
                   (unsigned long long)ts, e->pid, e->uid,
                   e->protocol == 6 ? "tcp" : "udp",
                   e->operation == 1 ? "connect" : "sendmsg", ip,
                   ntohs((uint16_t)e->port), comm);
  if (n < 0 || (size_t)n >= sizeof(line)) {
    invalid++;
    return 0;
  }
  if (!publish(line, (size_t)n))
    output_dropped++;
  received++;
  return 0;
}
static int caller(uint32_t *uid) {
  const char *s = getenv("PKEXEC_UID");
  if (!s || !*s)
    s = getenv("SUDO_UID");
  if (!s || !*s)
    return -1;
  char *end = NULL;
  errno = 0;
  unsigned long n = strtoul(s, &end, 10);
  if (errno || *end || !n || n > UINT32_MAX || s[0] == '-')
    return -1;
  *uid = (uint32_t)n;
  return 0;
}
int main(int argc, char **argv) {
  if (argc == 2 && !strcmp(argv[1], "--help")) {
    puts("kub0-capture: invoke through pkexec; observes the invoking UID's "
         "user slice; optional --cgroup must be a descendant of that slice; "
         "send stop or close stdin to detach");
    return 0;
  }
  if ((argc != 1 && !(argc == 3 && !strcmp(argv[1], "--cgroup"))) ||
      geteuid() != 0 || caller(&target_uid)) {
    fprintf(stderr, "capture requires root and an authenticated non-root "
                    "PKEXEC_UID/SUDO_UID\n");
    return 1;
  }
  pid_t parent = getppid();
  if (prctl(PR_SET_PDEATHSIG, SIGTERM) || getppid() != parent)
    return 1;
  struct sigaction handler = {.sa_handler = stop};
  sigemptyset(&handler.sa_mask);
  sigaction(SIGINT, &handler, NULL);
  sigaction(SIGTERM, &handler, NULL);
  sigaction(SIGPIPE, &handler, NULL);
  int flags = fcntl(STDOUT_FILENO, F_GETFL);
  if (flags < 0 || fcntl(STDOUT_FILENO, F_SETFL, flags | O_NONBLOCK))
    return 1;
  char base[128], path[PATH_MAX];
  snprintf(base, sizeof(base), "/sys/fs/cgroup/user.slice/user-%u.slice",
           target_uid);
  if (!realpath(argc == 3 ? argv[2] : base, path)) {
    fprintf(stderr, "capture cgroup resolution failed: %s\n", strerror(errno));
    return 1;
  }
  size_t prefix = strlen(base);
  if (strncmp(path, base, prefix) || (path[prefix] && path[prefix] != '/')) {
    fprintf(stderr, "capture cgroup outside invoking UID slice\n");
    return 1;
  }
  int cgroup = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (cgroup < 0) {
    fprintf(stderr, "capture cgroup: %s\n", strerror(errno));
    return 1;
  }
  struct bpf_object *object =
      bpf_object__open_mem(capture_blob, sizeof(capture_blob), NULL);
  struct bpf_link *links[6] = {0};
  struct ring_buffer *ring = NULL;
  int result = 1;
  if (!object || libbpf_get_error(object)) {
    object = NULL;
    goto cleanup;
  }
  if (bpf_object__load(object))
    goto cleanup;
  struct bpf_map *config = bpf_object__find_map_by_name(object, "owner");
  uint32_t zero = 0;
  if (!config ||
      bpf_map_update_elem(bpf_map__fd(config), &zero, &target_uid, BPF_ANY))
    goto cleanup;
  const char *names[] = {"connect4", "connect6", "sendmsg4", "sendmsg6"};
  for (size_t i = 0; i < 4; i++) {
    struct bpf_program *p = bpf_object__find_program_by_name(object, names[i]);
    if (!p)
      goto cleanup;
    links[i] = bpf_program__attach_cgroup(p, cgroup);
    if (libbpf_get_error(links[i])) {
      links[i] = NULL;
      goto cleanup;
    }
  }
  /* DNS answers ride on a pair of skb programs: egress records the owner's
   * queries, ingress reports only the responses that match one. Both or
   * neither: an ingress program without the egress one would match nothing,
   * so a kernel that refuses either keeps just the four address hooks.
   * Capture without names is still capture, and the status line says which
   * it is. */
  {
    struct bpf_program *egress = bpf_object__find_program_by_name(object, "dns_egress"),
                       *ingress = bpf_object__find_program_by_name(object, "dns_ingress");
    if (egress && ingress) {
      links[4] = bpf_program__attach_cgroup(egress, cgroup);
      if (libbpf_get_error(links[4])) {
        links[4] = NULL;
      } else {
        links[5] = bpf_program__attach_cgroup(ingress, cgroup);
        if (libbpf_get_error(links[5])) {
          links[5] = NULL;
          bpf_link__destroy(links[4]);
          links[4] = NULL;
        } else {
          dns_attached = 1;
        }
      }
      if (!dns_attached)
        fprintf(stderr, "dns capture unavailable; address capture continues\n");
    }
  }
  struct bpf_map *events = bpf_object__find_map_by_name(object, "events"),
                 *counts = bpf_object__find_map_by_name(object, "counts");
  if (!events || !counts)
    goto cleanup;
  ring = ring_buffer__new(bpf_map__fd(events), sample, NULL, NULL);
  if (!ring)
    goto cleanup;
  uint64_t last = 0;
  while (!stopping) {
    int rc = ring_buffer__poll(ring, 200);
    if (rc < 0 && rc != -EINTR) {
      fprintf(stderr, "ring poll failed: %d\n", rc);
      goto cleanup;
    }
    struct pollfd input = {.fd = STDIN_FILENO, .events = POLLIN | POLLHUP};
    if (poll(&input, 1, 0) > 0 && (input.revents & (POLLIN | POLLHUP))) {
      char command[16];
      ssize_t n = read(STDIN_FILENO, command, sizeof(command));
      if (n <= 0 || (n >= 4 && !memcmp(command, "stop", 4)))
        break;
    }
    uint64_t now = nanos(CLOCK_MONOTONIC);
    if (now - last >= 1000000000) {
      struct capture_counts stats;
      if (bpf_map_lookup_elem(bpf_map__fd(counts), &zero, &stats)) {
        fprintf(stderr, "capture counters unreadable\n");
        goto cleanup;
      }
      char line[512];
      int n = snprintf(
          line, sizeof(line),
          "{\"type\":\"capture-status\",\"state\":\"current\",\"received\":%"
          "llu,\"emitted\":%llu,\"kernelDropped\":%llu,\"collectorDropped\":%"
          "llu,\"invalid\":%llu,\"dns\":%s,\"dnsReceived\":%llu,"
          "\"dnsEmitted\":%llu,\"dnsDropped\":%llu,\"dnsQueries\":%llu,"
          "\"dnsUnmatched\":%llu}\n",
          (unsigned long long)received, (unsigned long long)stats.emitted,
          (unsigned long long)stats.dropped, (unsigned long long)output_dropped,
          (unsigned long long)invalid, dns_attached ? "true" : "false",
          (unsigned long long)dns_received,
          (unsigned long long)stats.dns_emitted,
          (unsigned long long)stats.dns_dropped,
          (unsigned long long)stats.dns_queries,
          (unsigned long long)stats.dns_unmatched);
      if (n < 0 || (size_t)n >= sizeof(line))
        goto cleanup;
      publish(line, (size_t)n);
      last = now;
    }
  }
  result = 0;
cleanup:
  if (ring)
    ring_buffer__free(ring);
  for (size_t i = 0; i < sizeof(links) / sizeof(links[0]); i++)
    if (links[i])
      bpf_link__destroy(links[i]);
  if (object)
    bpf_object__close(object);
  close(cgroup);
  if (result)
    fprintf(stderr, "capture unavailable; all acquired links detached\n");
  return result;
}
