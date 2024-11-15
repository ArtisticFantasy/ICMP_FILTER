#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <linux/netfilter.h>
#include <linux/if_link.h>
#include <unistd.h>

#define PATH_MAX 4096

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    char filename[PATH_MAX];
    int ret;

    snprintf(filename, sizeof(filename), "%s", "icmp_filter.o");

    obj = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 1;
    }

    ret = bpf_object__load(obj);
    if (ret) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "icmp_filter");
    if (!prog) {
        fprintf(stderr, "ERROR: finding a program in BPF object file failed\n");
        return 1;
    }

    struct bpf_netfilter_opts opts = {
        .sz = sizeof(struct bpf_netfilter_opts),
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_LOCAL_IN,
        .priority = 1,
        .flags = 0,
    };

    link = bpf_program__attach_netfilter(prog, &opts);
    if (!link) {
        fprintf(stderr, "ERROR: attaching BPF program to Netfilter hook failed\n");
        return 1;
    }

    ret = bpf_link__pin(link, "/sys/fs/bpf/icmp_filter_link");
    if (ret) {
        fprintf(stderr, "ERROR: pinning BPF link failed\n");
        bpf_link__destroy(link);
        return 1;
    }

    printf("eBPF program icmp_filter successfully attached to Netfilter hook and pinned\n");

    return 0;
}