#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <linux/netfilter.h>
#include <bpf/bpf_helpers.h>
#include "common.h"

#define ONE_SECOND 1000000000
struct perdst_entry {
    int credit;
    __u64 stamp;
};

__u64 mymin64(__u64 a, __u64 b) {
    return a < b ? a : b;
}

__u32 mymin32(__u32 a, __u32 b) {
    return a < b ? a : b;
}

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);
	__type(value, struct perdst_entry);
	__uint(max_entries, 1000);
} icmp_map SEC(".maps");

/*NF_INET_LOCAL_IN*/
SEC("netfilter")
int icmp_filter(struct bpf_nf_ctx *ctx) {
    struct sk_buff *skb = ctx->skb;
    struct iphdr iph, inner_iph;
    struct icmphdr icmph;

    if (bpf_probe_read_kernel(&iph, sizeof(iph), skb->head + skb->network_header) < 0) {
        return NF_ACCEPT;
    }

    if (iph.protocol != IPPROTO_ICMP) {
        return NF_ACCEPT;
    }

    if (bpf_probe_read_kernel(&icmph, sizeof(icmph), skb->head + skb->network_header + sizeof(iph)) < 0) {
        return NF_ACCEPT;
    }

    __u64 cur_stamp = bpf_ktime_get_ns();
    struct perdst_entry *entry = bpf_map_lookup_elem(&icmp_map, &iph.daddr);
    if (!entry) {
        struct perdst_entry new_entry = {
            .credit = 1000,
            .stamp = cur_stamp,
        };
        bpf_map_update_elem(&icmp_map, &iph.daddr, &new_entry, BPF_ANY);
        entry = &new_entry;
    }
    
    __u64 diff;
    if (entry->stamp > cur_stamp) {
        diff = ONE_SECOND;
    }
    else diff = cur_stamp - entry->stamp;

    entry->stamp = cur_stamp;

    diff = mymin64(ONE_SECOND, diff);

    if (diff >= ONE_SECOND / 2) {
        entry->credit = mymin32(1000, entry->credit + (int)(1000 * diff / ONE_SECOND));
    }

    __u32 consume = bpf_get_prandom_u32() % 2 + 1;
    __u8 drop = 0;

    if (entry->credit < consume) {
        drop = 1;
    }
    else {
        entry->credit -= consume;
    }

    bpf_map_update_elem(&icmp_map, &iph.daddr, entry, BPF_ANY);    

    if (drop) {
        bpf_trace_printk("Dropped an ICMP packet according to rate limit!\n", sizeof("Dropped an ICMP packet according to rate limit!\n"));
        return NF_DROP;
    }


    if ((icmph.type != ICMP_DEST_UNREACH || icmph.code != ICMP_FRAG_NEEDED) && icmph.type != ICMP_REDIRECT) {
        return NF_ACCEPT;
    }

    if (bpf_probe_read_kernel(&inner_iph, sizeof(inner_iph), skb->head + skb->network_header + sizeof(iph) + sizeof(icmph)) < 0) {
        return NF_ACCEPT;
    }

    if (inner_iph.protocol == IPPROTO_UDP || inner_iph.protocol == IPPROTO_ICMP) { //stateless protocol
        if (icmph.type == ICMP_DEST_UNREACH && icmph.code == ICMP_FRAG_NEEDED) {
          bpf_trace_printk("Dropped an ICMP_FRAG_NEEDED packet!\n", sizeof("Dropped an ICMP_FRAG_NEEDED packet!\n"));
        } else {
          bpf_trace_printk("Dropped an ICMP_REDIRECT packet!\n", sizeof("Dropped an ICMP_REDIRECT packet!\n"));
        }
        return NF_DROP;
    }

    return NF_ACCEPT;
}

char _license[] SEC("license") = "GPL";