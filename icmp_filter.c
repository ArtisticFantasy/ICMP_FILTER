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
    long long credit;
    __u64 stamp;
};

static 

__u64 mymin64(__u64 a, __u64 b) {
    return a < b ? a : b;
}

__u32 mymin32(__u32 a, __u32 b) {
    return a < b ? a : b;
}

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct perdst_entry);
	__uint(max_entries, 2048);
} icmp_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} hash_key SEC(".maps");

__u32 hash_calc (__u32 ip) {
    __u32 x = 0;
    __u32* key = bpf_map_lookup_elem(&hash_key, &x);
    if (!key) {
        __u32 tmp = bpf_get_prandom_u32();
        key = &tmp;
        bpf_map_update_elem(&hash_key, &x, key, BPF_ANY);
    }
    return (ip ^ *key) % 2048;
}

/*NF_INET_LOCAL_IN*/
SEC("netfilter")
int icmp_filter(struct bpf_nf_ctx *ctx) {
    struct sk_buff *skb = ctx->skb;
    struct iphdr iph, inner_iph;
    struct icmphdr icmph, inner_icmph;

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
    __u32 hash = hash_calc(iph.daddr);

    if (hash >= 2048 ) {
        hash = 0;
    }

    struct perdst_entry *entry = bpf_map_lookup_elem(&icmp_map, &hash);
    if (!entry) {
        struct perdst_entry new_entry = {
            .credit = 1000,
            .stamp = cur_stamp,
        };
        bpf_map_update_elem(&icmp_map, &hash, &new_entry, BPF_ANY);
        entry = &new_entry;
    }
    
    __u64 old_stamp, new_stamp;
    __u64 diff;
    long long old_credit, new_credit;
    __u8 drop = 0;
    __u32 consume = bpf_get_prandom_u32() % 2 + 1;
    old_stamp = entry->stamp;
    old_credit = entry->credit;

    diff = cur_stamp > old_stamp ? cur_stamp - old_stamp : ONE_SECOND;
    new_stamp = cur_stamp;
    diff = mymin64(ONE_SECOND, diff);

    if (diff >= ONE_SECOND / 2) {
        new_credit = mymin64(1000, old_credit + (int)(1000 * diff / ONE_SECOND));
    }
    else {
        new_credit = old_credit;
    }

    if (new_credit < consume) {
        drop = 1;
    }

    if (__sync_val_compare_and_swap(&entry->stamp, old_stamp, new_stamp) == old_stamp) {
        if (__sync_val_compare_and_swap(&entry->credit, old_credit, new_credit - (drop ? 0 : consume)) == old_credit) {
            goto finish;
        }
    }

    if (__sync_sub_and_fetch(&entry->credit, consume) < 0) {
        drop = 1;
        __sync_add_and_fetch(&entry->credit, consume);
    }

finish:
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

    if (icmph.type == ICMP_REDIRECT) {
        if (inner_iph.protocol == IPPROTO_UDP || inner_iph.protocol == IPPROTO_ICMP) {
            bpf_trace_printk("Dropped an ICMP_REDIRECT packet!\n", sizeof("Dropped an ICMP_REDIRECT packet!\n"));
            return NF_DROP;
        }
    } else {
        if (inner_iph.protocol == IPPROTO_ICMP) {
            if (bpf_probe_read_kernel(&inner_icmph, sizeof(inner_icmph), skb->head + skb->network_header + sizeof(iph) + sizeof(icmph) + sizeof(inner_iph)) < 0) {
                return NF_ACCEPT;
            }
            if (inner_icmph.type == ICMP_ECHOREPLY) {
                bpf_trace_printk("Dropped an ICMP_REDIRECT packet!\n", sizeof("Dropped an ICMP_REDIRECT packet!\n"));
                return NF_DROP;
            }
        }
    }

    return NF_ACCEPT;
}

char _license[] SEC("license") = "GPL";