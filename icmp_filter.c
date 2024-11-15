#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <linux/netfilter.h>
#include <bpf/bpf_helpers.h>
#include "common.h"

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