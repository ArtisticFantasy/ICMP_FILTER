#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <time.h>

struct log_event {
    __u32 pid;
    char ip[256];
    __u8 type;
    __u64 timestamp;
};

void handle_event(void *ctx, int cpu, void *data, __u32 size) {
    struct event *e = data;
    printf("CPU: %d, PID: %u, Message: %s\n", cpu, e->pid, e->message);
}

void print_log(struct log_event event) {
    struct timespec boot_time, real_time;
    clock_gettime(CLOCK_BOOTTIME, &boot_time);
    clock_gettime(CLOCK_REALTIME, &real_time);

    u64 boot_sec = boot_time.tv_sec;
    u64 real_sec = real_time.tv_sec;
    u64 offset_sec = real_sec - boot_sec;

    // 将内核时间转换为用户空间时间
    time_t user_time_sec = event.timestamp/1e9 + offset_sec;

    struct tm *user_time_tm = localtime(&user_time_sec);

    printf("[%s] ICMP Filter: ", asctime(user_time_tm));
    switch (event.type) {
        case 0:
            printf("Dropped an ICMP packet from %s according to rate limit!\n", event.ip);
            break;
        case 1:
            printf("Dropped an ICMP Redirect packet from %s!\n", event.ip);
            break;
        case 2:
            printf("Dropped an ICMP Fragment Needed packet from %s!\n", event.ip);
            break;
    }
}

int main() {
    struct perf_buffer *pb;
    struct perf_buffer_opts pb_opts = {};
    int map_fd;

    obj = bpf_object__open_file("icmp_filter.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open eBPF object file\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load eBPF object\n");
        bpf_object__close(obj);
        return 1;
    }

    map_fd = bpf_object__find_map_fd_by_name(obj, "log_map");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find 'events' map\n");
        bpf_object__close(obj);
        return 1;
    }

    pb = perf_buffer__new(map_fd, 8, handle_event, NULL, NULL, NULL);
    if (!pb) {
        fprintf(stderr, "Failed to create perf buffer\n");
        bpf_object__close(obj);
        return 1;
    }

    while (1) {
        int ret = perf_buffer__poll(pb, 100);
        if (ret < 0) {
            fprintf(stderr, "Error polling perf buffer: %d\n", ret);
            break;
        }
    }

    perf_buffer__free(pb);
    bpf_object__close(obj);
    return 0;
}