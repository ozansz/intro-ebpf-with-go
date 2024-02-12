// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define LINE_SIZE 100

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
    u32 pid;
    u8  line[LINE_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

SEC("uretprobe/bash_readline")
int uretprobe_bash_readline(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    pid_t pid = id >> 32;
    pid_t tid = (u32)id;

    if (pid != tid)
        return 0;

    struct event *e;

	e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!e) {
		return 0;
	}

	e->pid = pid;
	// bpf_probe_read(e->line, sizeof(e->line), (void *)(ctx->regs[0]));
	bpf_probe_read(e->line, sizeof(e->line), (void *)PT_REGS_RC(ctx));

	bpf_ringbuf_submit(e, 0);

	return 0;
}