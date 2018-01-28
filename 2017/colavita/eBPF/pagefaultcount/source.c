#include <linux/ptrace.h>
#include <linux/sched.h>
#include <uapi/linux/bpf_perf_event.h>
struct data_t {
	u32 pid;
	u64 cpu;
	char comm[TASK_COMM_LEN];
};

BPF_HASH(min_flt_table, struct data_t);
BPF_HASH(maj_flt_table, struct data_t);

static inline __attribute__((always_inline)) void get_key(struct data_t* data) {
    data->cpu = bpf_get_smp_processor_id();
    data->pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&(data->comm), sizeof(data->comm));
}

int page_min_flt(struct bpf_perf_event_data *ctx) {
    struct data_t data = {};
    get_key(&data);
    u64 zero = 0, *val;
    val = min_flt_table.lookup_or_init(&data, &zero);
    (*val) += ctx->sample_period;
    return 0;
}

int page_maj_flt(struct bpf_perf_event_data *ctx) {
    struct data_t data = {};
    get_key(&data);
    u64 zero = 0, *val;
    val = maj_flt_table.lookup_or_init(&data, &zero);
    (*val) += ctx->sample_period;
    return 0;
}

