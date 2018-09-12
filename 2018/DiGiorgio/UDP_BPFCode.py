# creato da: Brendan Gregg
# modificato da: Alessandro Di Giorgio
    #mail: a.digiorgio1@studenti.unipi.it

text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/pid_namespace.h>

//crea hash map currsock, dove la chiave e' un u32 e il  valore e' un struct sock*
BPF_HASH(currsock, u32, struct sock *);

// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
    u64 pid;
    u64 uid;
    u64 saddr;
    u64 daddr;
    u64 ip;
    u64 port;
    char task[TASK_COMM_LEN];
};

//crea una tabella BPF per inviare informazioni allo spazio utente attraverso un buffer circolare.
BPF_PERF_OUTPUT(ipv4_send_events);
BPF_PERF_OUTPUT(ipv4_receive_events);

struct ipv6_data_t {
    u64 pid;
    u64 uid;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u64 ip;
    u64 port;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv6_send_events);
BPF_PERF_OUTPUT(ipv6_receive_events);


int trace_send_entry(struct pt_regs* ctx, struct sock* sk){
    u32 pid = bpf_get_current_pid_tgid();

    FILTER_PID

    currsock.update(&pid, &sk);
    return 0;
}

static int trace_send_return(struct pt_regs *ctx, short ipver){
    int ret = PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid();

    struct sock **skpp;
    skpp = currsock.lookup(&pid);
    if (skpp == NULL || ret == -1) {
        return 0;   // missed entry
    }

    // pull in details
    struct sock *skp = *skpp;
    u16 port = skp->__sk_common.skc_dport;
    port = ntohs(port);
    if(port == 0) return 0;

    FILTER_RPORT
    FILTER_PORT

    if (ipver == 4) {
        struct ipv4_data_t data4 = {.pid = pid, .ip = ipver};
        data4.saddr = skp->__sk_common.skc_rcv_saddr;
        data4.daddr = skp->__sk_common.skc_daddr;
        data4.port = ntohs(port);
        data4.uid = bpf_get_current_uid_gid() & 4294967295;
        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        ipv4_send_events.perf_submit(ctx, &data4, sizeof(data4)); //invio dati allo spazio utente
    } else if (ipver == 6) {
        struct ipv6_data_t data6 = {.pid = pid, .ip = ipver};
        bpf_probe_read(&data6.saddr, sizeof(data6.saddr),
            skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read(&data6.daddr, sizeof(data6.daddr),
            skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        data6.port = ntohs(port);
        data6.uid = bpf_get_current_uid_gid() & 4294967295;
        bpf_get_current_comm(&data6.task, sizeof(data6.task));
        ipv6_send_events.perf_submit(ctx, &data6, sizeof(data6));
    }

    currsock.delete(&pid); //elimino entry con pid *pid

    return 0;
}

int trace_send_v4_return(struct pt_regs *ctx) //IPV4
{
    return trace_send_return(ctx, 4);
}

int trace_send_v6_return(struct pt_regs *ctx) //IPV6
{
    return trace_send_return(ctx, 6);
}


static int trace_receive(struct pt_regs *ctx, struct sock *sk, short ipver){
    u32 pid = bpf_get_current_pid_tgid();
    FILTER_PID

    int ret = PT_REGS_RC(ctx);
    if (sk == NULL || ret == -1)
        return 0;
    u16 port = 0;
    port = sk->__sk_common.skc_num;
    port = ntohs(port);
    if(port == 0) return 0;

    FILTER_RPORT_A
    FILTER_PORT_A

    if (ipver == 4) {
        struct ipv4_data_t data4 = {.pid = pid, .ip = ipver};
        data4.saddr = sk->__sk_common.skc_rcv_saddr;
        data4.daddr = sk->__sk_common.skc_daddr;
        data4.port = ntohs(port);
        data4.uid = bpf_get_current_uid_gid() & 4294967295;
        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        ipv4_receive_events.perf_submit(ctx, &data4, sizeof(data4));
    } else if (ipver == 6) {
        struct ipv6_data_t data6 = {.pid = pid, .ip = ipver};
        data6.saddr = sk->__sk_common.skc_rcv_saddr;
        data6.daddr = sk->__sk_common.skc_daddr;
        data6.port = ntohs(port);
        data6.uid = bpf_get_current_uid_gid() & 4294967295;
        bpf_get_current_comm(&data6.task, sizeof(data6.task));
        ipv6_receive_events.perf_submit(ctx, &data6, sizeof(data6));
    }

    return 0;
}

int trace_receive_v4(struct pt_regs *ctx, struct sock *sk) {
    return trace_receive(ctx, sk, 4);
}

int trace_receive_v6(struct pt_regs *ctx, struct sock *sk) {
    return trace_receive(ctx, sk, 6);
}


"""
