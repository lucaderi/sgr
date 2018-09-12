# creato da: Brendan Gregg
# modificato da: Salvatore Costantino, Alessandro Di Giorgio
    #mail: s.costantino5@studenti.unipi.it,
    #      a.digiorgio1@studenti.unipi.it

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
BPF_PERF_OUTPUT(ipv4_connect_events);
BPF_PERF_OUTPUT(ipv4_accept_events);

struct ipv6_data_t {
    u64 pid;
    u64 uid;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u64 ip;
    u64 port;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv6_connect_events);
BPF_PERF_OUTPUT(ipv6_accept_events);


//ctx: Registers and BPF context... gli altri sono argomenti della sys-call da monitorare
int trace_connect_entry(struct pt_regs *ctx, struct sock *sk)
{
    u32 pid = bpf_get_current_pid_tgid();
    FILTER_PID

    // stash the sock ptr for lookup on returns
    currsock.update(&pid, &sk); //inserisco (&pid,&sk)

    return 0;
};

static int trace_connect_return(struct pt_regs *ctx, short ipver)
{
    int ret = PT_REGS_RC(ctx); //valore di ritorno della chiamata alla tcp_connect
    u32 pid = bpf_get_current_pid_tgid();

    struct sock **skpp;
    skpp = currsock.lookup(&pid); //ricerca per pid
    if (skpp == 0) {
        return 0;   // missed entry
    }


    if (ret != 0) {
        // failed to send SYNC packet, may not have populated
        // socket __sk_common.{skc_rcv_saddr, ...}
        currsock.delete(&pid); //elimino entry dalla tabella hash
        return 0;
    }

    // pull in details
    struct sock *skp = *skpp;
    u16 port = skp->__sk_common.skc_dport;
    port = ntohs(port);

    FILTER_RPORT
    FILTER_PORT

    if (ipver == 4) {
        struct ipv4_data_t data4 = {.pid = pid, .ip = ipver};
        data4.saddr = skp->__sk_common.skc_rcv_saddr;
        data4.daddr = skp->__sk_common.skc_daddr;
        data4.port = ntohs(port);
        /*
            prelevo l'id dell'utente chiamante
            prendendo gli ultimi 32 bit
        */
        data4.uid = bpf_get_current_uid_gid() & 4294967295;

        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        ipv4_connect_events.perf_submit(ctx, &data4, sizeof(data4));

    } else /* 6 */ {
        struct ipv6_data_t data6 = {.pid = pid, .ip = ipver};
        bpf_probe_read(&data6.saddr, sizeof(data6.saddr),
            skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read(&data6.daddr, sizeof(data6.daddr),
            skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        data6.port = ntohs(port);
        data6.uid = bpf_get_current_uid_gid() & 4294967295;
        bpf_get_current_comm(&data6.task, sizeof(data6.task));
        ipv6_connect_events.perf_submit(ctx, &data6, sizeof(data6));
    }

    currsock.delete(&pid); //elimino entry con pid *pid

    return 0;
}

int trace_connect_v4_return(struct pt_regs *ctx) //IPV4
{
    return trace_connect_return(ctx, 4);
}

int trace_connect_v6_return(struct pt_regs *ctx) //IPV6
{
    return trace_connect_return(ctx, 6);
}


int kretprobe__inet_csk_accept(struct pt_regs *ctx)
{
    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid();

    FILTER_PID

    if (newsk == NULL)
        return 0;

    // pull in details
    u16 port = 0;
    bpf_probe_read(&port, sizeof(port), &newsk->__sk_common.skc_num);
    port = ntohs(port);

    FILTER_RPORT_A
    FILTER_PORT_A

    u16 family = 0;
    bpf_probe_read(&family, sizeof(family), &newsk->__sk_common.skc_family);

    if (family == AF_INET) {
        struct ipv4_data_t data4 = {.pid = pid, .ip = 4};
        bpf_probe_read(&data4.saddr, sizeof(u32),
            &newsk->__sk_common.skc_rcv_saddr);
        bpf_probe_read(&data4.daddr, sizeof(u32),
            &newsk->__sk_common.skc_daddr);
        data4.port = port;
        data4.uid = bpf_get_current_uid_gid() & 4294967295;
        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        ipv4_accept_events.perf_submit(ctx, &data4, sizeof(data4));

    } else if (family == AF_INET6) {
        struct ipv6_data_t data6 = {.pid = pid, .ip = 6};
        bpf_probe_read(&data6.saddr, sizeof(data6.saddr),
            &newsk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read(&data6.daddr, sizeof(data6.daddr),
            &newsk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        data6.port = port;
        data6.uid = bpf_get_current_uid_gid() & 4294967295;
        bpf_get_current_comm(&data6.task, sizeof(data6.task));
        ipv6_accept_events.perf_submit(ctx, &data6, sizeof(data6));
    }
    return 0;
}
"""
