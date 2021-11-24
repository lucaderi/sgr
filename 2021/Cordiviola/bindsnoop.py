#!/usr/bin/python3.8

#bindsnoop - trace IPv4 and IPv6 (TCP/UDP) bind attempts

# usage: sudo python3 bindsnoop.py

from bcc import BPF
from struct import pack
from socket import inet_ntop, AF_INET, AF_INET6

#BPF program
prog = """

#include <bcc/proto.h>
#include <net/inet_sock.h>

//structure to send information to user space
struct data_t {
   
    u64 ts;
    u64 pid;
    char comm[TASK_COMM_LEN];
    u64 port;
    u32 v4addr;
    u64 proto;
    u64 version;
    u64 v6addr[2];

};

//event map
BPF_PERF_OUTPUT(events);

static int inetbind(struct pt_regs* ctx, struct socket* sock, const struct sockaddr* addr, int addrlen){

    //initialize data structures
    struct data_t data;
    __builtin_memset(&data,0,sizeof(data));
    struct sock* sk = sock->sk;
    struct inet_sock* inetsk = (struct inet_sock*) sk;

    //get time
    data.ts = bpf_ktime_get_ns() / 1000;
    
    //get pid 
    data.pid = bpf_get_current_pid_tgid();
    
    //get comm
    bpf_get_current_comm(data.comm, TASK_COMM_LEN);

    //get protocol with direct read workaround
    u8 protocol = 0;
    bpf_probe_read(&protocol,1,(u8*)&sk->sk_gso_max_segs - 3);
    
    //TCP or UDP?
    if(protocol == IPPROTO_TCP)
        data.proto = 1;
    else if(protocol == IPPROTO_UDP)
        data.proto = 2;

    //get socket IP family
    u16 family = sk->__sk_common.skc_family;
    
    //get IPv4 address and port
    if(family == AF_INET){
        struct sockaddr_in *in_addr = (struct sockaddr_in *)addr;
        data.v4addr = in_addr->sin_addr.s_addr;
        data.port = in_addr->sin_port;
        data.port = ntohs(data.port);
        data.version = 1;
    }
    
    //or get IPv6 address and port
    else if(family == AF_INET6){
        struct sockaddr_in6 *in6_addr = (struct sockaddr_in6 *)addr;
        bpf_probe_read(data.v6addr,sizeof(data.v6addr),in6_addr->sin6_addr.s6_addr);
        data.port = in6_addr->sin6_port;
        data.port = ntohs(data.port);
        data.version = 2;
    }
    
    //submit event to user space
    events.perf_submit(ctx,&data, sizeof(data));
    return 0;

};

int kprobe__inet_bind(struct pt_regs* ctx, struct socket* socket, const struct sockaddr* addr, int addrlen){

    return inetbind(ctx,socket,addr,addrlen);

}

int kprobe__inet6_bind(struct pt_regs* ctx, struct socket* socket, const struct sockaddr* addr, int addrlen){

    return inetbind(ctx,socket,addr,addrlen);

}

"""

#format output
def print_event(cpu,data,size):
    event = b["events"].event(data)
    
    #get protocol, version, address and pid
    if event.proto == 1:
        protocol = "TCP"
    elif event.proto == 2:
        protocol = "UDP"
    else:
        protocol = "UNK"
    if event.version == 1:
        protocol += "v4"
        address = inet_ntop(AF_INET,pack("I",event.v4addr))
    elif event.version == 2:
        protocol += "v6"
        address = inet_ntop(AF_INET6,event.v6addr)
    pid = event.pid >> 32 
    print("%-10s %-20s %-12s %-8d %-40s" % (pid,event.comm,protocol,event.port,address))
    return print_event

#initialize BPF
b = BPF(text = prog)
b["events"].open_perf_buffer(print_event)

#print headers
print("%-10s %-20s %-12s %-8s %-40s" % ("PID","COMM","PROTO","PORT","ADDR"))

#read events
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
