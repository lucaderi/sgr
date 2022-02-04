#!/usr/bin/env python

from __future__ import print_function
from bcc import BPF
from time import strftime
    
#program
bpf_text = """
#include <uapi/linux/ptrace.h>


int printret(struct pt_regs *ctx) {
    if (!ctx->ax )
        return 0;
    char str[30] = {};
    bpf_probe_read(&str, sizeof(str), (void *)ctx->ax);
    bpf_trace_printk("%s\\n", &str);
    return 0;
}


int printret1(struct pt_regs *ctx) {
    if (!ctx->ax )
        return 0;
    char str[30] = {};
    bpf_probe_read(&str, sizeof(str), (void *)ctx->ax);
    bpf_trace_printk("%s\\n", &str);
    return 0;
}


int printerr(struct pt_regs *ctx) {
    if (!ctx->ax )
        return 0;
    char str[30] = {};
    bpf_probe_read(&str, sizeof(str), (void *)ctx->ax);
    bpf_trace_printk("%s\\n", &str);
    return 0;
};
"""
# load BPF program
b = BPF(text=bpf_text)
b.attach_uretprobe(name="/bin/bash", sym="get_name_for_error", fn_name="printerr") #cd error
b.attach_uretprobe(name="/bin/bash", sym="readline", fn_name="printret") # bash readline
b.attach_uretprobe(name="/bin/bash", sym="get_string_value", fn_name="printret1") # current_dir cd


def print_event(cd,prev):
    """format output
    Args: cd current path
          prev this directory path
    Return: name of previous and current folder after cd"""
    path = cd.split("/")
    if prev == '/' and path[0] == '..':
        return prev, prev
    prev_path = prev.split("/")
    prev_path.insert(1,"/")
    prev_path.remove('')
   
    if path[0] == '..':
	directory = prev_path[len(prev_path)-1]
	prev_path.remove(directory)
	return directory , prev_path[len(prev_path)-1]
    else:
	directory = '/'
	for i in prev_path:
	    if i != '':
		prev = i
	for i in path : 
	    if i != '':
		prev_path.append(i)
		directory = i
	return prev , directory
     

# header
print("%-12s %-10s %-15s %-10s %s" % ("TIME", "PID", "PREV_DIR" , "CURR_DIR" ,"COMM"))
directory = ""
while 1: 
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields() #return readline probe
    except ValueError:
            continue 
    if msg != '': 
        command = ""
        try:
            command,directory = msg.split(" ")
        except ValueError:
            directory = "~" 
        if command == 'cd' : 
            curr_pid = pid
            try:
                (task, pid, cpu, flags, ts, msg) = b.trace_fields() #return current_workdirectory probe
            except ValueError:
                    continue 
	    if msg == 'bash':
                print("%-12s %-5d %-1s %-1s %-1s %s " % (strftime("%H:%M:%S"), pid, 
                                        msg,": cd :",directory,
                                           "File o directory non esistente"))
            else:
		    prec_path = msg  
		    try:
		        (task, pid, cpu, flags, ts, msg) = b.trace_fields() 
		    except ValueError:
		            continue  
		    if msg == 'bash':
		        print("%-12s %-5d %-1s %-1s %-1s %s " % (strftime("%H:%M:%S"), pid, 
                                        msg,": cd :",directory,
                                           "File o directory non esistente"))             
		    else: 
		        if directory == "~" or directory == "--" :
		            directory = "home"
		        p , c = print_event(directory,prec_path)
		        print("%-12s %-10d %-15s %-10s %s" % (strftime("%H:%M:%S"), 
		                                              curr_pid, p,c,command+" "+directory))            
		    
