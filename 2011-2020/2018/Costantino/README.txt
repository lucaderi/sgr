
REQUISITI
	-python 2.7
	-compilatore bcc (https://github.com/iovisor/bcc/blob/master/INSTALL.md) 
	-kernel Linux (versione >=4.1)
	-kernel compilato con i seguenti flag
		CONFIG_BPF=y
		CONFIG_BPF_SYSCALL=y
		CONFIG_NET_CLS_BPF=m
		CONFIG_NET_ACT_BPF=m	
		CONFIG_BPF_JIT=y
		CONFIG_HAVE_BPF_JIT=y
		CONFIG_BPF_EVENTS=y

USO
	eBPF_TCPFlow.py [-h] [-p PID] [-R RPORT] [-P PORT] [-f FILE]
	vedere relazione.pdf per maggiori dettagli sull'utilizzo del tool 

		
