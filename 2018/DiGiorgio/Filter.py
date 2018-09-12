# encoding=utf8
# autore: Salvatore Costantino
# modificato da: Alessandro Di Giorgio
# mail: s.costantino5@studenti.unipi.it,
#       a.digiorgio1@studenti.unipi.it

def filter(args,bpf_text):
    """
        modifica codice BPF, aggiungendo filtri su PID e porte
    """
    if args.pid: #filtraggio su PIDs
        try:
            dpids = [int(dpid) for dpid in args.pid.split(',')]
            dpids_if = ' && '.join(['pid != %d' % dpid for dpid in dpids])
            bpf_text = bpf_text.replace('FILTER_PID',
                'if (%s) { return 0; }' % dpids_if) #accept
        except ValueError:
            print("wrong value for pid (ignored option): %s" % args.pid)
    if args.port: #filtraggio su porte
        try:
            dports = [int(dport) for dport in args.port.split(',')]
            dports_if = ' && '.join(['port != %d' % dport for dport in dports])
            print(dports_if)
            bpf_text = bpf_text.replace('FILTER_PORT_A',
                'if (%s) { return 0; }' % dports_if) #accept
            bpf_text = bpf_text.replace('FILTER_PORT',
                'if (%s) { currsock.delete(&pid); return 0; }' % dports_if) #connect
        except ValueError:
            print("wrong value(s) for port (ignored option) : %s" % args.port)
    if args.rport: #filtraggio su porte (range)
        try:
            a,b=args.rport.split(',',1)
            a=int(a)
            b=int(b)
            if not(a < 0 or b < 0) and a<=b:
                bpf_text = bpf_text.replace('FILTER_RPORT_A',
                    'if (port < %d || port > %d) { return 0; }' % (a, b)) #accept
                bpf_text = bpf_text.replace('FILTER_RPORT',
                    'if (port < %d || port > %d) { currsock.delete(&pid); return 0; }' % (a, b)) #connect
            else:
                print("wrong value(s) for rport (ignored option) : %s" % args.rport)
        except ValueError:
            print("wrong value(s) for rport (ignored option) : %s" % args.rport)

    bpf_text = bpf_text.replace('FILTER_PID', '')

    bpf_text = bpf_text.replace('FILTER_PORT_A', '')
    bpf_text = bpf_text.replace('FILTER_RPORT_A', '')

    bpf_text = bpf_text.replace('FILTER_PORT', '')
    bpf_text = bpf_text.replace('FILTER_RPORT', '')

    return bpf_text
