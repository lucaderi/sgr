import re
import structures

def st(albero, packet, igmp_opt):
    # take protocol (transport layer) from packet
    protocol_result = re.search('proto (\w+)', packet)
    test_protocol = protocol_result.group(1)
    # take the sender ip and port from packet
    if test_protocol == 'IGMP':
        if igmp_opt == 'yes':
            return "Satisfied a filter"
        else:
            return "Any filter has been satisfied"

    sender = re.search('(([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})).([0-9]{1,6}) >', packet)
    test_sender_ip = sender.group(1)
    test_sender_port = int(sender.group(6))
    #take the destination ip and port from packet
    receiver = re.search('(([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})).([0-9]{1,6}):', packet)
    test_receiver_ip = receiver.group(1)
    test_receiver_port = int(receiver.group(6))
    pkt = (test_protocol,test_receiver_ip,test_receiver_port,test_sender_ip,test_sender_port)
    #print 'ricevuto ' + pkt[0] + ' ' + pkt[1] + ' ' + str(pkt[2]) + ' ' + pkt[3] + ' ' + str(pkt[4]) + '\n'
    return albero.search(pkt)

def tentar(albero,tupl):
    return albero.search(tupl)
