import curses
from typing import Dict
import utils
import socket
from curses import wrapper
import sflow
from datetime import datetime
import threading
import math

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from _curses import _CursesWindow
    Window = _CursesWindow
else:
    from typing import Any
    Window = Any


# thread structure for handling user input
inter_thread = {
    'exit': False,
    'refresh': False,
    'sortBy': 0
}


# function for writing in the terminal without errors
def safe_write(stdscr: Window, string: str, end='\n', bold=False):
    height, width = stdscr.getmaxyx()
    y, x = stdscr.getyx()
    if y < height - 1 or (y == height - 1 and x == 0):
        try:
            if not bold:
                stdscr.addnstr(y,x,f'{string}{end}', width)
            else:
                stdscr.addnstr(f'{string}{end}', width, curses.A_STANDOUT)
        except:
            pass


# function for handling the different key presses
def press_handler(stdscr: Window):
    global inter_thread
    while not inter_thread['exit']:
        ch = ''
        try:
            ch = stdscr.getkey()
        except:
            pass
        if ch == 'r':
            inter_thread['refresh'] = True
        elif ch ==  's':
            inter_thread['refresh'] = True
            inter_thread['sortBy'] = (inter_thread['sortBy'] + 1) % 4
        elif ch ==  'q':
            inter_thread['exit'] = True
         

# function for scaling and showing the top talkers of the network 
def print_top_talkers(stdscr: Window, IPs: Dict, max_talkers: int, sortBy: int, samplePool: tuple, samples: int):
    if samples == 0: return
    if samplePool[0] == -1: return
    
    samplingRatio = (samplePool[1] - samplePool[0]) / samples
    
    curr_time = datetime.now().strftime('%Y-%m-%d_%H:%M:%S.%f')[:-3]
    
    stdscr.clear()
    
    safe_write(stdscr, f'Time: {curr_time}\tRatio: {round(samplingRatio)}')
    safe_write(stdscr, '+----+-----------------+--------------+--------------+--------------+--------------+')
    safe_write(stdscr, '|Rank|        IP       |', end='')
    safe_write(stdscr, '   inBytes    ', end='', bold=(sortBy == 0))
    safe_write(stdscr, '|', end='')
    safe_write(stdscr, '  inPackets   ', end='', bold=(sortBy == 1))
    safe_write(stdscr, '|', end='')
    safe_write(stdscr, '   outBytes   ', end='', bold=(sortBy == 2))
    safe_write(stdscr, '|', end='')
    safe_write(stdscr, '  outPackets  ', end='', bold=(sortBy == 3))
    safe_write(stdscr, '|')
    safe_write(stdscr, '+----+-----------------+--------------+--------------+--------------+--------------+')

    tmpDict = {}
    for IP in IPs:
        tmpDict[IP] = (
            (round(IPs[IP][0] * samplingRatio), round(196 * math.sqrt(utils.safe_div(1, IPs[IP][1])))),
            (round(IPs[IP][1] * samplingRatio), round(196 * math.sqrt(utils.safe_div(1, IPs[IP][1])))),
            (round(IPs[IP][2] * samplingRatio), round(196 * math.sqrt(utils.safe_div(1, IPs[IP][3])))),
            (round(IPs[IP][3] * samplingRatio), round(196 * math.sqrt(utils.safe_div(1, IPs[IP][3]))))
        )
    i = 0
    for w in sorted(tmpDict, key=lambda x: tmpDict[x][sortBy], reverse=True):
        if max_talkers == 0 or max_talkers > i:
            # the Top Talkers are shown with the error percentage
            safe_write(stdscr, 
                "|{:^4}|{:<17}|{:^14}|{:^14}|{:^14}|{:^14}|".format(i+1, w, 
                    str(utils.prettify_bytes(tmpDict[w][0][0]) + ('±') + (str(tmpDict[w][0][1])) + ('%')), 
                    str(str(tmpDict[w][1][0]) + ('±') + (str(tmpDict[w][1][1])) + ('%') ), 
                    str(utils.prettify_bytes(tmpDict[w][2][0]) + ('±') + (str(tmpDict[w][2][1])) + ('%')), 
                    str(str(tmpDict[w][3][0]) + ('±') + (str(tmpDict[w][3][1])) + ('%') )
                )
            )
            i += 1
        else:
            break
    safe_write(stdscr, '+----+-----------------+--------------+--------------+--------------+--------------+')
    stdscr.refresh()


# main tool function
def tool(stdscr: Window, args):
    
    global inter_thread
    
    #this is the thread that handles keyboard interruptions
    t = threading.Thread(target=press_handler, args=(stdscr, ))
    t.start()

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((args.a, args.p))
        sock.settimeout(1)
    except:
        print('Cannot connect to socket, exiting...', flush=True)
        exit(1)
    safe_write(stdscr, "Waiting for sFlow packets to arrive...")
    stdscr.refresh()

    IPs = {}
    samplePool = (-1, 0)
    samples = 0
    while not inter_thread['exit']:
        inter_thread['refresh'] = False
        try:
            (data, _) = sock.recvfrom(utils.BUF_MAX)
            sflow_data = sflow.sFlow(data)
            (samplePool, samples) = utils.parse_sp(sflow_data, samplePool, samples)
            (IPs, inter_thread['refresh']) = utils.parse_ips(sflow_data, IPs)
            
        except socket.timeout:
            pass
        
        if inter_thread['refresh']:
            print_top_talkers(stdscr, IPs, args.m, inter_thread['sortBy'], samplePool, samples)


def main():
    args = utils.parse_args()
    wrapper(tool,args)


if __name__ == '__main__':
    main()   