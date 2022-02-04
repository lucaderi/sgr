/**
 * @file
 *
 * @author Gioacchino Mazzurco <gio@eigenlab.org>
 *
 * @section LICENSE
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <iostream>
#include <unistd.h>
#include <csignal>

#include "BalOutIface.h"
#include "PacketDispatcher.h"

using namespace std;
using namespace BPFRD;

/**
 * @var keeprunning
 * @brief Global variable used for external signal hendling
 * @details True by default, false if received at least one of SIGHUP, SIGINT, SIGQUIT, SIGABRT, SIGTERM, SIGTSTP.
 */
bool keeprunning = true;

/**
 * @brief Handle external signal
 * @param signum Unused
 */
void stopMe_handler(int signum)
{
    keeprunning = false;
    (void)signum;
}

/**
 * @brief main
 * @param argc argument counts
 * @param argv arguments
 * @returns 0 everything gone as expected
 * @returns -1 wrong parameters
 * @returns -2 internal error
 */
int main( int argc, char * argv[] )
{
    string usage =  "usage: pfringbalancer <options>"
                    " -o <output interface> ( use multiple -o flags for multiple output interface ) \n"
                    " [ -i <input interface> ] \n"
                    " [ -m { 0 | 1 } ] ( dispatch mode ) \n";
    if( argc > 1 )
    {
        struct sigaction stopMe;
        memset(&stopMe, 0, sizeof(stopMe));
        stopMe.sa_handler = &stopMe_handler;
        sigaction(SIGHUP,  &stopMe, NULL);
        sigaction(SIGINT,  &stopMe, NULL);
        sigaction(SIGQUIT, &stopMe, NULL);
        sigaction(SIGABRT, &stopMe, NULL);
        sigaction(SIGTERM, &stopMe, NULL);
        sigaction(SIGTSTP, &stopMe, NULL);

        DispatchingModes dspMode = IP_DSP;
        string inputIf = "eth0";

        list<BalOutIface *> outIfs;

        int opt;

        while( (opt = getopt(argc, argv, "i:o:m:")) != -1)
        {
            switch (opt)
            {
            case 'i':
            {
                inputIf = optarg;
                break;
            }
            case 'o':
            {
                BalOutIface * oIf = new BalOutIface(optarg);
                oIf->open();
                outIfs.push_back(oIf);
                break;
            }
            case 'm':
            {
                switch (atoi(optarg))
                {
                case IP_DSP:
                {
                    dspMode = IP_DSP;
                    break;
                }
                case IPP_DSP:
                {
                    dspMode = IPP_DSP;
                    break;
                }
                default:
                {
                    FREE_OUT_IFACES;
                    cout << usage;
                    return -1;
                }
                }
                break;
            }
            default:
            {
                FREE_OUT_IFACES;
                cout << usage;
                return -1;
            }
            }
        }

        pfring * input_ring = pfring_open( (char *) inputIf.c_str(), 1500, PF_RING_PROMISC );

        if(!input_ring)
        {
            cout << "pfring_open error for " << inputIf << " " << strerror(errno) << endl;
        }
        else
        {
            pfring_set_application_name(input_ring, (char *)"pfringdispatcher-input");
            pfring_set_direction(input_ring, rx_only_direction);
            pfring_enable_ring(input_ring);

            PacketDispatcher dsp( dspMode, &outIfs );

            u_char *buffer;
            struct pfring_pkthdr hdr;

            while( keeprunning && pfring_recv(input_ring, &buffer, 0, &hdr, 1) )
            {
                PDEBUG(90,"main received %d bytes\n", hdr.caplen);
                /*
                for(int i = 0; i < hdr.caplen; ++i)
                {
                    cout << (char) buffer[i];
                }
                cout << endl;
                */
                dsp.dispatch( (char *) buffer, &hdr);
            }

            pfring_close(input_ring);
        }

        FREE_OUT_IFACES;

        if(keeprunning)
                return -2;

        return 0;
    }

    cout << usage;
    return -1;
}
