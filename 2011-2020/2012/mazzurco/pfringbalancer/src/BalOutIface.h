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

#ifndef __BalOutIface_H__
#define __BalOutIface_H__

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <iostream>
#include <string>

extern "C"
{
#include <pthread.h>
#include <pfring.h>
#include <unistd.h>
#include <pthread.h>
}

#include "macroUtils.h"

using namespace std;

namespace BPFRD
{

/**
 * @class BalOutIface
 * @brief Represent an output interfaces used by the balancer
 */
class BalOutIface
{
public:
    /**
     * @brief Represent an output interface adapt to load balancing
     * @param ifName Linux interface name
     * @param refreshTime Time in seconds after packet count get resetted
     */
    BalOutIface(string ifName, unsigned int refreshTime = 10);
    ~BalOutIface();

    /**
     * @brief Open the interface for sending packets
     *
     * @returns 1  if evreything goes fine
     * @returns 2  if the interface was already open
     * @returns -1 if error occurred while opening the interface
     */
    int open();

    /**
     * @brief Close the interface
     */
    void close();

    /**
     * @brief Get linux interface name
     *
     * @return A string containing the linux interface name
     */
    string getIfName();

    /**
     * @brief Compare one interface to another by #freshTxPkts
     *
     * @param oIf1 first interface
     * @param oIf2 second interface
     *
     * @return true if oIf1 has sent less packet than oIf2, false otherwise
     */
    static inline bool compare (BalOutIface * oIf1, BalOutIface * oIf2)
    {
        return (oIf1->freshTxPkts < oIf2->freshTxPkts);
    }

    /**
     * @brief Send given packet throught the interface
     *
     * @param pkt Packet to send
     * @param lenght Lenght of the packet to send
     *
     * @returns pfring_send return value if passed param are correct or FUNC_PARAM_CHECKING is undefined
     * @returns 0 if FUNC_PARAM_CHECKING is defined and passed param are wrong
     */
    inline int send(char * pkt, size_t lenght)
    {
        PDEBUG(90,"BalOutIface::send(%p, %zu)\n", (void *)pkt, lenght);

        #ifdef BPFRD_FUNC_PARAMS_CHECKING
        if(!pkt || (lenght == 0) || this->closed)
        {
            std::cerr << "BalOutIface::send( "<< pkt << ", " << lenght << " )" << endl << this->closed << " WRONG PRECONDITIONS" << std::endl;
            return 0;
        }
        #endif

        ++this->freshTxPkts;

        int sended = pfring_send(this->outRing, pkt, lenght, 1);

        PDEBUG(90,"BalOutIface::send(%p, %zu) sended %d bytes trough %s\n", (void *)pkt, lenght, sended, this->ifName.c_str());

        return sended;
    }

protected:

    /**
     * @brief Stores the linux ifname to wich the #BalOutIface is attacched
     */
    string ifName;

    /**
     * @brief Pointer to the pf_ring output ring attacched to ifName
     */
    pfring * outRing;

    /**
     * @brief True if the interface is closed flase otherways
     */
    bool closed;

    /**
     * @brief Pointer tho the thread that reset the #freshTxPkts counter
     */
    pthread_t * refreshThread;

    /**
     * @brief Seconds between #freshTxPkts reset
     */
    unsigned int refreshTime;

    /**
     * @brief Number of recently sended packets
     */
    unsigned long long freshTxPkts;

    /**
     * @brief Reset #freshTxPkts counter to 0 approssimatively each #refreshTime seconds
     * @param arg The this pointer must be passed as arg as the function is static
     */
    static void * refreshTxPkts(void * arg);
};

}

#endif //__BalOutIface_H__
