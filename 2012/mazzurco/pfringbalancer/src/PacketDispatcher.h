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

#ifndef __PACKETDISPATCHER_H__
#define __PACKETDISPATCHER_H__

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <list>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>

#include "BalOutIface.h"
#include "macroUtils.h"

extern "C"
{
#include <time.h>
#include <pfring.h>
#include <pthread.h>
}

namespace BPFRD
{

/**
 * @typedef ptHashFunc
 * @brief type of packets hashing capable function
 */
typedef unsigned int (*ptHashFunc) (char buffer[], unsigned int buffer_len, unsigned int mask);

/**
 * @class HashTableElement
 * @brief Represent an element of the flux hash table
 */
class HashTableElement
{
public:
    HashTableElement();
    ~HashTableElement();

    /**
     * @brief pointer to the BalOutIface dispatching packets flow matching this HashTableElement
     */
    BalOutIface * outIf;

    /**
     * @brief time of latest packet dispatched matching this this HashTableElement
     */
    time_t lastMatch;

    /**
     * @brief reset this HashTableElement
     */
    void reset();
};

/**
 * @enum DispatchingModes
 * @brief Available dispatching modes enum
 */
enum DispatchingModes { IP_DSP, IPP_DSP };

/**
 * @class PacketDispatcher
 * @brief Represent The Dispatcher
 */
class PacketDispatcher
{
public:
    /**
     * @brief Initialize PacketDispatcher
     * @param dispatchingMode chosen dispatching mode from DispatchingModes enum
     * @param outIfList list of output interface
     * @param _tableSize size of hashtable ( will be rounded to next power of 2 )
     * @param agingTime time in seconds between periodical flow hash table cleanings
     */
    PacketDispatcher( DispatchingModes dispatchingMode, list<BalOutIface *> * outIfList, unsigned int _tableSize = 1024, unsigned int agingTime = 600 );
    ~PacketDispatcher();

    /**
     * @brief dispatch dispatch packet
     * @param pkt packet
     * @param hdr pfring packet header
     */
    inline void dispatch(char * pkt, struct pfring_pkthdr *hdr)
    {
        #ifdef BPFRD_FUNC_PARAMS_CHECKING
        if( !pkt || !hdr)
        {
            std::cerr << "PacketDispatcher::dispatch() wrong parameters" << std::endl;
            return;
        }
        #endif

        HashTableElement * flux = &this->fluxTable[hash(this->dspMode, pkt, hdr->caplen, this->tableSizeMask)];
        if(unlikely(!flux->outIf))
        {
            this->outIfList->sort(BalOutIface::compare);
            flux->outIf = this->outIfList->front();
        }

        flux->outIf->send(pkt, hdr->caplen);
        time(&flux->lastMatch);
    }

protected:
    /**
     * @brief selected dispatching mode
     */
    DispatchingModes dspMode;

    /**
     * @brief real flow hash table size
     */
    unsigned int tableSize;

    /**
     * @brief mask used for fast hashing
     */
    unsigned int tableSizeMask;

    /**
     * @brief time in seconds between periodical flow hash table cleanings
     */
    unsigned int agingTime;

    /**
     * @brief pointer to flow hash table
     */
    HashTableElement * fluxTable;

    /**
     * @brief pointer to output interface list
     */
    list<BalOutIface *> * outIfList;

    /**
     * @brief pointer to flow hash table cleaner thread
     */
    pthread_t * refreshThread;

    /**
     * @brief Hash table cleaner loop
     * @param arg A pointer to PacketDispatcher must be passed as argument because the function is static to be referanceable
     */
    static void * timedCleanTable(void * arg);

    /**
     * @brief Number of hashing modes available
     */
    static const unsigned int hashingModesNum = 2;

    /**
     * @brief Array of pointers to the available hashing function
     */
    static const ptHashFunc hasherArray[hashingModesNum];

    /**
     * @brief function to be called to hash packets
     * @param hashingMode hashing mode
     * @param buffer packet to be hashed
     * @param buffer_len packet lenght
     * @param mask mask for fast hashing
     * @return packet hash
     */
    static inline unsigned int hash(DispatchingModes hashingMode, char * buffer, unsigned int buffer_len, unsigned int mask)
    {
        #ifdef BPFRD_FUNC_PARAMS_CHECKING
        if( unlikely( hashingMode < 0 || hashingMode >= hashingModesNum ) )
        {
            std::cerr << "PacketDispatcher::hash() called with wrong hashingMode: " << hashingMode << std::endl;
            return 0;
        }
        #endif
        return PacketDispatcher::hasherArray[hashingMode](buffer, buffer_len, mask);
    }

    /**
     * @brief Source and destination IP hashing function
     * @param buffer packet to hash
     * @param buffer_len packet lenght
     * @param mask
     * @return pachet hash
     */
    static inline unsigned int ipHash(char buffer[], unsigned int buffer_len, unsigned int mask)
    {
        register unsigned int hash = 0;

        #ifdef BPFRD_FUNC_PARAMS_CHECKING
        if( unlikely( !buffer || buffer_len == 0 ) )
        {
            std::cerr << "PacketDispatcher::hash() called with wrong parameters" << std::endl;
            return hash;
        }
        #endif

        unsigned short int minAcceptableLen = sizeof(struct ether_header);
        if( unlikely(buffer_len <= minAcceptableLen) )
            return hash;

        struct ether_header * ehdr = (struct ether_header *) buffer;

        u_short eth_type = ehdr->ether_type;

        switch_ether: ;
        switch (eth_type)
        {
        case ETHERTYPE_IP:
        {
            minAcceptableLen += sizeof(ip);
            if( unlikely( buffer_len <= minAcceptableLen))
                return hash;

            struct ip * iphdr = (ip*)buffer + sizeof(ether_header);
            hash = (iphdr->ip_src.s_addr + iphdr->ip_dst.s_addr) & mask;

            PDEBUG(90, "\nParsed valid IPv4 packet!!\n");

            return hash;
        }
        case ETHERTYPE_IPV6:
        {
            minAcceptableLen += sizeof(ip6_hdr);
            if( unlikely( buffer_len <= minAcceptableLen))
                return hash;

            struct ip6_hdr * ip6hdr = (ip6_hdr *)buffer + sizeof(ether_header);
            hash  = ip6hdr->ip6_src.s6_addr32[0] ^ ip6hdr->ip6_dst.s6_addr32[0];
            hash += ip6hdr->ip6_src.s6_addr32[1] ^ ip6hdr->ip6_dst.s6_addr32[1];
            hash += ip6hdr->ip6_src.s6_addr32[2] ^ ip6hdr->ip6_dst.s6_addr32[2];
            hash += ip6hdr->ip6_src.s6_addr32[3] ^ ip6hdr->ip6_dst.s6_addr32[3];

            PDEBUG(90, "\nParsed valid IPv6 packet!!\n");

            return ( hash & mask );
        }
        case ETHERTYPE_VLAN:
        {
                buffer += 4;
                minAcceptableLen += 4;
                eth_type = buffer[16];
                eth_type <<= 8;
                eth_type += buffer[17];
                goto switch_ether;
        }
        }

        return hash;
    }

    /**
     * @brief Source IP, destination IP, transport protocol, source port, destination port hashing function
     * @param buffer packet to hash
     * @param buffer_len packet lenght
     * @param mask mask for fast hashing
     * @return packet hash
     */
    static inline unsigned int ippHash(char buffer[], unsigned int buffer_len, unsigned int mask)
    {
        register unsigned int hash = 0;

        #ifdef BPFRD_FUNC_PARAMS_CHECKING
        if( unlikely( !buffer || buffer_len == 0 ) )
        {
            std::cerr << "PacketDispatcher::hash() called with wrong parameters" << std::endl;
            return hash;
        }
        #endif

        unsigned short int minAcceptableLen = sizeof(struct ether_header);
        if( unlikely(buffer_len <= minAcceptableLen) )
            return hash;

        struct ether_header * ehdr = (struct ether_header *) buffer;

        u_short eth_type = ehdr->ether_type;

        uint8_t transport_proto = IPPROTO_IP;

        switch_ether: ;
        switch (eth_type)
        {
        case ETHERTYPE_IP:
        {
            minAcceptableLen += sizeof(ip);
            if( unlikely( buffer_len <= minAcceptableLen))
                return hash;

            struct ip * iphdr = (ip*)buffer + sizeof(ether_header);
            hash = (iphdr->ip_src.s_addr + iphdr->ip_dst.s_addr) & mask;

            buffer += sizeof(ip);
        }
        case ETHERTYPE_IPV6:
        {
            minAcceptableLen += sizeof(ip6_hdr);
            if( unlikely( buffer_len <= minAcceptableLen))
                return hash;

            struct ip6_hdr * ip6hdr = (ip6_hdr *)buffer + sizeof(ether_header);
            hash  = ip6hdr->ip6_src.s6_addr32[0] ^ ip6hdr->ip6_dst.s6_addr32[0];
            hash += ip6hdr->ip6_src.s6_addr32[1] ^ ip6hdr->ip6_dst.s6_addr32[1];
            hash += ip6hdr->ip6_src.s6_addr32[2] ^ ip6hdr->ip6_dst.s6_addr32[2];
            hash += ip6hdr->ip6_src.s6_addr32[3] ^ ip6hdr->ip6_dst.s6_addr32[3];

            buffer += sizeof(ip6_hdr);
        }
        case ETHERTYPE_VLAN:
        {
                buffer += 4;
                minAcceptableLen += 4;
                eth_type = buffer[16];
                eth_type <<= 8;
                eth_type += buffer[17];
                goto switch_ether;
        }
        }

        switch (transport_proto)
        {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
        {
            minAcceptableLen += 4;
            if( unlikely(buffer_len <= minAcceptableLen) )
                return hash;

            hash += * (unsigned int *) buffer;

            PDEBUG(90, "\nParsed valid TCP/UDP packet!!\n");
            return hash;
        }
        }

        return hash;
    }
};

}

#endif //__PACKETDISPATCHER_H__
