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

#include "PacketDispatcher.h"

extern "C"
{
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
}

using namespace BPFRD;

PacketDispatcher::PacketDispatcher( DispatchingModes dispatchingMode, list<BalOutIface *> * outIfList, unsigned int _tableSize, unsigned int agingTime )
{
    this->dspMode = dispatchingMode; //% this->hashingModesNum;

    //Round up to next power of 2 thaken from http://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
    tableSize = _tableSize;
    --tableSize;
    tableSize |= tableSize >> 1;
    tableSize |= tableSize >> 2;
    tableSize |= tableSize >> 4;
    tableSize |= tableSize >> 8;
    tableSize |= tableSize >> 16;
    ++tableSize;
    tableSize += (tableSize == 0);
    this->tableSizeMask = tableSize - 1;

    this->fluxTable = new HashTableElement[tableSize];

    this->agingTime = agingTime;

    this->outIfList = outIfList;

    this->refreshThread = new pthread_t;
    pthread_create(this->refreshThread, NULL, timedCleanTable, this);
}

PacketDispatcher::~PacketDispatcher()
{
    pthread_cancel(*this->refreshThread);
    delete this->refreshThread;

    delete[] this->fluxTable;
}

const ptHashFunc PacketDispatcher::hasherArray[hashingModesNum] = { ipHash, ippHash };

void * PacketDispatcher::timedCleanTable(void * arg)
{
#ifdef BPFRD_FUNC_PARAMS_CHECKING
    if(!arg)
    {
        std::cerr << "PacketDispatcher::timedCleanTable wrong parameter" << std::endl;
        return NULL;
    }
#endif
    PacketDispatcher * self = (PacketDispatcher *) arg;
    while(true)
    {
        sleep(self->agingTime / 3);
        time_t now;
        time(&now);
        for(int i=0; i < self->tableSize; ++i)
        {
            if(difftime(self->fluxTable[i].lastMatch, now) < self->agingTime)
            {
                self->fluxTable[i].reset();
            }
        }
    }
    pthread_exit(arg); // never executed
}

HashTableElement::HashTableElement()
{
    this->reset();
}

HashTableElement::~HashTableElement()
{}

void HashTableElement::reset()
{
    this->outIf = NULL;
}
