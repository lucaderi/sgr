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

#include "BalOutIface.h"
#include "macroUtils.h"

extern "C"
{
#include <pfring.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
}

using namespace BPFRD;

BalOutIface::BalOutIface(string ifName, unsigned int refreshTime)
{  
    PDEBUG(90, "BalOutIface::BalOutIface(%s)\n", ifName.c_str());

    this->ifName = ifName;
    this->closed = true;
    this->outRing = NULL;

    this->refreshThread = NULL;
    this->refreshTime = refreshTime;
    this->freshTxPkts = 0;
}

BalOutIface::~BalOutIface()
{
    PDEBUG(90, "BalOutIface::~BalOutIface()\n");
    if(!this->closed)
        this->close();
}

int BalOutIface::open()
{
    PDEBUG(90, "BalOutIface::open()\n");
    if(!this->closed)
    {
        PDEBUG(3, "BalOutIface::open() tryng to open already opened interface %s\n", this->ifName.c_str());
        return 2;
    }
    //                          \\     // this is not necessary if the method in the library has correct type!
    this->outRing = pfring_open((char *)this->ifName.c_str(), 1500, 0);
    if(!this->outRing)
    {
        std::cerr << "pfring_open error for " << this->ifName << " " << strerror(errno) << std::endl;
        pfring_close(this->outRing);
        return -1;
    }

    pfring_set_application_name(this->outRing, (char *) "pfringbalancer-out");
    pfring_set_direction(this->outRing, tx_only_direction);
    pfring_enable_ring(this->outRing);

    this->closed = false;
    this->freshTxPkts = 0;

    this->refreshThread = new pthread_t;
    pthread_create(this->refreshThread, NULL, &(this->refreshTxPkts), this);

    return 1;
}

void BalOutIface::close()
{
    PDEBUG(90, "BalOutIface::close()\n");
    if(!this->closed)
    {
        pfring_close(this->outRing);
        this->closed = true;

        pthread_cancel(*this->refreshThread);
        delete this->refreshThread;

        return;
    }

    PDEBUG(3, "BalOutIface::close() trying to close already closed interface %s\n", this->ifName.c_str());
}

void * BalOutIface::refreshTxPkts(void * arg)
{
    BalOutIface * self = (BalOutIface *) arg;

    while(!self->closed)
    {
        sleep(self->refreshTime);
        self->freshTxPkts = 0;
    }

    pthread_exit(NULL);
}
