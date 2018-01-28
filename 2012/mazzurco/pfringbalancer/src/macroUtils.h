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

#ifndef __MACROUTILS_H__
#define __MACROUTILS_H__

/**
 * @def likely
 * @brief Suggests to gcc compiler that the expression passed as param has probably true value
 * @param x The expression
 */
#define likely(x) __builtin_expect((x),1)

/**
 * @def unlikely
 * @brief Suggests to gcc compiler that the expression passed as param has probably false value
 * @param x The expression
 */
#define unlikely(x) __builtin_expect((x),0)

/**
 * @def FREE_OUT_IFACES
 * @brief Free output interfaces
 */
#define FREE_OUT_IFACES while(outIfs.size()) { delete outIfs.front(); outIfs.pop_front(); }

/**
 * @def PDEBUG
 * @brief Printf like conditional debugging macro, substituted with nothing if debug is disabled ( BPFRD_DEBUG_LEVEL <= 0 )
 * @param level Maximum debug level of messages printed
 */
#if BPFRD_DEBUG_LEVEL > 0

extern "C"
{
#include "stdio.h"
}

#define PDEBUG(level,...) if(level <= BPFRD_DEBUG_LEVEL) printf(__VA_ARGS__)

#else
#define PDEBUG(level,...)

#endif //BPFRD_DEBUG_LEVEL > 0


#endif //__MACROUTILS_H__
