/* 
   File:            sysmacro.h
   Specifica:       macro per chiamate di sistema
*/
#ifndef __SYSMACRO_H
#define __SYSMACRO_H

#include <stdio.h>  /* serve per la perror */
#include <stdlib.h> /* serve per la exit   */
#include <string.h> /* serve per strlen    */
#include <errno.h>  /* serve per errno     */
#include <unistd.h> /* serve per la write  */

#define IFERROR(s, m) \
    if ((s) == -1)    \
    {                 \
        perror(m);    \
        exit(errno);  \
    }
#define IFERROR3(s, m, c) \
    if ((s) == -1)        \
    {                     \
        perror(m);        \
        c;                \
    }
#define IFNULL(s, m) \
    if ((s) == NULL) \
    {                \
        perror(m);   \
        exit(errno); \
    }

#define WRITE(m) IFERROR(write(STDOUT, m, strlen(m)), m);
#define WRITELN(m) \
    WRITE(m);      \
    WRITE("\n");

#ifndef STDIN
#define STDIN 0
#endif

#ifndef STDOUT
#define STDOUT 1
#endif

#ifndef STDERR
#define STDERR 2
#endif

#endif
