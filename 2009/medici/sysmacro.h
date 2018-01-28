/*
   File:            sysmacro.h
   Specifica:       macro per chiamate di sistema
*/

#ifndef SYSMACRO_H
#define SYSMACRO_H

#include <stdio.h>  /* serve per la perror */
#include <stdlib.h> /* serve per la exit   */
#include <string.h> /* serve per strlen    */
#include <errno.h>  /* serve per errno     */
#include <unistd.h> /* serve per la write  */

#define IFERROR(s,m) if((s)==-1) {perror(m); exit(errno);}
#define IFERROR3(s,m,c) if((s)==-1) {perror(m); c;}
//#define IFMAGG(s,m,msg)   if(s > m) {perror(msg); exit(0);}
#define IFMAGG(s,m)		if(s > m) {perror("The temporary buffer for writing characters is full, string was truncated!"); exit(0);}
#define IFNULL(s,msg)     if(s == NULL) {perror(msg); exit(errno);}
#define WRITE(m) IFERROR(write(STDOUT,m,strlen(m)), m);
#define WRITELN(m) WRITE(m);WRITE("\n");

#define STDIN  0
#define STDOUT 1
#define STDERR 2

#endif
