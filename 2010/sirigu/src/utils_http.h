#ifndef COLLECTD_UTILS_HTTP_H
#define COLLECTD_UTILS_HTTP_H 1
/*
 * collectd - src/utils_http.h
 * Copyright (C) 2010  Daniele Sirigu
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of The Measurement Factory nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * 
 * Author:
 *   Daniele Sirigu  <serdank at gmail.org>
 *
 * 
 */

#include "config.h"
#include <arpa/nameser.h>
#include <stdint.h>

#if HAVE_PCAP_H
# include <pcap.h>
#endif

#define T_MAX 65536
#define RM_MAX 8
#define SC_MAX 20
#define MM_MAX 9

/* Header HTTP packet type*/
enum PACKET_TYPE_E
{
  PT_HEADER_REQUEST,
  PT_HEADER_RESPONSE,
  PT_OTHER
};
typedef enum PACKET_TYPE_E PACKET_TYPE;

/* Mime type */
enum MIME_TYPE_E
{
  MIME_APPLICATION = 0,
  MIME_AUDIO = 1,
  MIME_EXAMPLE = 2,
  MIME_IMAGE = 3,
  MIME_MESSAGE = 4,
  MIME_MODEL = 5,
  MIME_MULTIPART = 6,
  MIME_TEXT = 7,
  MIME_VIDEO = 8  
};
typedef enum MIME_TYPE_E MIME_TYPE;

/* Request Method type */
enum REQUEST_METHOD_E
{
  RM_OPTIONS = 0,
  RM_GET = 1,
  RM_HEAD = 2,
  RM_POST = 3,
  RM_PUT = 4,
  RM_DELETE = 5,
  RM_TRACE = 6,
  RM_CONNECT = 7

};
typedef enum REQUEST_METHOD_E REQUEST_METHOD;

/* Status Code type*/
enum STATUS_CODE_E
{
  SC_100 = 0,
  SC_101 = 1,
  SC_200 = 2,
  SC_201 = 3,
  SC_202 = 4,
  SC_203 = 5,
  SC_204 = 6,
  SC_205 = 7,
  SC_206 = 8,
  SC_300 = 9,
  SC_301 = 10,
  SC_302 = 11,
  SC_303 = 12,
  SC_304 = 13,
  SC_305 = 14,
  SC_306 = 15,
  SC_307 = 16,
  SC_400 = 17,
  SC_401 = 18,
  SC_402 = 19,
  SC_403 = 20,
  SC_404 = 21,
  SC_405 = 22,
  SC_406 = 23,
  SC_407 = 24,
  SC_408 = 25,
  SC_409 = 26,
  SC_410 = 27,
  SC_411 = 28,
  SC_412 = 29,
  SC_413 = 30,
  SC_414 = 31,
  SC_415 = 32,
  SC_416 = 33,
  SC_417 = 34,
  SC_500 = 35,
  SC_501 = 36,
  SC_502 = 37,
  SC_503 = 38,
  SC_504 = 39,
  SC_505 = 40

};
typedef enum STATUS_CODE_E STATUS_CODE;

/*
* Structure used to represent an HTTP header 
*/
struct http_header_s 
{
  PACKET_TYPE packet_type;
  REQUEST_METHOD request_method;
  STATUS_CODE status_code;
  MIME_TYPE mime_type;
  unsigned int has_mime_type:1;
  uint16_t length;
  
};
typedef struct http_header_s http_header_t;

/* Counters of the number of Request Methods (one counter for every request method type)*/
extern int rm_type_counts[RM_MAX];   
/* Counters of the number of Status Codes  (one counter for every status code type)*/
extern int sc_type_counts[SC_MAX];   
/* Counters of the number of Mime Types (one counter for every mime type)*/
extern int mime_type_counts[MM_MAX];

#if HAVE_PCAP_H
/* Function that sets the network device that will be sniffed*/
void http_set_pcap_obj (pcap_t *po);
#endif
/* Functions that sets the callback that sent the values to collectd */
void http_set_callback (void (*cb) (const http_header_t *));
/**/
void ignore_list_add_name (const char *name);
#if HAVE_PCAP_H
/**/
void handle_pcap (u_char * udata, const struct pcap_pkthdr *hdr, const u_char * pkt);
#endif
/* Function that returns the string corresponding to the input request method type */
const char *rm_str(int r);
/* Function that returns the string corresponding to the input status code type */
const char *sc_str(int s);
/* Function that returns the string corresponding to the input mime type */
const char *mime_str(int m);

#endif /* !COLLECTD_UTILS_HTTP_H */
