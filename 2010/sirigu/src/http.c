/*
 * collectd - src/http.c
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
#define _BSD_SOURCE
#include "collectd.h"
#include "common.h"
#include "plugin.h"
#include "configfile.h"
#include "utils_http.h"
#include <pthread.h>
#include <pcap.h>
#include <poll.h>

/* TCP header */
typedef u_int tcp_seq;
struct sniff_tcp {
  u_short th_sport;               /* Source port */
  u_short th_dport;               /* Destination port */
  tcp_seq th_seq;                 /* Sequence number */
  tcp_seq th_ack;                 /* Acknowledgement number */
  u_char  th_offx2;               /* Data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
  u_char  th_flags;
  #define TH_FIN  0x01
  #define TH_SYN  0x02
  #define TH_RST  0x04
  #define TH_PUSH 0x08
  #define TH_ACK  0x10
  #define TH_URG  0x20
  #define TH_ECE  0x40
  #define TH_CWR  0x80
  #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
  u_short th_win;                 /* Window */
  u_short th_sum;                 /* Checksum */
  u_short th_urp;                 /* Urgent pointer */
};

/* Key-value pairs linked list */
struct counter_list_s
{
  unsigned int key;
  unsigned int value;
  struct counter_list_s *next;
};
typedef struct counter_list_s counter_list_t;

/* Configuration options */
static const char *config_keys[] =
{
  "Interface",
  "IgnoreSource"
};
static int config_keys_num = STATIC_ARRAY_SIZE (config_keys);

#define PCAP_SNAPLEN 1460
/*  Network device that will be sniffed */
static char   *pcap_device = NULL;
/* HTTP traffic counter (bytes) */
static counter_t	http_traffic;
/* Request Methods linked list*/
static counter_list_t *rm_list;
/* Status Codes linked list*/
static counter_list_t *sc_list;
/* Mime Types linked list*/
static counter_list_t *mime_list;
/* Thread for the http_child_loop function*/
static pthread_t       listen_thread;
/* Thread control flag */
static int             listen_thread_init = 0;

/* Http traffic Mutex*/
static pthread_mutex_t http_traffic_mutex = PTHREAD_MUTEX_INITIALIZER;
/* Request Methods mutex*/
static pthread_mutex_t rm_mutex  = PTHREAD_MUTEX_INITIALIZER;
/* Status Codes mutex */
static pthread_mutex_t sc_mutex   = PTHREAD_MUTEX_INITIALIZER;
/* Mime Types mutex*/
static pthread_mutex_t mime_mutex   = PTHREAD_MUTEX_INITIALIZER;

/* Search inside a counter_list_t's type list the element with a specified key */
static counter_list_t *counter_list_search (counter_list_t **list, unsigned int key)
{
  counter_list_t *entry;
  for (entry = *list; entry != NULL; entry = entry->next)
	  if (entry->key == key)
		  break;
  return (entry);
}

/* Add the element (key,value) to the existing list (if list is NULL then create the list)*/
static counter_list_t *counter_list_create (counter_list_t **list,
		unsigned int key, unsigned int value)
{
  counter_list_t *entry;
  entry = (counter_list_t *) malloc (sizeof (counter_list_t));
  if (entry == NULL)
	  return (NULL);

  memset (entry, 0, sizeof (counter_list_t));
  entry->key = key;
  entry->value = value;

  if (*list == NULL)
  {
    *list = entry;
  }
  else
  {
    counter_list_t *last;

    last = *list;
    while (last->next != NULL)
	    last = last->next;

    last->next = entry;
  }
  return (entry);
}

/* Add 'increment' to the value of the element with a given key*/
static void counter_list_add (counter_list_t **list,
		unsigned int key, unsigned int increment)
{
  counter_list_t *entry;	
    /* Find the element with the specified key*/
    entry = counter_list_search (list, key);

  if (entry != NULL)
  {
    entry->value += increment;
  }
  else
  {
    counter_list_create (list, key, increment);
  }
}

/*
* Update a certain linked list depending on the http packet content and add the lenght of the packet to the HTTP traffic counter
*/
static void http_child_callback (const http_header_t *http)
{
  /* Check if it is a Http Request packet and, in case affirmative add the request method type to the Requests Method linked list */
  if (http->packet_type == PT_HEADER_REQUEST)
  {		
    pthread_mutex_lock (&rm_mutex);
    counter_list_add (&rm_list,  http->request_method,  1);
    pthread_mutex_unlock (&rm_mutex);
  }
  /* Check if it is Http Response packet and, in case affirmative add the status code type
    to the Status Codes linked list and the MimeType type too if present*/
  else if(http->packet_type == PT_HEADER_RESPONSE)
  {  
    pthread_mutex_lock (&sc_mutex);
    counter_list_add (&sc_list,  http->status_code,  1);
    pthread_mutex_unlock (&sc_mutex);
      
    if(http->has_mime_type == 1)
    {
      pthread_mutex_lock (&mime_mutex);
      counter_list_add (&mime_list,  http->mime_type,  1);
      pthread_mutex_unlock (&mime_mutex);
    }
	  
  }
	
  /* Add the lenght of the packet to the HTTP traffic counter*/
  if(http->packet_type != PT_OTHER)
  {
    pthread_mutex_lock (&http_traffic_mutex);
    http_traffic += http->length;
    pthread_mutex_unlock (&http_traffic_mutex);
  }
  
}

/*
* Start the sniffing procedure.
*/
static void *http_child_loop (void __attribute__((unused)) *dummy)
{
  pcap_t *pcap_obj;
  char    pcap_error[PCAP_ERRBUF_SIZE];
  struct  bpf_program fp;
  int status;

  /* Don't block any signals */   
  sigset_t sigmask;
  sigemptyset (&sigmask);
  pthread_sigmask (SIG_SETMASK, &sigmask, NULL);

  /* Open the device for capturing: passing `pcap_device == NULL' is okay and the same as passign "any" */
  DEBUG ("DBGHTTP http plugin: Creating PCAP object..");
  pcap_obj = pcap_open_live ((pcap_device != NULL) ? pcap_device : "any",
    PCAP_SNAPLEN,
    0 /* Not promiscuous */,
    interval_g,
    pcap_error);
  
  /* Check if the interface is valid */
  if (pcap_obj == NULL)
    {
      ERROR ("DBGHTTP http plugin: Opening interface `%s' "
	    "failed: %s",
	    (pcap_device != NULL) ? pcap_device : "any",
	    pcap_error);
    return (NULL);
    }

  memset (&fp, 0, sizeof (fp));
  /* Compile into a filter program that allows only packets on port 80 */
  if (pcap_compile (pcap_obj, &fp, "port 80", 1, 0) < 0)
  {
    ERROR ("DBGHTTP http plugin: pcap_compile failed");
    return (NULL);
  }
  /* Set the filter*/
  if (pcap_setfilter (pcap_obj, &fp) < 0)
  {
    ERROR ("DBGHTTP http plugin: pcap_setfilter failed");
    return (NULL);
  }

  DEBUG ("DBGHTTP http plugin: PCAP object created.");
  
  /* Initialize the utils_http pcap object and callback   */
  http_set_pcap_obj (pcap_obj);
  http_set_callback (http_child_callback);

  /* Call the callback function every time a packet is sniffed that meets the filter requirements (only packets on port 80) */
  status = pcap_loop (pcap_obj,
		  -1   		/* How many packets it should sniff for before returning (a negative value
				   means it should sniff until an error occurs  (loop forever) ) */,
		  handle_pcap 	/* Callback that will be called*/,
		  NULL 		/* Arguments to send to the callback (NULL is nothing) */);
  
  /* Check for errors*/
  if (status < 0)
    ERROR ("DBGHTTP http plugin: Listener thread is exiting "
      "abnormally: %s", pcap_geterr (pcap_obj));

  DEBUG ("DBGHTTP http plugin: Child is exiting.");
  
  /* Cleaning operations and closing section  */
  pcap_close (pcap_obj);
  listen_thread_init = 0;
  pthread_exit (NULL);
  
  return (NULL);
} /* static void http_child_loop (void) */

/*
* Dispatch the input value ( it could be a Request Method, a Status code or a Mime Type) to collectd which will pass
* them on to all registered write functions.
*/
static void submit_counter (const char *type, const char *type_instance,
		counter_t value)
{
	value_t values[1];
	value_list_t vl = VALUE_LIST_INIT;

	values[0].counter = value;

	vl.values = values;
	vl.values_len = 1;
	sstrncpy (vl.host, hostname_g, sizeof (vl.host));
	sstrncpy (vl.plugin, "http", sizeof (vl.plugin));
	sstrncpy (vl.type, type, sizeof (vl.type));
	sstrncpy (vl.type_instance, type_instance, sizeof (vl.type_instance));
	
	plugin_dispatch_values (&vl);
} /* void submit_counter */

/*
* Dispatch the http traffic counter (bytes) value to collectd which will pass them on to all registered write functions.
*/
static void submit_octets (counter_t htraffic)
{
  value_t value[1];
  value_list_t vl = VALUE_LIST_INIT;

  value->counter = htraffic;
  
  vl.values = value;
  vl.values_len = 1;
  sstrncpy (vl.host, hostname_g, sizeof (vl.host));
  sstrncpy (vl.plugin, "http", sizeof (vl.plugin));
  sstrncpy (vl.type, "http_octets", sizeof (vl.type));

  plugin_dispatch_values (&vl);
  
} /* void submit_counter */

/*
* Configuration callback that is called for each configuration item (each key-value-pair read from the config file).
*/
static int http_config (const char *key, const char *value)
{ 
  /* If selected, use the set interface*/
  if (strcasecmp (key, "Interface") == 0)
  {
  DEBUG ("DBGHTTP key=Interface");
    
  if (pcap_device != NULL)
      free (pcap_device);
  if ((pcap_device = strdup (value)) == NULL)
      return (1);
  }
  /* If selected, ignore the chosen source  */
  else if (strcasecmp (key, "IgnoreSource") == 0)
  {
    DEBUG ("DBGHTTP key=IgnoreSource");
    if (value != NULL)
      ignore_list_add_name (value);
  }
  else
  {
    ERROR("DBGHTTP Error: key has an invalid value");
	  return (-1);
  }
  
  DEBUG ("DBGHTTP http_config stops here");
  
  return (0);
} /*int http_config*/

/* 
* Initialization callback used to set the plugin up before using it. 
* It is called after the configuration file has been read and before 
* any calls to the read- and write-functions. 
*/
static int http_init (void)
{
  /* clean up an old thread */ 
  int status;
  pthread_mutex_lock (&http_traffic_mutex);
  http_traffic = 0;
  pthread_mutex_unlock (&http_traffic_mutex);
 
  if (listen_thread_init != 0)
	  return (-1);
  
  /*create a thread for the http_child_loop function */
  status = pthread_create (&listen_thread, NULL, http_child_loop,
		  (void *) 0);
  if (status != 0)
  {
    char errbuf[1024];
    ERROR ("DBGHTTP http plugin: pthread_create failed: %s",
		    sstrerror (errno, errbuf, sizeof (errbuf)));
    return (-1);
  }
  listen_thread_init = 1;
  
  return (0);
} /* int http_init */


/*
* Collect the actual data and pass the data values to collectd which will pass them on to all registered write functions. 
* It is called once per interval. The value types passed by it must be present in types.db. 
*/
static int http_read (void)
{	
  unsigned int keys[T_MAX];
  unsigned int values[T_MAX];
  int len;
  int i;
  counter_list_t *ptr;
  counter_t traf;
  traf=0;

  /* If http traffic has been generated submit the value of its size (in bytes) to collectd */
  pthread_mutex_lock (&http_traffic_mutex);
  traf= http_traffic;
  pthread_mutex_unlock (&http_traffic_mutex);
  if( traf != 0)
    submit_octets(traf);
  
  /* Submit the request methods values that are been generated to collectd */
  pthread_mutex_lock (&rm_mutex);
  for (ptr = rm_list, len = 0; (ptr != NULL) && (len < T_MAX); ptr = ptr->next, len++)
  {
    keys[len]   = ptr->key;
    values[len] = ptr->value;
  }
  pthread_mutex_unlock (&rm_mutex);
  for (i = 0; i < len; i++)
  {
    DEBUG ("DBGHTTP request method = %u; counter = %u;", keys[i], values[i]);
    submit_counter ("http_request_methods", rm_str (keys[i]), values[i]);
  }
  
  /* Submit the status codes values that are been generated to collectd */
  pthread_mutex_lock (&sc_mutex);
  for (ptr = sc_list, len = 0; (ptr != NULL) && (len < T_MAX); ptr = ptr->next, len++)
  {
    keys[len]   = ptr->key;
    values[len] = ptr->value;
  }
  pthread_mutex_unlock (&sc_mutex);
  for (i = 0; i < len; i++)
  {
    DEBUG ("DBGHTTP status_code = %u; counter = %u;", keys[i], values[i]);
    submit_counter ("http_status_codes", sc_str(keys[i]), values[i]);
  }

  /* Submit the mime types values that are been generated to collectd */
  pthread_mutex_lock (&mime_mutex);
  for (ptr = mime_list, len = 0;(ptr != NULL) && (len < T_MAX); ptr = ptr->next, len++)
  {
    keys[len]   = ptr->key;
    values[len] = ptr->value;
  }
  pthread_mutex_unlock (&mime_mutex);
  for (i = 0; i < len; i++)
  {
    DEBUG ("DBGHTTP mime_types = %u; counter = %u;", keys[i], values[i]);
    submit_counter ("http_mime_types", mime_str(keys[i]), values[i]);
  }
	  
  return (0);
} /* int http_read */

/* 
* Register the callbacks
*/
void module_register (void)
{
        DEBUG ("DBGHTTP*****************STARTING**HTTP**REGISTRATION****************************");
	plugin_register_config ("http", http_config, config_keys, config_keys_num);
	plugin_register_init ("http", http_init);
	plugin_register_read ("http", http_read);
	
} /* void module_register */

