/*
 * HTTPinteface.h
 *
 *  Created on: 8-giu-2009
 *      Author: Matteo Vigoni <mattevigo@gmail.com>
 */

#ifndef HTTPINTEFACE_H_
#define HTTPINTEFACE_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <stdint.h>
#include <microhttpd.h>

#define DEFAULT_HTTPD_PORT 19999
#define HTTP_PAGE_BUFFER_SIZE 300000
#define HTTP_INDEX "index.html"

/* Callback for the http request
 *
 * @param void*
 * @param MHD_Connection*
 * @param const char*
 * @param const char*
 * @param const char*
 * @param const char*
 * @param size_t*
 * @param void**
 *
 */
int httpd_request_callback(	void *cls,
								struct MHD_Connection *connection,
								const char *url,
								const char *method,
								const char *version,
								const char *upload_data,
								size_t *upload_data_size,
								void **con_cls
							);

/* Httpd initialization
 *
 * @param short the deamon port number
 *
 */
struct MHD_Daemon* httpd_init(short port);

#endif /* HTTPINTEFACE_H_ */
