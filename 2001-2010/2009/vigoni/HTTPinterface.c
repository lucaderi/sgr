/*
 * HTTPinterface.c
 *
 *  Created on: 9-giu-2009
 *      Author: Matteo Vigoni <mattevigo@gmail.com>
 */


#include "capture.h"
#include <stdio.h>
#include <fcntl.h>
#include <stdarg.h>

#include "HTTPinterface.h"

#ifndef HTTPD
#define HTTPD
#endif

/*** ************************************************************************************* ***/

/* Callback for the http request
 *
 * @param void*				n/a
 * @param MHD_Connection*	n/a
 * @param const char*		url of the request
 * @param const char*		n/a
 * @param const char*		n/a
 * @param const char*		n/a
 * @param size_t*			n/a
 * @param void**			n/a
 *
 */
int httpd_request_callback(	void *cls,
		struct MHD_Connection *connection,
		const char *url,
		const char *method,
		const char *version,
		const char *upload_data,
		size_t *upload_data_size,
		void **con_cls	)
{
	struct MHD_Response *res;
	u_int status = 200;
	int state;
	u_int js_len;
	char *js = "Sorry, content not available!";

	/*position += snprintf(buffer+position, HTTP_PAGE_BUFFER_SIZE - position, url);*/

 	if(strcmp(url, "/flows") == 0)
	{
		js = get_json_flows();
		js_len = strlen(js);

		printf("httpd_request_callback: json retrived for flows dump (size=%d)\n", js_len);
	}
	else if(strcmp(url, "/counters") == 0)
	{
		js = calloc(1000, sizeof(char));
		capture_get_json_counters(js);

		js_len = strlen(js);

		printf("httpd_request_callback: json retrived for count dump (size=%d)\n", js_len);
	}
	else
	{
	  js_len = strlen(js);
	}

	res = MHD_create_response_from_data(js_len, js, MHD_YES, MHD_YES);
	MHD_add_response_header(res, "Content-Type", "text/javascript");

	state = MHD_queue_response(connection, status, res);
	printf("httpd_request_callback: response queued (state=%d)\n", state);
	MHD_destroy_response(res);

	return state;
}

/* Httpd initialization
 *
 * @param short the deamon port number
 *
 */
struct MHD_Daemon* httpd_init(short port)
{
	struct MHD_Daemon *http_daemon = NULL;

	http_daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, port, NULL, NULL, &httpd_request_callback, NULL, MHD_OPTION_END);

	if(http_daemon)
		printf(">>>> http interface started on port %d\n", port);
	else
		printf("WAR> cannot start http interface on port %d\n", port);

	return http_daemon;
}

/*** ************************************************************************************* ***/
