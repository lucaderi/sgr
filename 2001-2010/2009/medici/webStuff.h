/*
 * webStuff.h
 *
 *  Created on: 06-giu-2009
 *      Author: Gianluca Medici 275788
 */

#ifndef WEBSTUFF_H_
#define WEBSTUFF_H_
#define closesocket(a) close(a)
void sendHTTPHeader(int sock, int headerFlags) ;

void sendHead(int sock);
void sendBody(int sock);
void sendChartPage(int sock);
void closeSocket(int *sockId);

#endif /* WEBSTUFF_H_ */
