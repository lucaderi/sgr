/*
 * webStuff.c
 *
 *  Created on: 06-giu-2009
 *      Author: Gianluca Medici 275788
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <sys/utsname.h>
#include <errno.h>
#include "webStuff.h"
#include "sysmacro.h"
#include "myhash.h"
#include "GeoVis.h"

#define BITFLAG_HTTP_IS_CACHEABLE           (1<<0)
#define BITFLAG_HTTP_NO_CACHE_CONTROL       (1<<1)
#define BITFLAG_HTTP_KEEP_OPEN              (1<<2)
#define BITFLAG_HTTP_MORE_FIELDS            (1<<4)

#define BITFLAG_HTML_NO_REFRESH             (1<<0)
#define BITFLAG_HTML_NO_STYLESHEET          (1<<1)
#define BITFLAG_HTML_NO_BODY                (1<<2)
#define BITFLAG_HTML_NO_HEADING             (1<<3)


#define BUFFER_TEMP_DIM		256

#define CONST_RFC1945_TIMESPEC              "%a, %d %b %Y %H:%M:%S GMT"

struct _HTTPstatus {
	int statusCode;
	char *reasonPhrase;
	char *longDescription;
};

/*
 This is just a small list of "Status Codes" and suggested
 "Reason Phrases" for HTTP responses, as stated in RFC 2068
 NOTE: the natural order is altered so "200 OK" results the
 first item in the table (index = 0)
 */
struct _HTTPstatus HTTPstatus[] = {
  { 200, "OK", NULL },
  { 100, "Continue", NULL },
  { 201, "Created", NULL },
  { 202, "Accepted", NULL },
  { 400, "Bad Request", "The specified request is invalid." },
  { 403, "Forbidden", "Server refused to fulfill your request." },
  { 404, "Not Found", "The server cannot find the requested page "
    "(page expired ?)." },

  { 408, "Request Time-out", "The request was timed-out." },
  { 414, "Request-URI Too Large", NULL },

  { 500, "Internal Server Error", NULL },
  { 503, "Service Unavailable", NULL },
  { 505, "HTTP Version not supported", "This server doesn't support the specified HTTP version." },
};



static char *getversion(void) {
	return (VERSION);
}

void closeSocket(int *sockId) {
	if (*sockId == FLAG_DUMMY_SOCKET)
		return;

	closesocket(*sockId);

	*sockId = FLAG_DUMMY_SOCKET;
}

//Taken from ntop source and modified a little
static int safe_snprintf(char* buf, size_t sizeofbuf,
		  char* format, ...) {
  va_list va_ap;
  int rc;

  va_start (va_ap, format);

  rc = vsnprintf(buf, sizeofbuf, format, va_ap);
  if(rc < 0)
    perror( "Buffer too short ");
  else if(rc >= sizeofbuf) {
   perror("Buffer too short (increase)");
    rc = 0 - rc;
  }

  va_end (va_ap);
  return(rc);
}

static void getOSinfo(char* temp, int size) {

	struct utsname mysys;
	IFERROR3(uname(&mysys), "No system uname information!", return );
	snprintf(temp, size, "%s %s %s", mysys.sysname, mysys.release,
				mysys.version);
	return ;

}


static void sendStringLen(int sock, char *theString, unsigned int len) {
	int bytesSent, rc, retries = 0;


	if (sock == FLAG_DUMMY_SOCKET)
		return;

	if (len == 0)
		return; /* Nothing to send */

	bytesSent = 0;

	while (len > 0) {
		RESEND: errno = 0;

		if (sock == FLAG_DUMMY_SOCKET)
			return;

		rc = send(sock, &theString[bytesSent], (size_t) len, 0);

		if ((errno != 0) || (rc < 0)) {
			if ((errno == EAGAIN /* Resource temporarily unavailable */)
					&& (retries < 3)) {
				len -= rc;
				bytesSent += rc;
				retries++;

				goto RESEND;
			}

			if (errno == EPIPE /* Broken pipe: the  client has disconnected */) {
				static int epipecount = 0;
				epipecount++;

				if (epipecount < 10)
					perror("EPIPE during sending of page to web client");
				else if (epipecount == 10)
					perror("EPIPE during sending of page to web client (skipping further warnings)");

			} else if (errno == EBADF /* Bad file descriptor: a
			 disconnected client is still sending */) {
				perror("EBADF during sending of page to web client");
			} else if (errno != 0) {
				perror( "Error during sending of page to web client");
			}

			if (errno != 0)
				perror("Failed text was unknown bytes");
			closeSocket(&sock);
			return;
		} else {
			len -= rc;
			bytesSent += rc;
		}
	}
}

static void sendString(int sock, char *theString) {
	sendStringLen(sock, theString, strlen(theString));
}

void sendHTTPHeader(int sock, int headerFlags) {
	int statusIdx, tim;
	char tmpStr[256], theDate[48], sysinfo[256];
	time_t t;
	struct tm *temp;

	statusIdx = (headerFlags >> 8) & 0xff;
	if ((statusIdx < 0) || (statusIdx > sizeof(HTTPstatus)
			/ sizeof(HTTPstatus[0]))) {
		statusIdx = 0;

	}
	snprintf(tmpStr, sizeof(tmpStr), "HTTP/1.0 %d %s\r\n",
			HTTPstatus[statusIdx].statusCode,
			HTTPstatus[statusIdx].reasonPhrase);
	sendString(sock, tmpStr);

	t = time(NULL);
	temp = localtime(&t);
	if (temp == NULL) {
		perror("localtime");
		exit(EXIT_FAILURE);
	}

	/* Use en standard for this per RFC*/
	strftime(theDate, sizeof(theDate) - 1, CONST_RFC1945_TIMESPEC, temp);
	theDate[sizeof(theDate) - 1] = '\0';
	snprintf(tmpStr, sizeof(tmpStr), "Date: %s\r\n", theDate);
	sendString(sock, tmpStr);

	if (headerFlags & BITFLAG_HTTP_IS_CACHEABLE) {
		sendString(sock,
				"Cache-Control: max-age=3600, must-revalidate, public\r\n");

		strftime(theDate, sizeof(theDate) - 1, CONST_RFC1945_TIMESPEC, temp);
		theDate[sizeof(theDate) - 1] = '\0';
		snprintf(tmpStr, sizeof(tmpStr), "Expires: %s\r\n", theDate);
		sendString(sock, tmpStr);
	} else if ((headerFlags & BITFLAG_HTTP_NO_CACHE_CONTROL) == 0) {
		sendString(sock, "Cache-Control: no-cache\r\n");
		sendString(sock, "Expires: 0\r\n");
	}

	if ((headerFlags & BITFLAG_HTTP_KEEP_OPEN) == 0) {
		sendString(sock, "Connection: close\n");
	}

	getOSinfo(sysinfo, sizeof(sysinfo));
	tim = snprintf(tmpStr, sizeof(tmpStr), "Server: GeoVisualizer/%s (%s)\r\n",
			getversion(), sysinfo);//getenv("MACHTYPE")

	sendString(sock, tmpStr);

	sendString(sock, "Content-Type: text/html\r\n\r\n");
	return;
}


void sendHead(int sock){

	char buffer [BUFFER_TEMP_DIM];
	int countryDim, i, j, cittDim;
	struct nationHash* itr=IpHastTable;
	struct cityHash* cityItr;

	sendString(sock, "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\n");
	sendString(sock, "<html xmlns=\"http://www.w3.org/1999/xhtml\">\n<head>\n<meta http-equiv=\"content-type\" content=\"text/html; charset=ISO-8859-1\" />\n");

	safe_snprintf(buffer, BUFFER_TEMP_DIM, "<title>GeoPacketVisualizer Version %s Result Page</title>\n", getversion());
	sendString(sock,buffer);

	sendString(sock, "<script type=\"text/javascript\" src=\"http://www.google.com/jsapi\"></script>\n<script type=\"text/javascript\">\n");
	sendString(sock, "\tgoogle.load('visualization', '1', {packages: ['geomap', 'table']});\n\n");
	sendString(sock, "function drawVisualization() {\n\tvar data = new google.visualization.DataTable();\n\tvar array= new Array();\n");

	sendString(sock, "\n\n\tvar emptyTable = new google.visualization.DataTable();\n\n\temptyTable.addRows(1);\n\temptyTable.addColumn('number', 'LATITUDE', 'Latitude');\n\temptyTable.addColumn('number', 'LONGITUDE', 'Longitude');\n\t");
	sendString(sock, "emptyTable.addColumn('number', 'IP Addrs', 'Value');\n\temptyTable.addColumn('string', 'City', 'Hover');\n");


	sendString(sock, "\n\temptyTable.setValue(0,0,0.00);\n\temptyTable.setValue(0,1,0.00);\n\temptyTable.setValue(0,2,0);\n\temptyTable.setValue(0,3,'None');\n\n");

	sendString(sock, "\tdata.addColumn('string', 'Code');\n\tdata.addColumn('number', 'IP Addrs');\n\tdata.addColumn('string', 'Country');");

	//sort the countries by the num packets received, bigger first
	sort_by_numPKT(&IpHastTable);

	//count the nation in the hash
	countryDim=countNations(&IpHastTable);

	safe_snprintf(buffer, BUFFER_TEMP_DIM, "\n\tdata.addRows(%d);\n", countryDim);

	sendString(sock,buffer);

	for(i=0; i< countryDim && itr; i++){

		safe_snprintf(buffer, BUFFER_TEMP_DIM, "\n\tdata.setValue(%d, 0, '%s');\n\t",i ,itr->countryId);

		sendString(sock,buffer);


		safe_snprintf(buffer, BUFFER_TEMP_DIM, "data.setValue(%d, 1, %d);\n\t", i,itr->numberPkt);

		sendString(sock,buffer);

		safe_snprintf(buffer, BUFFER_TEMP_DIM, "data.setValue(%d, 2,'%s');\n\n\t",i,itr->countryName);

		sendString(sock,buffer);

		cityItr=itr->listaCitta;
		cittDim=countCities(cityItr);

		safe_snprintf(buffer, BUFFER_TEMP_DIM, "var %sTable = new google.visualization.DataTable();\n\t%sTable.addColumn('number', 'LATITUDE', 'Latitude');\n\t",itr->countryId,itr->countryId);


		sendString(sock,buffer);


		safe_snprintf(buffer, BUFFER_TEMP_DIM, "%sTable.addColumn('number', 'LONGITUDE', 'Longitude');\n\t%sTable.addColumn('number', 'IP Addrs', 'Value');\n\t%sTable.addColumn('string', 'City', 'Hover');\n\t%sTable.addRows(%d);\n\t",itr->countryId,itr->countryId,itr->countryId,itr->countryId,cittDim);

		sendString(sock,buffer);


		safe_snprintf(buffer, BUFFER_TEMP_DIM, "\n\tarray['%s']=%sTable;\n\t", itr->countryId, itr->countryId);

		sendString(sock,buffer);


		for(j=0;j < cittDim && cityItr; j++){


			safe_snprintf(buffer, BUFFER_TEMP_DIM, "\n\n\t%sTable.setValue(%d,0,%f);\n\t%sTable.setValue(%d,1,%f);\n\t", itr->countryId, j, cityItr->latitude,itr->countryId, j, cityItr->longitude);

			sendString(sock,buffer);

			safe_snprintf(buffer, BUFFER_TEMP_DIM, "%sTable.setValue(%d,2,%d);\n\t%sTable.setValue(%d,3,'%s');\n",itr->countryId,j, cityItr->numberPkt ,itr->countryId, j, cityItr->cityName);

			sendString(sock,buffer);
			if(strcmp(cityItr->cityName, UNKNOWN_CITY)==0 && cittDim>1){
				safe_snprintf(buffer, BUFFER_TEMP_DIM, "\t%sTable.setTableProperty('unk', %d);\n" ,itr->countryId,j);
				sendString(sock, buffer);
			}

			cityItr=cityItr->hh.next;
		}

		itr=itr->hh.next;
	}

	sendString(sock, "\tvar geomap = new google.visualization.GeoMap(document.getElementById('GeoMappa'));\n");
	sendString(sock, "\n\tvar options={};\n\toptions['width'] = '640px';\n\toptions['height'] = '480px';\n\t");
	sendString(sock, "options['showLegend'] = true;\n\toptions['region'] = 'world';\n\toptions['dataMode'] = 'regions';\n");
	sendString(sock, "\n\tgeomap.draw(data, options);\n\tvar table = new google.visualization.Table(document.getElementById('table'));\n");
	sendString(sock, "\n\tvar viewTable= new google.visualization.DataView(data);\n\tviewTable.setColumns([2,1,0]);\n\ttable.draw(viewTable, null);\n");
	sendString(sock, "\n\tgoogle.visualization.events.addListener(geomap, 'regionClick', clickHandler);\n\tgoogle.visualization.events.addListener(geomap, 'zoomOut', zoomOut);\n\t");
	sendString(sock, "google.visualization.events.addListener(table, 'select', tableClick );\n\tvar table2 = new google.visualization.Table(document.getElementById('table2'));\n\n");


	sendString(sock, "function clickHandler(msg) {\n\talert('You selected the region ' +msg['region']);\n\toptions['region']= msg['region'];\n\toptions['showZoomOut']=true;\n\toptions['colors'] = [0x9999FF, 0x0000FF, 0x000066];\n\toptions['dataMode'] = 'markers';\n");

	sendString(sock, "\n\tif(array[msg['region']]!= undefined){\n\tvar view= new google.visualization.DataView(array[msg['region']]);\n\tview.setColumns([3, 2]);\n\t");
	sendString(sock, "var countryV=new google.visualization.DataView(array[msg['region']]);\n\tvar toHide=(array[msg['region']]).getTableProperty('unk');\n\tif(toHide!=null){\n\tcountryV.hideRows([toHide]);\n}\n\ttable2.draw(view,null);");

	sendString(sock, "\n\tgeomap.draw(countryV, options);\n\t}else{\n\tgeomap.draw(emptyTable, options);\n\tvar temp=document.getElementById('table2');\n\ttemp.removeChild(temp.firstChild);\n\t}\n}");

	sendString(sock, "\nfunction tableClick() {\n\tvar temp=table.getSelection();\n\tvar arrayAss=new Object()\n\tarrayAss['region']=data.getFormattedValue(temp[0].row, 0);\n\tclickHandler(arrayAss);\n}\n");

	sendString(sock, "function zoomOut(){\n\toptions['region']= 'world';\n\toptions['showZoomOut']=false;\n\toptions['colors'] = [0xE0FFD4, 0xA5EF63, 0x50AA00, 0x267114];\n\toptions['dataMode']='regions';\n\ttable.setSelection();\n\t");
	sendString(sock, "geomap.setSelection();\n\tgeomap.draw(data,options);\n\tvar temp=document.getElementById('table2');\n\ttemp.removeChild(temp.firstChild);\n}\n}\n");


	sendString(sock, "\n\tgoogle.setOnLoadCallback(drawVisualization);\n</script>");

	sendString(sock, "<style type=\"text/css\">\n<!--\n.style1 {\n\tfont-family: Arial, Helvetica, sans-serif;\n\tfont-size: large;\n\tfont-style: normal;	font-weight: bold;\n\tcolor: #666666;\n}\n");

	sendString(sock, ".style2 {\n\t	font-family: Arial, Helvetica, sans-serif;\n\tfont-size: medium;\n\tfont-style: normal;\n\tfont-weight: normal;\n\tcolor: #000000;\n}\n");

	sendString(sock, ".style3 {\n\tfont-family: Georgia, \"Times New Roman\", Times, serif;\n\tfont-size: small;\n\tfont-style: italic;\n\tfont-variant: normal;\n}\n");

	sendString(sock, ".style4 {\n\tfont-family: Georgia, \"Times New Roman\", Times, serif;\n\tfont-size: large;\n\tfont-style: normal;\n\tfont-weight: normal;\n}\n");

	sendString(sock, ".table1 {\n\tborder-collapse: collapse;\n\tborder-top-width: 2px;\n\tborder-right-width: 2px;\n\tborder-bottom-width: 2px;\n\tborder-left-width: 2px;\n\tborder-top-color: #666666;\n\tborder-right-color: #666666;\n\tborder-bottom-color: #666666;\n\tborder-left-color: #666666;\n}\n");

	sendString(sock, ".table2 {\n\tborder-color: #000000;\n\tborder-collapse: collapse;\n\tpadding-right: 3px;\n\tpadding-left: 3px;\n}\n");
	sendString(sock, ".table3 {\n\tborder-collapse: collapse;\n\theight: 50px;\n}\n-->\n</style>\n</head>\n\n");
	return;

}

void sendBody(int sock){
	char buffer[BUFFER_TEMP_DIM];
	sendString(sock, "<body style=\"font-family: Arial;border: 0 none;\">\n\t<table width=\"100%\" border=\"1\" cellpadding=\"0\" cellspacing=\"0\" class=\"table1\" >\n<tr class=\"table1\">\n\t<td align=\"center\" class=\"table1\" scope=\"col\">");

	safe_snprintf(buffer, BUFFER_TEMP_DIM, "<span class=\"style1\">GeoPacketVisualizer version %s</span>\n\t</td>\n\t</tr>\n</table>\n<p class=\"style2\">Click on a region of the map or on a row of the table to see the information collected on that region</p>\n", getversion());
	sendString(sock,buffer);

	sendString(sock, "<p class=\"style2\">&nbsp;</p>\n<table cellspacing=\"5\">\n\t<tr>\n\t<td colspan=\"2\"><div id=\"GeoMappa\" style=\"width: 700px; height: 480px;\"></div>\n</td>\n\t</tr>\n");
	sendString(sock, "<tr>\n\n\t<td height=\"50\" colspan=\"2\">&nbsp;</td>\n\t</tr>\n<tr>\n\t<td valign=\"top\"><div id=\"table\" style=\"width: 300px;\"></div>\n\t</td>\n\n\t");

	sendString(sock, "<td valign=\"top\"><table width=\"100%\" border=\"0\" cellpadding=\"0\" cellspacing=\"0\" class=\"table3\">\n\t<tr>\n\t<td></td>\n\t</tr>\n</table>\n\n<div id=\"table2\" style=\"width: 220px;\"> </div></td>\n</tr>\n</table>\n");

	sendString(sock, "<p class=\"style2\">&nbsp;</p>\n<p class=\"style4\">GeoPacketVisualizer report:</p>\n<table width=\"60%\" border=\"1\" cellpadding=\"0\" cellspacing=\"0\" class=\"table2\" >\n\t<tr><th width=\"80%\" class=\"table2\" ");
	sendString(sock, "scope=\"col\">Packets</th>\n\t<th width=\"20%\" align=\"right\" class=\"table2\" scope=\"col\"><div align=\"center\">Number</div></th>\n</tr>\n");

	safe_snprintf(buffer, BUFFER_TEMP_DIM, "<tr>\n\t<td width=\"80%\" class=\"table2\" scope=\"col\">Processed</td>\n\t<td width=\"20%\" align=\"right\" class=\"table2\" scope=\"col\">%d</td>\n</tr>\n", PKTprocessed);
	sendString(sock, buffer);

	safe_snprintf(buffer, BUFFER_TEMP_DIM, "<tr>\n\t<td width=\"80%\" class=\"table2\" scope=\"row\">With unimplemented protocol</td>\n\t<td width=\"20%\" align=\"right\" class=\"table2\" scope=\"row\">%d</td>\n</tr>\n", PKToutsideBuckett);
	sendString(sock, buffer);
	sendString(sock, "<tr>\n\t<th width=\"80%\" class=\"table2\" scope=\"row\">IP addresses</th>\n\t<th width=\"20%\" align=\"right\" class=\"table2\" scope=\"row\"><div align=\"center\">Number</div></th>\n</tr>\n");

	safe_snprintf(buffer, BUFFER_TEMP_DIM, "<tr>\n\t<td width=\"80%\" class=\"table2\" scope=\"row\">Total considered for analysis</td>\n\t<td width=\"20%\" align=\"right\" class=\"table2\" scope=\"row\">%d</td>\n</tr>\n", totalIpConsidered);
	sendString(sock, buffer);

	safe_snprintf(buffer, BUFFER_TEMP_DIM, "<tr>\n\t<td width=\"80%\" class=\"table2\" scope=\"row\">Of unknown countries</td>\n\t<td width=\"20%\" align=\"right\" class=\"table2\" scope=\"row\">%d</td>\n</tr>\n", PKTfromUnidentifiedCountry);
	sendString(sock, buffer);

	safe_snprintf(buffer, BUFFER_TEMP_DIM, "<tr>\n\t<td width=\"80%\" class=\"table2\" scope=\"row\">Of unknown cities</td>\n\t<td width=\"20%\" align=\"right\" class=\"table2\" scope=\"row\">%d</td>\n</tr>\n", PKTfromUnknowCity);
	sendString(sock, buffer);

	sendString(sock, "</table>\n\t<p>&nbsp;</p>\n\n<p class=\"style3\">GeoPacketVisualizer by Gianluca Medici 275788, courtesy of Google Visualization &copy;2009 Google and GeoLite City</p>\n<p class=\"style3\">Other software used: libpcap, UtHash</p>\n</body>\n</html>");
	return;
}

void sendChartPage(int sock){

	//send the header of the response http upon the socket
	sendHTTPHeader(sock, 0);

	//send the head of the html document upon the socket
	sendHead(sock);

	//send the body of the html document upon the socket
	sendBody(sock);
	return;
}
