#!/usr/bin/env python
'''
	file		 webserver.py
	author		 Tranchida Giulio, No Matricola 241732\n
				 Si dichiara che il contenuto di questo file e',
 				 in ogni sua parte, opera originale dell'autore.\n\n

	version 1.0
	copyright (C) 2011 Tranchida Giulio under GNU Public License v3.
  
	This program is free software; you can redistribute it and/or
	modify it under the terms of the GNU General Public License
	as published by the Free Software Foundation; either version 2
	of the License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
	MA  02110-1301, USA.
'''

import string, cgi, time
import CGIHTTPServer, BaseHTTPServer
from os import curdir, sep, system
from BaseHTTPServer import HTTPServer
from CGIHTTPServer import CGIHTTPRequestHandler
from SocketServer import ThreadingMixIn

class ThreadingServer(ThreadingMixIn, HTTPServer):
    pass

def main():
	print 'Copyright (C) 2012  Giulio Tranchida\nThis program comes with ABSOLUTELY NO WARRANTY;'
	print 'This is free software, and you are welcome to redistribute it\nunder certain conditions;\n'
	try:
		server_address = ("", 8090)
		httpd = ThreadingServer(server_address, CGIHTTPRequestHandler)
		print 'started httpserver...'
		httpd.serve_forever()
	except KeyboardInterrupt:
		print ' received, shutting down server'

if __name__ == '__main__':
	main()

