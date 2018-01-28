+----------------------------------------------------------------------------+
|   	      SockClosePercPar - A tool to check unclosed socket FDs	     |
|                      Network Management Final Project			     |
|			   Student: Alessandra Fais                          |
+----------------------------------------------------------------------------+

SockClosePercPar is a Lua script that intercepts the 'socket' system calls 
made by active processes (one in particular, or all of them) and for each 
process it checks if the relative file descriptors are eventually closed.

+----------------------------------------------------------------------------+
|				 Requirements				     |
+----------------------------------------------------------------------------+

The following tools are required in order to use the script:
- Sysdig
- Lua 5.2

+----------------------------------------------------------------------------+
|			       Using the script 	                     |
+----------------------------------------------------------------------------+

Open a terminal session and navigate to the script's directory. The script can 
be run with the following command:

			sysdig -c SockClosePercPar.lua param

The 'param' parameter can be either 'all' or the desired process' name.
NOTE: In order to run the script, you must have superuser privilegies.

+----------------------------------------------------------------------------+
|				   Results				     |
+----------------------------------------------------------------------------+

SockClosePercPar outputs how many system calls ('socket' or 'close') were made
by the process since the script's execution and during the last update 
interval, as well as the number of file descriptors closed after a 'socket' 
syscall. Both 'socket' and 'close' are classified by type (tcp, udp, other): 
every output column contains the whole number of 'socket' or 'close' and their 
subdivision between families. The script outputs new data every 7 seconds.
