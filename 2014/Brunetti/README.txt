ProcTraffic version 2.0 07/17/2014
Author:Lorenzo Brunetti                
                          PROCTRAFFIC
------------------------------------------------------------------------
The chisel analyizes the traffic of each process and save it in a log 
file every n seconds where n is a parameter that you have to specify.
Log's name is setted up using this syntax:
	log_day.month.year_hour:minutes
The chisel monitors these system calls:
	for in data it considers recv ,recvmsg, rcvfrom system calls
	for out data it considers send and sendto system calls

---------------------REQUIREMENTS---------------------------------------
The Script needs:
-Sysdig (obvious..)
-Be sure that you can obtain superuser privileges
-This script is tested on Unix kernel only (no guarantee of its result 
 on Windows kernel)
---------------------HOWTO----------------------------------------------
Navigate into folder that contains PT2.lua.
In order to use the chisel you must specify a parameter (integer) that represents 
the interval of the updates.
Example of command line:
  sysdig -c PT2.lua 3
(In this way updates are written every 3 seconds)

---------------------RESULTS--------------------------------------------
The chisel shows in and out traffic with 3 columns
- in/out :the total amount of in/out traffic
- LastIn/LastOut: the last amount in last interval
- DiffLast: the comparision between the last two revelations

In the first line it shows the process name and PID.
The same syntax is used to write log files.
Each log file is named with date and time of script's starts