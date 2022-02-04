secRep README

author: Guido Ricci

Required software
--------------------
sysdig: http://www.sysdig.org/install/

Install
--------------------
Extract the content of the folder sr to /usr/share/sysdig/chisels or
to ~/.chisels, if only you want to be able to use the chisel
Practical stuff:
    tar -xf secRep.tar.gz
    cd sr
    sudo cp srOut.lua secRep.lua srLogic.lua /usr/share/sysdig/chisels
    
Usage
--------------------
sysdig -c secRep "[p] [l]"
where
    p is a PID or a no-path executable name,
    l is a string, if it's value is y or yes or s or si then every relevant event is sent to the log file
NOTE: you might need superuser permissions
Examples:
    sysdig -c secRep cat
    sysdig -c secRep nc
    sysdig -c secRep 5987
    
Output files
--------------------
Report file:
	~/scRep[hh]:[mm]:[ss]_[month].[day].[year].txt containing the final output of the script
Log file
	~/scRepLog[hh]:[mm]:[ss]_[month].[day].[year].txt containing every relevant event

Author Contact
--------------------
guidoricci@live.com
