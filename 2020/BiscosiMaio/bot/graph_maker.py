
import rrdtool
import os.path


def create_dir_graph(
        hostname, graph_type):
    """ Creates the necessary repository and the requested graph

    :param hostname: ip address of the snmp agent
    :param graph_type: resource requested, 0 for CPU, 1 for RAM, 2 for Disk, 3 for InOctets, 4 for OutOctets
    :return: Boolean: the outcome of the creation of the graph
    """
    # Creating the directories
    if not os.path.isdir("./graph"):
        try:
            os.mkdir("./graph")
            os.mkdir("./graph/" + hostname)
        except Exception:
            print("ERROR: Problem while creating the directory")
            return False

    else:
        if not os.path.isdir("./graph/" + hostname):
            try:
                os.mkdir("./graph/" + hostname)
            except Exception:
                print("ERROR: Problem while creating the directory")
                return False

    # Creating the image
    if graph_type == 0:
        result = create_cpu_graph(hostname)

    elif graph_type == 1:
        result = create_ram_graph(hostname)

    elif graph_type == 2:
        result = create_disk_graph(hostname)

    elif graph_type == 3:
        result = create_in_graph(hostname)

    elif graph_type == 4:
        result = create_out_graph(hostname)

    return result


def create_cpu_graph(
        hostname):
    """ Create a CPU graph using hostname's info

    :param hostname: ip address of the snmp agent
    :return: Boolean: the outcome of the creation of the graph
    """

    try:
        rrdtool.graph(
            "./graph/" + hostname + "/cpuGraph.png",
            "--width", "1600",
            "--height", "400",
            "--start", "now-24hour",
            "--end", "now",
            "--lower-limit", "0",
            "--upper-limit", "100",
            "--title", "CPU Usage",
            "--vertical-label", "%",
            "DEF:cpu=./RRDlog/" + hostname + "/cpu.rrd:cpu:AVERAGE",
            "DEF:pred=./RRDlog/" + hostname + "/cpu.rrd:cpu:HWPREDICT",
            "DEF:dev=./RRDlog/" + hostname + "/cpu.rrd:cpu:DEVPREDICT",
            "DEF:fail=./RRDlog/" + hostname + "/cpu.rrd:cpu:FAILURES",
            "TICK:fail#ffffa0:1.0:  Failures Average",
            "CDEF:upper=pred,dev,3,*,+",
            "CDEF:lower=pred,dev,3,*,-",
            "CDEF:scaledupper=upper,0,GT,upper,0,IF",
            "CDEF:scaledlower=lower,0,GT,lower,0,IF",
            "VDEF:prccpu=cpu,95,PERCENTNAN",
            "VDEF:msmax=cpu,MAXIMUM",
            "VDEF:msavg=cpu,AVERAGE",
            "VDEF:msmin=cpu,MINIMUM",
            "LINE2:prccpu#00ff8c:95th_Percentile",
            "LINE2:cpu#0000ff:CPU Usage",
            "LINE:scaledupper#ff4d00:Upper Bound Average",
            "LINE:scaledlower#ff4d00:Lower Bound Average",
            r"GPRINT:msmax:Max\: %6.1lf %%",
            r"GPRINT:msavg:Avg\: %6.1lf %%",
            r"GPRINT:msmin:Min\: %6.1lf %%",
        )

        return True
    except Exception:
        print("ERROR: Problem while creating the CPU Graph")
        return False


def create_ram_graph(
        hostname):
    """ Create a RAM graph using hostname's info

    :param hostname: ip address of the snmp agent
    :return: Boolean: the outcome of the creation of the graph
    """
    try:
        rrdtool.graph(
            "./graph/" + hostname + "/ramGraph.png",
            "--width", "1600",
            "--height", "400",
            "--start", "now-24hour",
            "--end", "now",
            "--lower-limit", "0",
            "--upper-limit", "100",
            "--title", "Ram Usage",
            "--vertical-label", "%",
            "DEF:ram=./RRDlog/" + hostname + "/ram.rrd:ram:AVERAGE",
            "DEF:pred=./RRDlog/" + hostname + "/ram.rrd:ram:HWPREDICT",
            "DEF:dev=./RRDlog/" + hostname + "/ram.rrd:ram:DEVPREDICT",
            "DEF:fail=./RRDlog/" + hostname + "/ram.rrd:ram:FAILURES",
            "TICK:fail#ffffa0:1.0:  Failures Average",
            "CDEF:upper=pred,dev,3,*,+",
            "CDEF:lower=pred,dev,3,*,-",
            "CDEF:scaledupper=upper,0,GT,upper,0,IF",
            "CDEF:scaledlower=lower,0,GT,lower,0,IF",
            "VDEF:prcram=ram,95,PERCENTNAN",
            "VDEF:msmax=ram,MAXIMUM",
            "VDEF:msavg=ram,AVERAGE",
            "VDEF:msmin=ram,MINIMUM",
            "LINE2:prcram#00ff8c:95th_Percentile",
            "LINE:scaledupper#ff4d00:Upper Bound Average",
            "LINE:scaledlower#ff4d00:Lower Bound Average",
            "LINE2:ram#0000ff:RAM Usage",
            r"GPRINT:msmax:Max\: %6.1lf %%",
            r"GPRINT:msavg:Avg\: %6.1lf %%",
            r"GPRINT:msmin:Min\: %6.1lf %%",
        )

        return True
    except Exception:
        print("ERROR: Problem while creating the RAM Graph")
        return False


def create_disk_graph(
        hostname):
    """ Create a Disk graph using hostname's info

    :param hostname: ip address of the snmp agent
    :return: Boolean: the outcome of the creation of the graph
    """
    try:
        rrdtool.graph(
            "./graph/" + hostname + "/diskGraph.png",
            "--width", "1600",
            "--height", "400",
            "--start", "now-24hour",
            "--end", "now",
            "--lower-limit", "0",
            "--upper-limit", "100",
            "--title", "Disk Usage",
            "--vertical-label", "%",
            "DEF:disk=./RRDlog/" + hostname + "/disk.rrd:disk:AVERAGE",
            "DEF:pred=./RRDlog/" + hostname + "/disk.rrd:disk:HWPREDICT",
            "DEF:dev=./RRDlog/" + hostname + "/disk.rrd:disk:DEVPREDICT",
            "DEF:fail=./RRDlog/" + hostname + "/disk.rrd:disk:FAILURES",
            "TICK:fail#ffffa0:1.0:  Failures Average bits out",
            "CDEF:upper=pred,dev,3,*,+",
            "CDEF:lower=pred,dev,3,*,-",
            "CDEF:scaledupper=upper,0,GT,upper,0,IF",
            "CDEF:scaledlower=lower,0,GT,lower,0,IF",
            "VDEF:prcdisk=disk,95,PERCENTNAN",
            "VDEF:msmax=disk,MAXIMUM",
            "VDEF:msavg=disk,AVERAGE",
            "VDEF:msmin=disk,MINIMUM",
            "LINE2:prcdisk#00ff8c:95th_Percentile",
            "LINE:scaledupper#ff4d00:Upper Bound Average",
            "LINE:scaledlower#ff4d00:Lower Bound Average",
            "LINE2:disk#0000ff:Disk Usage",
            r"GPRINT:msmax:Max\: %6.1lf %%",
            r"GPRINT:msavg:Avg\: %6.1lf %%",
            r"GPRINT:msmin:Min\: %6.1lf %%",
        )

        return True
    except Exception:
        print("ERROR: Problem while creating the Disk Graph")
        return False


def create_in_graph(
        hostname):
    """ Create a Disk graph using hostname's info

    :param hostname: ip address of the snmp agent
    :return: Boolean: the outcome of the creation of the graph
    """
    try:
        rrdtool.graph(
            "./graph/" + hostname + "/inOctetGraph.png",
            "--width", "1600",
            "--height", "400",
            "--start", "now-24hour",
            "--end", "now",
            "--lower-limit", "0",
            "--title", "Download",
            "--vertical-label", "bits per second",
            "DEF:inOctet=./RRDlog/" + hostname + "/inOctet.rrd:inOctet:AVERAGE",
            "DEF:pred=./RRDlog/" + hostname + "/inOctet.rrd:inOctet:HWPREDICT",
            "DEF:dev=./RRDlog/" + hostname + "/inOctet.rrd:inOctet:DEVPREDICT",
            "DEF:fail=./RRDlog/" + hostname + "/inOctet.rrd:inOctet:FAILURES",
            "TICK:fail#ffffa0:1.0:  Failures Average bits out",
            "CDEF:upper=pred,dev,2,*,+",
            "CDEF:lower=pred,dev,2,*,-",
            "CDEF:bytes=inOctet,8,*",
            "CDEF:scaledupper=upper,8,*",
            "CDEF:scaledlower=lower,8,*",
            "CDEF:resultupper=scaledupper,0,GT,scaledupper,0,IF",
            "CDEF:resultlower=scaledlower,0,GT,scaledlower,0,IF",
            "VDEF:prcinoct=bytes,95,PERCENTNAN",
            "VDEF:msmax=bytes,MAXIMUM",
            "VDEF:msavg=bytes,AVERAGE",
            "VDEF:msmin=bytes,MINIMUM",
            "LINE2:prcinoct#00ff8c:95th_Percentile",
            "LINE:resultupper#ff4d00:Upper Bound Average",
            "LINE:resultlower#ff4d00:Lower Bound Average",
            "LINE2:bytes#0000ff:bits downloaded",
            r"GPRINT:msmax:Max\: %6.0lf bits",
            r"GPRINT:msavg:Avg\: %6.0lf bits",
            r"GPRINT:msmin:Min\: %6.0lf bits",
        )

        return True
    except Exception:
        print("ERROR: Problem while creating the Download Graph")
        return False


def create_out_graph(
        hostname):
    """ Create a Disk graph using hostname's info

    :param hostname: ip address of the snmp agent
    :return: Boolean: the outcome of the creation of the graph
    """
    try:
        rrdtool.graph(
            "./graph/" + hostname + "/outOctetGraph.png",
            "--width", "1600",
            "--height", "400",
            "--start", "now-24hour",
            "--end", "now",
            "--title", "Upload",
            "--vertical-label", "bits per second",
            "DEF:outOctet=./RRDlog/" + hostname + "/outOctet.rrd:outOctet:AVERAGE",
            "DEF:pred=./RRDlog/" + hostname + "/outOctet.rrd:outOctet:HWPREDICT",
            "DEF:dev=./RRDlog/" + hostname + "/outOctet.rrd:outOctet:DEVPREDICT",
            "DEF:fail=./RRDlog/" + hostname + "/outOctet.rrd:outOctet:FAILURES",
            "TICK:fail#ffffa0:1.0:  Failures Average bits out",
            "CDEF:upper=pred,dev,2,*,+",
            "CDEF:lower=pred,dev,2,*,-",
            "CDEF:bytes=outOctet,8,*",
            "CDEF:scaledupper=upper,8,*",
            "CDEF:scaledlower=lower,8,*",
            "CDEF:resultupper=scaledupper,0,GT,scaledupper,0,IF",
            "CDEF:resultlower=scaledlower,0,GT,scaledlower,0,IF",
            "VDEF:prcoutoct=bytes,95,PERCENTNAN",
            "VDEF:msmax=bytes,MAXIMUM",
            "VDEF:msavg=bytes,AVERAGE",
            "VDEF:msmin=bytes,MINIMUM",
            "LINE2:prcoutoct#00ff8c:95th_Percentile",
            "LINE:resultupper#ff4d00:Upper Bound Average",
            "LINE:resultlower#ff4d00:Lower Bound Average",
            "LINE2:bytes#0000ff:bits uploaded",
            r"GPRINT:msmax:Max\: %6.0lf bits",
            r"GPRINT:msavg:Avg\: %6.0lf bits",
            r"GPRINT:msmin:Min\: %6.0lf bits",
        )

        return True
    except Exception:
        print("ERROR: Problem while creating the upload Graph")
        return False
