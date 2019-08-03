import sys
from ndpi_util_struct import *

#example: -i <interface>

#------------------- rest function & structure ------------------

class pthread_t(Structure):
    pass

# struct associated to a workflow for a thread
class reader_thread(Structure):
    _fields_ = [
        ("workflow", POINTER(ndpi_workflow)),
        ("pthread", pthread_t),
        ("last_idle_scan_time", c_uint64),
        ("idle_scan_idx", c_uint32),
        ("num_idle_flows", c_uint32),
        ("idle_flows", POINTER(ndpi_flow_info * ndpi.ndpi_wrap_idle_scan_budget()))
    ]


ndpi.ndpi_init_detection_module.restype = c_void_p
ndpi.execute.restype = POINTER(reader_thread)

#----------------------------------------------------------------

print('Number of arguments:', len(sys.argv), 'arguments.')
print('Argument List:', str(sys.argv))

length = len(sys.argv)

#inizialize data to use them
arr = (c_char_p * length)()
arr[0] = './ndpiReader'.encode('utf-8')
for i in range(1, length):
    arr[i] = sys.argv[i].encode('utf-8')

#check ndpi version
if ndpi.ndpi_get_api_version() != ndpi.ndpi_wrap_get_api_version():
    print("nDPI Library version mismatch: please make sure this code and the nDPI library are in sync\n")
    sys.exit(-1)

#timestamp
startup_time = timeval(0, 0)
ndpi.gettimeofday(byref(startup_time), None)

#create a data structure of ndpi
ndpi_info_mod = ndpi_detection_module_struct.from_address(ndpi.ndpi_init_detection_module())
if ndpi_info_mod == None:
    sys.exit(-1)
ndpi_thread_info = ndpi.execute(length, arr, byref(ndpi_info_mod), startup_time)

#print example
stat = ndpi_thread_info[0].workflow.contents
print("tcp count is " + str(stat.stats.tcp_count))


#free
ndpi.free_detection_module_struct(byref(ndpi_info_mod))


