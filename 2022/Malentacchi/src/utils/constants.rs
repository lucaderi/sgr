pub const SYS_DESCR: &[u32; 9] = &[1,3,6,1,2,1,1,1,0]; //sysDesc.0
pub const SYS_NAME: &[u32; 9] = &[1,3,6,1,2,1,1,5,0]; //sysName.0
pub const SYS_UPTIME: &[u32; 9] = &[1,3,6,1,2,1,1,3,0]; //sysUpTime.0 -  time (in hundredths of a second) since the network daemon of the system was last re-initialized
pub const HR_SYSTEM_UPTIME: &[u32; 10] = &[1,3,6,1,2,1,25,1,1,0]; //hrSystemUptime.0 - measures the amount of time since the host was last initialized
pub const HR_SYSTEM_PROCESSES: &[u32; 10] = &[1,3,6,1,2,1,25,1,6,0]; //hrSystemProcesses.0 - number of processes
// Int wrapped
pub const LA_LOAD: &[u32;11] = &[1,3,6,1,4,1,2021,10,1,5,0]; // Bulk {...1,...2,...3} The average number of processes that are being executed by the CPU 
//pub const LA_LOAD_1: &[u32;11] = &[1,3,6,1,4,1,2021,10,1,5,1]; //laLoad.1 - The load average for the last minute.
//pub const LA_LOAD_2: &[u32;11] = &[1,3,6,1,4,1,2021,10,1,5,2]; //laLoad.2 - The load average for the last 5 minutes.
//pub const LA_LOAD_3: &[u32;11] = &[1,3,6,1,4,1,2021,10,1,5,3]; //laLoad.3- The load average for the last 15 minutes.

pub const SS_CPU_NUM_CPUS: &[u32;10] = &[1,3,6,1,4,1,2021,11,67,0]; //ssCpu.0 - The number of CPUs in the system.
pub const SS_CPU_RAW: &[u32; 9] = &[1,3,6,1,4,1,2021,11,49];  // Bulk {50.0,51.0,52.0}
//pub const SS_CPU_RAW_USER: &[u32; 10] = &[1,3,6,1,4,1,2021,11,50,0]; //The percentage of CPU time spent processing user-level code
//pub const SS_CPU_RAW_NICE: &[u32; 10] = &[1,3,6,1,4,1,2021,11,51,0]; //The percentage of CPU time spent processing low-priority code 
//pub const SS_CPU_RAW_SYSTEM: &[u32; 10] = &[1,3,6,1,4,1,2021,11,52,0]; //The percentage of CPU time spent processing sys-level code
//pub const SS_CPU_RAW_IDLE: &[u32; 10] = &[1,3,6,1,4,1,2021,11,53,0]; //Idle

pub const MEM_TOTAL_REAL: &[u32;10] = &[1,3,6,1,4,1,2021,4,5,0]; //memTotalReal.0 - Total RAM (KBytes)
pub const MEM_AVAIL_REAL: &[u32;10] = &[1,3,6,1,4,1,2021,4,6,0]; //memAvailReal.0 - Memory currently unused(KBytes)
pub const MEM_BUFFER: &[u32;10] = &[1,3,6,1,4,1,2021,4,14,0]; //memBuffer.0 - Memory currently buffered(KBytes)
pub const MEM_CACHED: &[u32;10] = &[1,3,6,1,4,1,2021,4,15,0]; //memCached.0 - Memory currently cached(KBytes)
//pub const MEM_TOTAL_FREE: &[u32;10] = &[1,3,6,1,4,1,2021,4,11,0]; //memTotalFree.0 - Total amount of memory free or available for use on this host. (KBytes)


//pub const SYS_CONTACT: [u32; 9]= &[1,3,6,1,2,1,1,4,0]; //sysName.0
//pub const HR_DEVICE_TABLE: &[u32; 9] = &[1,3,6,1,2,1,25,3,2]; //hrDeviceTable - set of services that this entity may potentially offer (sum)

//pub const HR_MEMORY_SIZE: &[u32; 10] = &[1,3,6,1,2,1,25,2,2,0]; //hrMemorySize.0 - RAM contained by the host. (KBytes)
pub const HR_SW_RUN_PERF_MEM: &[u32; 12] = &[1,3,6,1,2,1,25,5,1,1,2,0]; //hrSWRunPerfMem - The total amount of real system memory allocated to a process.