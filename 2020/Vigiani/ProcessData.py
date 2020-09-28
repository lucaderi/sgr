def process(values):
    processData = {}

    cpu = values["hrProcessorLoad"].split("%")

    cpu_usage = int(cpu[1]) +   \
                int(cpu[2]) +   \
                int(cpu[3]) +   \
                int(cpu[4]) +   \
                int(cpu[5]) +   \
                int(cpu[6]) +   \
                int(cpu[7]) +   \
                int(cpu[8])

    cpu_usage = (cpu_usage * 100) / 800


    ram_usage = int(values["hrStorageUsed"].split("%")[1]) * int(values["hrStorageAllocationUnits"].split("%")[1])
    ram_usage = ram_usage / (1024 * 1024 * 1024)

    processData["cpuUsage"] = cpu_usage
    processData["ramUsage"] = ram_usage

    return processData