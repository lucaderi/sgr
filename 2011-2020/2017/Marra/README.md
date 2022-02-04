# Simple Network Discovery

This is a simple network discovery tool that send ARP packets to all devices connected to the network.

```
usage: simple-network-discovery -i <INTERFACE_NAME> -s <SUBNET>

    -i          network interface to be used
    -s          subnet to be "scanned"

OPTIONAL:
    -h                   print usage
    -t <TIMEOUT>         time (in seconds) between each ARP request (min. 0, max. 256)
    -w <WAITING>         time (in seconds) before read all ARP replies (min. 0, max. 256). Default is 3
```


