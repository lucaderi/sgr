#WARNING!! This container send cpu over 100% usage, alloc 4G of memory and span many IO operation, for 10 seconds ;)..
#if some parameter are too expensive feel free to decrease or increase them
docker run --name=stress_container --rm -d progrium/stress --io 10 --vm 1 --vm-bytes 4G --vm-keep --timeout 10s


