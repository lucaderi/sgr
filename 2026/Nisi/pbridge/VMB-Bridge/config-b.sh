# mount shared folder vmware 
sudo vmhgfs-fuse .host:/ /mnt/hgfs -o allow_other 
# remove IPs (to test if it works anyway as it should since the bridge should work only on L2 Ethernet) 
sudo ip addr flush dev ens160 
sudo ip addr flush dev ens192 
# activate the network adapters 
sudo ip link set dev ens160 up 
sudo ip link set dev ens192 up 
# show results
sudo ifconfig