# mount shared folder vmware 
sudo vmhgfs-fuse .host:/ /mnt/hgfs -o allow_other 
# remove others IPs to set my custom one 
sudo ip addr flush dev ens160
# set my custom IP 
sudo ip addr add 192.168.42.2/24 dev ens160 
# activate the network adapter 
sudo ip link set ens160 up 
# show results
sudo ifconfig