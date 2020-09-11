# distribooze
<a href="https://imgbb.com/"><img src="https://i.ibb.co/vYQFp7m/distribooze-200x200.png" alt="distribooze-200x200" border="0"></a>

Packet length automatical distribution clustering and similarity plotting.

This tool takes a .pcap file as input, then it clusters similar flows automatically 
using DBSCAN. 
After clustering flows, it prints each flow's similarity to the average distribution
of its cluster.

You can use distribooze to se if there's a typical distribution in network flows from a specific pcap.
This could be useful to identify certain protocols that have a clear packet length distribution.

Different pcaps might require different settings of DBSCAN's hyperparameter
in order to get some meaningful results, read below for more info.

Bins used for the distributions all take 32 bytes each and go from 0 to 1504 bytes.

### Dependencies
The tool has the following dependency:
- **Numpy**
- **Sklearn**
- **Scapy 2.4.3** 

To install scapy you 
can run this command assuming you are in a 
conda environment

`conda install scapy numpy sklearn`

alternatively, if you're using plain pip, you can use

`pip3 install scapy numpy sklearn`

This is not recommended though, since it
 installs dependencies systemwide and could potentially break other projects.
 
 ### How it works
 
 The tool uses a slightly modified code taken from https://github.com/daniele-sartiano/doh 
 to extract distribution percentage vectors for each unidirectional
  flow in a given pcap. 
  
  After the flow extraction, a DBSCAN clustering is applied to the flows.
  
  If you want to find out more about DBSCAN please read https://scikit-learn.org/stable/modules/generated/sklearn.cluster.DBSCAN.html
  
  `np.linalg.norm()` is used to compute the similarity of each flow to its cluster's average distribution.

 
 ### Running the tool
 
 In order to run the tool you can use 
 
~~~
git clone https://github.com/gioleppe/distribooze
cd distribooze
python3 ./distribooze.py <pcap>
~~~

You can try it with
~~~
python3 ./distribooze.py pcaps/ssh_instagram.pcap
~~~

You'll get a result similar to

~~~
Cluster 0, average distribution:
61,4,2,5,5,1,0,1,0,0,0,0,1,0,0,1,0,0,0,0,2,0,10,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
('192.168.0.103:56382', 'to', '173.252.107.4:443') average distribution 55,11,0,0,22,0,0,0,11,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 similarity to cluster avg: 25.14
('173.252.107.4:443', 'to', '192.168.0.103:56382') average distribution 50,12,0,37,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 similarity to cluster avg: 36.69
('192.168.0.103:38816', 'to', '46.33.70.160:80') average distribution 92,0,0,0,7,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 similarity to cluster avg: 33.44
~~~

This shows the cluster number, its average distribution and its similarity to the average cluster 
packet length distribution expressed by computing an euclidean distance between distribution vectors.

If you want to manually set DBSCAN eps or min_samples hyperparameters, use the -e and -m flags, respectively.

Use flag -f to apply an optional BPF filter to the analyzed pcap

You can also use the -h flag to show an help message.

### Pcap Analysis 


Analyzing the pcaps in the /distribooze/pcaps folder we found out these things:

- bittorrent.pcap's flows have more or less the same distribution, there seems 
to be a large number of small packets exchanged by the clients belonging to the first bin.

- ssh_27122 and ssh_second_try pcaps, describing two distinct ssh connections on a nonstandard port with the same host, 
show that the flows are very similar, with more than 60% of client-side packets in the first bin
 (the one that goes from 0 to 32 bytes). This could be caused by the 
 single keystrokes being sent to the remote server via the ssh connection.
 To see these distributions please use `-f "tcp and port 27122"`.

-  the instagram pcap is difficult to analyse since there's a multitude of hosts in the pcap. 
That said there seems to be a certain regularity in the percentual distributions of the bins: either very small packages 
or medium sized ones belonging to the 23rd bin, the one that goes from 736 to 768 bytes.

- DoH has a very clear typical distributions and the majority of packets 
of its flows are to be found in the first bin.

- Netflix flows seem to have a clear bias towards medium sized packets. This could be caused by the nature of
the service (streaming a movie is much more network heavy than dns requests)