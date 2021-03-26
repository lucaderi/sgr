Edoardo Ermini (582198), Riccardo Luzi (579752), Luca G. Pinta (579458)

---

# Speedtest Analysis with wireshark (Group 1)
Since make an analysis into a local machine could lead to a bad evaluation of results due to other applications' network traffic noise, we made the analysis into a isolated environment like a virtual machine.
For a further accuracy in the capture we set the `tcp` filter option in wireshark and after we run the speedtest. 

## Fast.com result
![fastcom output](https://raw.githubusercontent.com/edoermini/network-management-exercises/main/wireshark-speedtest-analysis/fast_output.png)
From this speedtest we focused into 2 informations: the download speed (34 Mbps) and the upload speed (8.1 Mbps).

## Wireshark analysis
During the speedtest we captured all traffic outgoing and ingoing from and to our machine including the one created by fast.com and it can be found in [this pcap file](https://github.com/edoermini/network-management-exercises/blob/main/wireshark-speedtest-analysis/fastcom_capture.pcap).

### Conversations:
We report below the conversations extracted from wireshark capture of fast.com speedtest:

|Address A     |Address B      |Packets|Bytes   |Packets A → B|Bytes A → B|Packets B → A|Bytes B → A|Rel Start         |Duration          |Bits/s A → B      |Bits/s B → A      |
|--------------|---------------|-------|--------|-------------|-----------|-------------|-----------|------------------|------------------|------------------|------------------|
|2.23.20.150   |192.168.1.26   |99     |68235   |50           |62930      |49           |5305       |2.956970656       |20.871016903      |24121.48877746515 |2033.4418872469828|
|18.203.130.218|192.168.1.26   |199    |237956  |90           |16098      |109          |221858     |3.231622321       |50.044572927      |2573.385933133193 |35465.663831100996|
|23.246.50.154 |192.168.1.26   |3455   |7125883 |1773         |6270269    |1682         |855614     |4.555988725       |47.449749585      |1057163.6823950163|144256.0194704134 |
|23.246.51.156 |192.168.1.26   |6935   |15236960|3743         |13443084   |3192         |1793876    |4.048611567       |48.213388635      |2230597.6626983876|297656.07451167697|
|45.57.72.140  |192.168.1.26   |11830  |17815651|5780         |2471979    |6050         |15343672   |3.8753101770000002|49.786431338      |397213.2862012525 |2465518.6704717735|
|45.57.73.144  |192.168.1.26   |10827  |16367951|5415         |3349176    |5412         |13018775   |4.018383453       |49.667346519      |539457.206350863  |2096955.188861516 |
|52.18.232.179 |192.168.1.26   |27     |4584    |12           |2553       |15           |2031       |3.310762936       |49.588253263999995|411.87173686610544|327.6582442518841 |
|93.184.220.29 |192.168.1.26   |73     |12422   |30           |6784       |43           |5638       |1.40681827        |51.89994504       |1045.7043828884948|869.0567969819184 |
|151.99.109.9  |192.168.1.26   |14793  |24334779|7546         |8650752    |7247         |15684027   |3.610799148       |50.076952327      |1381993.3678888476|2505588.1032989523|
|192.168.1.1   |192.168.1.26   |568    |62131   |286          |32686      |282          |29445      |2.9564842540000003|46.32322729       |5644.8571331827   |5085.1379271420365|
|192.168.1.1   |224.0.0.1      |1      |60      |1            |60         |0            |0          |22.619512382      |0                 |0                 |0                 |
|192.168.1.9   |255.255.255.255|2      |376     |2            |376        |0            |0          |13.230641892      |30.003352839      |100.25546198590301|0                 |
|192.168.1.9   |192.168.1.255  |2      |376     |2            |376        |0            |0          |13.230796732      |30.003382556      |100.25536268738033|0                 |
|192.168.1.26  |224.0.0.251    |1      |46      |1            |46         |0            |0          |30.009647119      |0                 |0                 |0                 |

From this table we see that our machine exchange an high number of packets with these 5 endpoints: 23.246.50.154, 23.246.51.156, 45.57.72.140, 45.57.73.144, 151.99.109.9.
We suppose that fast.com opens 5 connections with these machines on the internet for the speedtest, in particular, analyzing the number of bytes exchanged in both directions between the local machine and these remote machines, the first two hosts (23.246.50.154, 23.246.51.156) are used to test the download speed, and the other three hosts (45.57.72.140, 45.57.73.144, 151.99.109.9) are used to test the upload speed.
Making a whois request on the address 52.18.232.179 (seventh row first column) the result is that it belongs to amazon and since netflix relies on AWS for its services we suppose also that the 5 hosts used for the speedtest were sent by the host with ip 52.18.232.179.

### I/O Graph analysis
To analyze the speedtest we opened the I/O Graph window from statistics menu and we added two filters: one for filtering the download traffic `tcp.srcport == 443` (the pink curve) and one for filtering the upload traffic `tcp.dstport == 443` (the blue curve).
![wireshark_downupl](https://raw.githubusercontent.com/edoermini/network-management-exercises/main/wireshark-speedtest-analysis/fastcom_capture_iograph.png)

## Results
From the wireshark analysis the curves describes with a good accuracy what fast.com says, in fact the upload curve in the chart oscillates around 35 Mbsp and the download around 9 Mbps.
In conclusion the wireshark estimation is very close to the fast.com speedtest result. 
