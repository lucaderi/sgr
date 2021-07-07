# DoSTect
DoSTect is high intensity SYN flooding attacks detection tool that operates in two modes : **online** (in which it observes the incoming and outgoing packets in real time) and **offline** (in which it observes a **pcap** file).

In both modes the logic behind the detection is based on a type of a statistical method called **CUSUM** (Cumulative Sum).
The CUSUM algorithm belongs to the family of change point detection algorithms that are based on hypothesis testing, as its name implies, it involves a cumulative sum of a statistical data records added to some weights and when the sum exceeds a certain threshold an anomaly is detected. 

This statistical method is used and implemented in two different ways that are **parametric CUSUM** and **non-parametric CUSUM**, both explained below.

The tool provides also the possibility to store the measurements done in an **InfluxDB** database, in which those values are plotted on a dedicated dashboard.

# Implementation description
In both algorithms is used a Single Exponential Smoothing (SES) algorithm to forecast next value from previous records used later to compute volume. 
The forecasting algorithm has a parameter called smoothing factor and it's optimal value should be between 0.95 and 0.99 as said in [1].
To compute the optimal smoothing factor in relation to the network conditions we use a certain number of intervals (default 4) to estimate that value with [SLSQP](https://docs.scipy.org/doc/scipy/reference/optimize.minimize-slsqp.html) alghorithm from SciPy library.

## Parametric CUSUM

For this type of CUSUM, we based our implementation on [1] in which 2 algorithms are presented: adaptive threshold algorithm, Cumulative Sum (CUSUM) algorithm.
For our aims only the second algorithm was implemented.

In this type of CUSUM we use as metric the number of SYN packets in a given time interval, that doesn't make the time series stationary in first place, but inside this CUSUM implementation we make the series stationary computing this difference:

<p align="center">
    <img width=150 src=https://render.githubusercontent.com/render/math?math={\widetilde{x}}_{n}=x_{n}-\overline{\mu}_{n-1}>
</p>


where ![formula](https://render.githubusercontent.com/render/math?math=x_{n}) is the number of SYN packets in the nth time interval, and ![formula](https://render.githubusercontent.com/render/math?math=\overline{\mu}_{n}) is an estimate of the mean rate at time n, which is computed using an exponential weighted moving average.

The volume is computed with the following formula:
<p align="center">
    <img width=400 src=https://render.githubusercontent.com/render/math?math=g_{n}=\left[g_{n-1}+\frac{\alpha\overline{\mu}_{n-1}}{\sigma^{2}}\cdot\left(x_{n}-\overline{\mu}_{n-1}-\frac{\alpha\overline{\mu}_{n-1}}{2}\right)\right]^{+}>
</p>

where ![formula](https://render.githubusercontent.com/render/math?math=\alpha) is the amplitude percentageparameter, which intuitively corresponds to the most probablepercentage of increase of the mean rate after a change (attack) has occurred, and ![formula](https://render.githubusercontent.com/render/math?math=\sigma^{2}) is the variance of Gaussians random variables used to model the variations of incoming SYN traffic (a value derivated from a classical CUSUM equation).

If the volume computed goes beyond a given fixed threshold an alarm is raised.

## Non-Parametric CUSUM

For this type of CUSUM, we based our implementation on [2].

The detection is done by measuring over time, this ratio:

<p align="center">
    <img width=130 src=https://render.githubusercontent.com/render/math?math=x_{n}=\frac{{S}_{n}-{A}_{n}}{{S}_{n}}>
</p>


where ![formula](https://render.githubusercontent.com/render/math?math={S}_{n}) denotes the number of SYN packets and ![formula](https://render.githubusercontent.com/render/math?math={A}_{n}) corresponds to SYN/ACK packets.
  
This allows to make the time series stationary because, during normal use of the network, the ratio tends to be zero (i.e. the number of incoming SYN packets equals that of outgoing ACK packets) while, during a SYN flooding attack, the ratio tends to increase, as they have more inbound SYN packets than outbound SYN/ACKs.

This detection method consists of three main modules:

1. **Outlier Processing**

    Its aim is to improve the accuracy of the detection (and to avoid false positive cases) by __discarding__ outliers values that go beyond a fixed threshold and treat them as anomalous, semplifying the detection of high-intensity attacks.

2. **Data Smoothing and Transformation**

    In this module is used a sliding window containing ![formula](https://render.githubusercontent.com/render/math?math=x_{n}) values and the random sequence ![formula](https://render.githubusercontent.com/render/math?math=z_{n}) (used to update the volume) is computed using the window mean ![formula](https://render.githubusercontent.com/render/math?math=y_{n}), the last exponentially weighted moving average (EWMA) value ![formula](https://render.githubusercontent.com/render/math?math=\widetilde{\mu}_{n-1}) and the last variance value ![formula](https://render.githubusercontent.com/render/math?math=\widetilde{\sigma}_{n-1}).

    <p align="center">
        <img width=230 src=https://render.githubusercontent.com/render/math?math=z_{n}=y_{n}-\widetilde{\mu}_{n-1}-3\widetilde{\sigma}_{n-1}>
    </p>

3. **Adaptive CUSUM Detection**

    In this module the volume is updated using the random sequence ![formula](https://render.githubusercontent.com/render/math?math=z_{n}) and according to that value either, if the ![formula](https://render.githubusercontent.com/render/math?math=z_{n}) value is equal or less than 0, the exponentially weighted moving average and the variance are computed or, if ![formula](https://render.githubusercontent.com/render/math?math=z_{n}) if greater than 0, the detection threshold is updated. 
    In case the detection threshold is updated a threshold crossing control is made.

# Aim 
The aim of this tool is to analyze the network traffic ingoing and outgoing from a single machine, in particular exchanged TCP packets, in order to detect anomalies inside it.
This tool considers only anomalies derivated from DoS/DDoS attacks where the number of incoming SYN packets increases quickly and it's greater than the number of SYN/ACK packets in a certain consecutive number of times interval.
The accuracy of the tool depends on these factors: type of CUSUM algorithm and parameters values (i.e. detection threshold in parametric CUSUM).

## Parametric CUSUM

## Accuracy
The parametric CUSUM algorithm's accuracy depends on the threshold's value, in fact high or low threshold's values in relation to network conditions can lead to false positives or negatives. 
Experimental evidences show us that a threshold value equals to 5.0 allows to correctly detect anomalies, simulated with an interval time between packets of about 1000 microseconds.

### Attack duration
For the Parametric CUSUM as said for the minimum packet rate the minimum duration of an attack depends on the threshold's avalue. 

## Non parametric CUSUM

### Accuracy
The non parametric CUSUM algorithm detects without errors SYN flooding attacks with an interval time between packets of about 475 microseconds.

### Attack duration
The minimum duration of an attack for the non parmateric CUSUM should be about 20 seconds to allow the algorithm to detect the anomaly.

# Limitations
* The tool needs a certain number of intervals (default 4) of analysis before start the detection in order to compute smoothing factors used to forecast next values. So the tool won't work properly if started during an attack.
* The tool implements only SYN flooding attack type detection, so other kinds of attacks such like UDP flooding attacks or ICMP flooding attacks won't be detected.
* With the paramentric CUSUM method it's necessary to know the normal network behaviour to give a reasonable threshold and parameters values, in order to avoid false positives or negatives.
* Both algorithms don't distinguish between requests made to an inactive service and a SYN flooding attack to an exposed service, this can lead to false positives in case a inactive service is requested multiple times. 

# Description

The project is divided in the following parts:

* **dostect.py**: is the main file
* **/core**:
    * **detectors.py**: contains CUSUM detection algorithms
    * **forecasting.py**: conta ins SES forecasting algorithm
    * **graph.py**: contains influxdb plotting class
    * **traffic.py**: contains traffic analysis classes
    * **utils.py**: contains general utilities
* **/config/influxdb**:
    * **config.ini**: contains influxdb's configuration options
    * **dostect.json**: dashboard configuration to import in influxdb

# Usage
Install dependencies: 
```
$ pip install -r requirements.txt
```

Run program, the options are listed below:
```
usage: dostect.py [-h] (-i INTERFACE | -f FILE .pcap/.pcapng) [-s INTERVAL] [-p [PARAM]]
                  [-g [GRAPH]] [-t THRESHOLD] [-a ADDRESS] [-v [VERBOSE]]

DoSTect allow to detect SYN flooding attack with Parametric/Non Parametric CUSUM change point
detection

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Network interface from which to perform live capture
  -f FILE .pcap/.pcapng, --file FILE .pcap/.pcapng
                        Packet capture file
  -s INTERVAL, --slice INTERVAL
                        Specify duration of time interval observation in seconds (e.g: 5)
  -p [PARAM], --parametric [PARAM]
                        Flag to set CUSUM Parametric mode
  -g [GRAPH], --graph [GRAPH]
                        Activate influxDB data sender: requires --interface
  -t THRESHOLD, --threshold THRESHOLD
                        Threshold detection value for CUSUM Parametric mode
  -a ADDRESS, --address ADDRESS
                        IPv4 address of attacked machine for PCAP capture: requires --file
  -v [VERBOSE], --verbose [VERBOSE]
                        Flag to set verbose output mode
```
If you need influxdb plotting you must configure first the influxdb options in the `config/influxdb/config.ini` where:
```
[influx2]
url="influxdb service url:port"
org="organization id"
token="influx db token created with read/write rights"
timeout="api request timeout in ms"
verify_ssl="True if there is necessity to verify ssl connection, False otherwise"
```

# Testing
To test the tool we used [hping3](https://tools.kali.org/information-gathering/hping3) to simulate traffic anomalies and attacks. To simulate an anomaly during a live traffic capture (*-i [INTERFACE]* option) run the following command from a machine on the same network or on a VM locally to the network:
```
sudo hping3 -c [MAX PACKETS] -S -i u475 --rand-source -p [PORT] [TARGET INTERFACE ADDRESS]
```
To test the offline capture [2 pcap files](https://mega.nz/file/B8VyjDQB#k6l-ao_TQcmfSFYpVbZ-AqNQA888jSRA5VnveAokegg) are provided: the first with an attack duration of about 30 seconds, the second with an attack duration of about 2 minutes. 
In offline analysis it's necessary provide the monitored machine network local address with *-a [ADDRESS]* option.
The machine attacked in pcap files has ip 192.168.1.9 so to run the analysis is important to secify the right ip address with `-a 192.168.1.9` flag.
The offline analysis might take a lot of time in relation to the attack's intensity and duration.

# References
[1]: [Application of anomaly detection algorithms for detecting SYN flooding attacks, V.A. Siris; F. Papagalou, IEEE, 2005](https://ieeexplore.ieee.org/document/1378372)

[2]: [A nonparametric adaptive CUSUM method and its application in source-end defense against SYN flooding attacks, Ming YU, Wuhan University Journal of Natural Sciences, 2011](https://link.springer.com/article/10.1007/s11859-011-0772-5)
