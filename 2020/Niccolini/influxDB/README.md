### **Requirements:**
Go to influxDB 2.0 an download it
https://portal.influxdata.com/downloads/

Then install Telegraf (Mac OS):
```
    brew update
    brew install telegraf
``` 
or(Ubuntu):
```
    wget https://dl.influxdata.com/telegraf/releases/telegraf_1.14.1-1_amd64.deb
    sudo dpkg -i telegraf_1.14.1-1_amd64.deb
```
After configure account on InfluxDB, click Load your data.
Stick with the default option of loading data with Telegraf.
Click Create Configuration. So, click System then Continue. 
Name the Telegraf configuration,then click Create and Verify.

Follow the setup instructions on your InfluxDB page,
in `Data -> Telegrapf`. Launch InfluxDb, if you haven't already:
```
    influxd
```

Now your InfluxDB comunicate with your system and collect data. 
For any other time you would to start telegraf you must repeat the
instructions on `Data -> Telegrapf`.

Install the following library for Python:
`NB: if command pip not work try pip3 `
```
    pip install influxdb-client
    pip install matplotlib
```

### **Compile:**
Launch the .py file with your personal information(token,org,bucket,interface),
by default there are my information
`NB: without []`
```
    python3 influxdb_bandwidth.py [your_token] [your_org] [your_bucket] [your_interface]
```
For terminate close the window that show the plot



 

