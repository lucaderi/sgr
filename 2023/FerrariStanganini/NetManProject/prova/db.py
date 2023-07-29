import os
import time
import random

os.system("rrdtool create 1.rrd --step=1 DS:speed:GAUGE:10:0:1000000 RRA:AVERAGE:0.5:1:120")

print("db creato, ")

for i in range(120): 
    print(str(i) + "*")
    os.system("rrdtool update 1.rrd N:" + str(random.randint(0, 1000000)))

    time.sleep(1)

os.system("rrdtool graph my.png -w 1920 -h 1080 -D --start end-120s DEF:da1=1.rrd:speed:AVERAGE LINE:da1#ff0000:'1'")

os.system("open my.png")
