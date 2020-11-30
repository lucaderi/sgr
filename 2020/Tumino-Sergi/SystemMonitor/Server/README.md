# Grafana & Plugins
Grafana is the tool that creates graphs and shows you the metrics that you are scraping.
Grafana Image Renderer is a Grafana plugin that is needed if you want to setup an alerting channel based on Telegram.

## Grafana Configuration
First thing first, you need to start Grafana service and check if it's working correctly.
You can do it executing ```sudo systemctl start grafana-server``` on a terminal, and check it on [http://localhost:3000/](http://localhost:3000/).

Second of all you need to set up your grafana account following the instruction provided by [Grafana Documentation](https://grafana.com/docs/grafana/latest/getting-started/getting-started/), then you can create your first dashboard.
The SystemMonitor provides some dashboard templates: 
- [Linux PC Metrics](https://github.com/Nitchbit/Tumino-Sergi/blob/main/SystemMonitor/Server/Linux%20PC%20Metrics-1606495399737.json) -> to monitor a single pc running a linux system;
- [Cluster Docker Metrics](https://github.com/Nitchbit/Tumino-Sergi/blob/main/SystemMonitor/Server/Cluster%20Docker%20Metrics-1606495389137.json) -> to monitor a pc that runs a cluster of docker containers;

You can import these templates while creating a new dashboard clicking on the "+" icon, then import the template uploading the JSON file.

Last thing to do is to create a datasource for each system that you want to monitor. You can do that clicking on the "settings" icon on Grafana -> Datasource -> Add Datasource -> Prometheus. Now you have to configure your datasource.
Make sure to insert the correct IP Address(IP where Prometheus is running) and the correct Port(Port where Prometheus is exposing the metrics, 9090 by default) in the URL field, and for a better result, we suggest you to insert 3s in the Scrape Interval and Query Timeout fields.
At the bottom of the page you can see a "Save & Test" button, click it and make sure to select the rigth datasource in each of your panels.
We recommend to create a different datasource for each dashboard.

## Alerting
Inside the templates, there are some alert rule already configured, however you have to configure by yourself the alerting channel.
In the Grafana page you can do it as follows: click on the "bell" icon -> Notification Channels -> Add Channel, then you can configure the channels that you want. Once your Alerting Channels is configured make sure to add it in each panel that have alert rule. For each panel you have to edit it, under the alert section you will find the alert rule and below that the option "Send to" with "+" icon.

We provide an alert system based on a Telegram bot, to do so you have to choose Telegram as your type of alerting as you create your Notification Channel.
To setup the Notification Channel you will need the bot token and your chat id.
Please ask the developers to get the token and chat it. Make sure to search our bot on Telegram (@SysOverloadAlertBot) and start a conversation with it before asking for the token or chat id

#### Troubleshooting
It can happen that when you test you datasource, Grafana gives you "Bed Gateway" error. In this case make sure that the IP Address and the Port are correct and that Prometheus is actually active on that address.

## [download.sh](download.sh)

This file allows you to download everything you need on the server side, such as:
- Grafana;
- Grafana Image Renderer;
