# NTOPNG PlugIn about Flow's packet retransmission

## Description

NTOPNG is a web-based network traffic monitoring application; it allows the creation of Scripts that help the monitoring.
Out of all the scripts you can develop, there's the alert type, scripts that send an alert message when they take notice of something.
The plugin can be composed by different scripts, each for a different type of analisys: Host, Flow, ecc.
There are also categories for the scripts, like security and network, and this script is part of the latter.

The plugin we developed checks every ending flow to see how many packets were retransmitted and send an alert if the percentage of those packets is above a certain threshold.
The script check both client to server and server to client direction, sending an alert message if one of the two exceed the choosen value, saving the values into a table.

The PlugIn is created under ```<installation_folder>/scripts/plugins/alerts/network/tcp_retransmissions/``` and from now on we can refer to this folder as the ```<plugin_folder>```

## Manifest

This file, present under ```<plugin_folder>/manifest.lua``` give the main informations about the plugin: the title of the plugin, a short description of what it does, who made the script, and if the script has some dependecies. For this one there are none of the latter.

## The language files

Under ```<plugin_folder>/locales/``` you can define lua tables for each language. For now it was created only the English one, but the structure is the same for the others.
The only two string we defined are ```tcp_retransmissions_alert_description```, for the description of the script, and ```tcp_retransmissions_alert_title``` for his title.

## The Main script

We can found the main script under ```<plugin_folder>/user_script/flow/tcp_retransmissions.lua```

In the ```script``` table you can assign the value of varius entry that define the script:

- ```category```: it define the category this script is in; for us is ```user_scripts.script_categories.network``` so this is a Network script;
- ```l4proto```: it's purpose is to tell the loader what type of L4 protocol this script is made for. This is a script for TCP connections, so we put it equal to ```tcp```;
- ```hooks```: define the hooks, that is when this script will be called by the main program. For now it's empty, because we are going to define them at the end of the file;
- ```gui```: this is a table whose purpose is to define varius info important for the interface. In this case there are defined only ```i18n_title``` and ```i18n_description```, the title and the description of the plugin. The string that go in this values are defined in the file ```en.lua```

After the script we define our function ```retransmissions_check```. This will be the function that will be executed when the hook is triggered.
The first part is the definition of the variables we are going to use and calling the functions ```flow.getCliRetrPercentage``` and ```flow.getSrvRetrPercentage``` who return the percentage of the packets retransmitted to and from the server. These values are calculated by the C part of the code, and we are just going to retrieve them.
Then there are two if, to check if the two values we got exceed the threshold (20%) and then we put a boolean flag ( ```emit_retransmission_alert```) true and adjust the client and server score. We also put the percentage into a table called info, that will be inserted into the alert JSON.
At the end of this function, we check the flag, to see if the flow retransmitted too many packets, and if the result is positive we trigger a status with the info we got earlier. The first parameter of the ```triggerStatus``` function is a recall of the constructor of the alert status, and one of his parameter is the info table we created during the second part of the function.

The last two row of this file are the hooks. This script is used at the end of the life cycle of a flow, so we assigne the ```retransmissions_check``` to ```script.hooks.flowEnd```. But we also need to check those flows that doesn't end so fast, so we also define ```script.hooks.periodicUpdate``` with our function, to have the script called periodically in that case.

## The alert definition

Found under ```<plugin_folder>/alert_definitions/alert_retransmissions.lua```, it's the definition of the alert we send when there are too many packets retransmitted.
We firstly define the builder, called ```createRetransmissions``` that takes two argument ```alert_severity``` and ```retransmissions_info```, that indicate the severity of the alert and the info we got with the script.
With that we build a lua table, which stores those informations. This function, is called when we call the ```triggerStatus``` during the final part of the main script. During the call we assign the severity as the same one present in the status definition, and the info as a table created by the script containing the percentage who surpassed the threshold, inside a different value for each direction.
The second part of this file have the definition of the alert as a table, where we define the title as a ```i18n_title```, the icon it should show on the gui: ```con = "fas fa-exclamation"``` is a yellow exclamation mark, very good visual for Warnings.
```alert_keys``` is a way to uniquely identify this alert, pointing at it's definition under ``<installation_folder>/scripts/lua/modules/alert_keys.lua```
```creator = createRetransmissions``` is the last entry of the alert table, and assign the function we wrote before as the builder for this alert.

## The status definition

Found under ```<plugin_folder>/status_definitions/status_retransmissions.lua```, it's the definition of the status we are going to use when we send the alert.
The ```status_key``` is a way to uniquely identify this status, pointing at it's definition under ```<installation_folder>/scripts/lua/modules/flow_status.lua```.
```i18n_title``` and ```i18n_description``` are the title and the description of the status, while ```alert_type``` is a pointer to our alert definition.
```alert_severity``` stands to indicate the severity of the alert, in this case it's just a warning. If there are too many packets retransmitted in a flow it could be a symptom of a slow connection, but it isn't an error that undermine the network integrity.

## Changes to the existing code

To get this Script working, we needed more specific function to optimize the script. The program already calculate the number of packets that are retransmitted, but only give you a summary of generic issue in the tcp connection with the ```getTCPIssues()``` function.
So we created two new function in the ```<installation_folder>/src/Flow.cpp``` file:

``` 
double Flow::getCliRetrPercentage() {
  if(get_packets_cli2srv() > 10 /* Do not compute retrasmissions with too few packets */)
    return((double)stats.get_cli2srv_tcp_retr()/ (double)get_packets_cli2srv());
  else
    return 0;
}

double Flow::getSrvRetrPercentage() {
  if(get_packets_srv2cli() > 10 /* Do not compute retrasmissions with too few packets */)
    return((double)stats.get_srv2cli_tcp_retr()/ (double)get_packets_srv2cli());
  else
    return 0;
}
```

To make he script less heavy, these function calculate the percentage directly, instead of letting the script do it. If the script did it then we would need to call double the functions, 2 for the retransmitted packets and 2 for the total packets of the direction.
It also have a control over the minimum number of packets sent/received, to prevent a flood of alerts from those quick tcp connection that retransmits only one or two packets giving a percentage that exceed the threshold that is not really significant for the state of the network.

Because these are C functions, we needed to add a way for them to be usable in the Lua scripts, for that reason we modified the ```<installation_folder>/src/LuaEngineFlow.cpp.inc``` in two part

```
static int ntop_flow_get_cli_retr_percentage(lua_State* vm) {
  Flow *f = ntop_flow_get_context_flow(vm);

  if(!f) return(CONST_LUA_ERROR);

  lua_pushnumber(vm, (lua_Number)f->getCliRetrPercentage());
  return(CONST_LUA_OK);
}

static int ntop_flow_get_srv_retr_percentage(lua_State* vm) {
  Flow *f = ntop_flow_get_context_flow(vm);

  if(!f) return(CONST_LUA_ERROR);

  lua_pushnumber(vm, (lua_Number)f->getSrvRetrPercentage());
  return(CONST_LUA_OK);
}
```

These functions call the C functions counterpart and then push the result into the Lua enviroment when they are called.

```
  { "getClientRetrPercentage",  ntop_flow_get_cli_retr_percentage    },
  { "getServerRetrPercentage",  ntop_flow_get_srv_retr_percentage    }, 
```

These two line are instead under the ```luaL_Reg``` table at the end of the file, and their purpose is to define a name usable by the Lua script for those functions: 
```getClientRetrPercentage``` and ```getServerRetrPercentage``` are, in fact, the functions that we use into the Main file of the script, not the C ones.

Also, we need to add the definition of the C functions in the ```<installation_folder>/srs/Flow.hpp``` file:

```
  double getCliRetrPercentage();
  double getSrvRetrPercentage();
```

## Testing

To test the behavior of the program written, we simulated a bad connection the device using ntopng with the linux command ```tc```.
```tc``` stands for Traffic Control, and allows you to use varius tool to shape, schedule, or more the net traffic.
The full command we use is ```tc qdisc add dev wlan0 root netem delay 100000ms 10000ms 90%```:

- ```qdisc``` stands for 'queueing disciplin'. When the Kernel send a packet to an interface, the packet is enqueued in the qdisc previusly configured. Using this command means that we are modifying qdisc's related rules.
- ```add```, it's used to add a rule. If there is already a rule with the same proprieties, the command will fail, and you need to use the ```change``` option instead. Using ```del``` delete all the rules written for the interface.
- ```dev wlan0``` serves to define the interface where we are going to issue the qdisc rules.
- ```root``` indicate the parent of the new rule, to create dependancies. Root is the start of the tree of rules, and given the fact that we are only going to define one we will use this.
- ```netem``` means that the rules is for network emulation. So we are going to emulate something about the network on the given interface.
- ```delay 100000ms 10000ms 90%```: The rules will emulate a network when there's a delay. The delay is for 90% of the packets that pass on the interface, and it's 100000ms +- 10000 ms, 100 +- 10sec.

This command create this rule that emulate a state of the network in the wlan0 interface of the pc where 90% of the packets sent and received have a delay of roughly 100 seconds. This delay is too much, both for a Human and for a Computer, to handle without pressing refresh, and as expected a lot of flows triggered the alert of the PlugIn implemented.
To delete the rule after ending the test, we used the command ```tc qdisc del dev wlan0 root``` that eliminate all the rules on the wlan0 interface and about qdisc starting from the root.
