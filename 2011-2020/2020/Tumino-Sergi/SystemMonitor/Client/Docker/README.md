## Docker folder
This folder contains all the tools you need to test the infrastracture.

### Requirements
You need to follow this [README](https://github.com/Nitchbit/Tumino-Sergi/blob/main/SystemMonitor/Client/README.md) to procede as follows.

#### First Step
Open a terminal in the Docker folder and execute ```make all```.
It will download the Ubuntu image from [link](https://hub.docker.com/_/ubuntu) and, based on that, it will create the tests images.

#### Second Step
```make up_cAdvisor``` will execute the cAdvisor container and you are ready to go. You can check it on [link](http://localhost:8080).

#### Third Step
You are now ready to do some tests. We provide to you three tests, based on CPU, RAM and Storage.
The result of these tests is to verify that cAdvisor can detect the overload on these three components and expose the correct metrics.

You can execute them simultaneously with ```make all_tests```.

To test them individually:\
**CPU**: ```make cpu_test```\
**RAM**: ```make ram_test```\
**STORAGE**: ```make disco_test```

### Clean up
After you have done as written above, cAdvisor service could be still active, so you can do as follows to stop it: ```make down_cAdvisor```.
To clean your system from all of the test files: ```make cleanup```.

To delete cAdvisor service from your system use ```docker image rm -f cAdvisor```.
