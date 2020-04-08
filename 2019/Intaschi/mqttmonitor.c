#define _POSIX_SOURCE
#include <signal.h>
#include "MQTTClient.h"
#include "configuration.h"
#include "database.h"

//Get the index of this topic name in the configuration struct
int topic_index(char * topic, struct configuration conf) {

	int i = 0;
	for (i=0; i<conf.n_topics; i++) {
		if (strcmp(topic, conf.topics[i]) == 0) {
			return i;
		}
	}
	return -1;

}

//Variable to stop the program with SIGINT
volatile sig_atomic_t stop = 0;

//Replace character 'a' with character 'b' in string str
char * string_char_replace(char * str, char a, char b) {

	int i = 0;
	for(i=0; i<strlen(str)+1; i++) {
		if (str[i] == a) str[i] = b;
	}
	return str;

}

//Signal handler function to stop the program
static void signal_handler(int signum) {

	stop = 1;

}



int main(int argc, char* argv[]) {

	//Variable used for return code
    int rc = 0;

    /*----- Signal handler installation for SIGINT -----*/

    struct sigaction s;
    memset(&s, 0, sizeof(s));
    s.sa_handler = signal_handler;
    //SIGINT stops the program correctly
    rc = sigaction(SIGINT, &s, NULL);
    if (rc == -1) {
    	perror("in signal handler installation");
    	exit(EXIT_FAILURE);
    }

    /*----- Parsing of configuration file -----*/

	//Struct for configuration parameters
	struct configuration conf;
	memset(&conf, 0, sizeof(conf));
    configuration_initialize(&conf);
    char * filename = malloc(18);
    if (filename == NULL) {
    	perror("in malloc");
    	exit(EXIT_FAILURE);
    }
    filename = strncpy(filename, "mqttmonitor.conf", 18);
    //Parsing configuration file
    configuration_parsing(&conf, filename);

    
    /*----- MQTT Client creation -----*/

    //MQTT Client
	MQTTClient client = NULL;

    if ((rc = MQTTClient_create(&client, conf.address, conf.clientid, MQTTCLIENT_PERSISTENCE_NONE, NULL)) != MQTTCLIENT_SUCCESS) {
    	printf("Failed to create client, return code %d\n", rc);
    	exit(EXIT_FAILURE);
    }

    /*----- MQTT Connection -----*/

    
	MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
    //Maximum time that should pass without communication between the client and the server, if there aren't data to send, the client 
    //send a small MQTT ping message to keep the connection
    conn_opts.keepAliveInterval = 20;
    //Boolean value, if true, in case of client connection, the server clear the previous session information for this client, if any
    conn_opts.cleansession = 1;
    //If the username and password are specified in the configuration file include it in the connect options
    if (conf.username != NULL) conn_opts.username = conf.username;
    if (conf.password != NULL) conn_opts.password = conf.password;

    if ((rc = MQTTClient_connect(client, &conn_opts)) != MQTTCLIENT_SUCCESS) {
        printf("Failed to connect, return code %d\n", rc);
        exit(EXIT_FAILURE);
    }

    /*----- Database creation ----- */

    database_creation(conf.db_address, "MQTTMonitor");

    /*----- Message elaboration -----*/

    MQTTClient_message * msg = NULL;
    char * f = NULL;
    char * field = NULL;
    char * temp = NULL;
    float n = 0.0f;
    char * topic = NULL;
    int i = 0;
    for (i=0; i<conf.n_topics; i++) {
        printf("Subscribing to topic %s for client %s using QoS%d\n\n", conf.topics[i], conf.clientid, conf.qos);
        MQTTClient_subscribe(client, conf.topics[i], conf.qos);
    }
    int topicLen = 0;
    int r = 0;
    size_t dim = 0;
	//Arrays used for compute the average values
	float * sums = malloc(conf.n_topics * sizeof(int));
	if (sums == NULL) {
		perror("in malloc");
		exit(EXIT_FAILURE);
	}
	int * cnts = malloc(conf.n_topics * sizeof(int));
	if (cnts == NULL) {
		perror("in malloc");
		exit(EXIT_FAILURE);
	}
	for(i=0; i<conf.n_topics; i++) {
		sums[i] = 0;
		cnts[i] = 0;
	}

    while (stop == 0) {
        //Wait a message for 3000 ms
    	r = MQTTClient_receive(client, &topic, &topicLen, &msg, 3000);
        if (r == MQTTCLIENT_SUCCESS) {
		    if (msg != NULL) {
                //Messagge arrived
            	//Transform the message in value
            	n = atof(msg->payload);
            	printf("Value received for %s: %4.2f\n", topic, n);
            	char b[10];
            	dim = 0;
            	float avg = 0;
				//Get the index of the topic in the struct
				int j = topic_index(topic, conf);
				if (j != -1) {
					//Update the sum and the number of values if the specified topic
					cnts[j]++;
					sums[j] = (float)(sums[j] + n);
					//Compute the average value
					avg = (double)(sums[j] / (float)cnts[j]);
					//Transform the value in string
					snprintf(b, 10, "%4.2f", avg);
				}

            	/*----- Query creation -----*/

            	//Transform the value in string
            	char a[10];
            	snprintf (a, 10, "%4.2f", n);
            	//Creation of query string
            	f = malloc(18);
            	if (f == NULL) {
    				perror("in malloc");
    				exit(EXIT_FAILURE);
    			}
            	f = strncpy(f, "value=", 7);
            	f = strncat(f, a, 18);
            	//Ignore the first part of the topic name ("$SYS/broker/")
            	char * tmp = topic+12;
            	dim = strlen(tmp) +1;
            	char * tmp1 = malloc(dim);
            	if (tmp == NULL) {
    				perror("in malloc");
    				exit(EXIT_FAILURE);
    			}
            	tmp1 = strncpy(tmp1, tmp, dim);
            	char * tmp2 = strtok(tmp1, "/");
            	//If there is "load" word in the topic name, ignore also that
            	if (strcmp(tmp2, "load") == 0) {
            		tmp = tmp + 5;
            	}
            	free(tmp1);
            	//Delete spaces in the string to correctly insert it in the database
            	tmp = string_char_replace(tmp, ' ', '_');
            	dim = strlen(tmp)+2;
            	temp = malloc(dim);
            	if (temp == NULL) {
    				perror("in malloc");
    				exit(EXIT_FAILURE);
    			}
            	temp = strncpy(temp, tmp, strlen(tmp)+1);
            	temp = strncat(temp, " ", 2);
            	dim = strlen(f) + strlen(temp) + 1;
            	field = malloc(dim);
            	if (field == NULL) {
    				perror("in malloc");
    				exit(EXIT_FAILURE);
    			}
            	field = strncpy(field, temp, strlen(temp) + 1);
            	field = strncat(field, f, strlen(f) + 1);

            	/*----- Database insertion -----*/

            	database_insert(conf.db_address, "MQTTMonitor", field);

				//Create and send the query to insert the average value in the database 
            	free(f);
            	free(field);
        		f = malloc(16);
        		f = strncpy(f, "avg=", 5);
        		f = strncat(f, b, 16);
            	dim = strlen(f) + strlen(temp) + 1;
        		char * field = malloc(dim);
        		field = strncpy(field, temp, strlen(temp) + 1);
        		field = strncat(field, f, strlen(f)+1);            		
				database_insert(conf.db_address, "MQTTMonitor", field);

				/*----- Allocated memory free -----*/

        		MQTTClient_freeMessage(&msg);
        		MQTTClient_free(topic);
        		free(temp);            		
				free(f);
            	free(field);
    	    }
	       	//else Time exceeded
		}
		else if (r == MQTTCLIENT_TOPICNAME_TRUNCATED) printf("Error\n");
	    else {
            printf("No message received, error: %s\n", MQTTClient_strerror(r));
            if (r == -3) {

            	/*----- Case Disconnection: Reconnection -----*/

                if ((rc = MQTTClient_connect(client, &conn_opts)) != MQTTCLIENT_SUCCESS) {
                    printf("Failed to connect, return code %d\n", rc);
                    exit(EXIT_FAILURE);
                }
                for (i=0; i<conf.n_topics; i++) {
                	printf("Subscribing to topic %s for client %s using QoS%d\n\n", conf.topics[i], conf.clientid, conf.qos);
                	MQTTClient_subscribe(client, conf.topics[i], conf.qos);
            	}
            }
        }
	}
    
    /*----- Program termination -----*/

    /*----- Drop database -----*/

    database_drop(conf.db_address, "MQTTMonitor");

    /*----- Allocated memory free -----*/

    MQTTClient_disconnect(client, 10000);
    MQTTClient_destroy(&client);
    configuration_free(&conf);
    free(filename);
	free(sums);
	free(cnts);

    return 0;
    
}