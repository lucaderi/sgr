#include "configuration.h"

//Initialize the memory that will contains the configuration parameters
void configuration_initialize(struct configuration * conf) {
    conf->address = malloc(50);
    if (conf->address == NULL) {
    	perror("in malloc");
    	exit(EXIT_FAILURE);
    }
    conf->clientid = malloc(50);
    if (conf->clientid == NULL) {
    	perror("in malloc");
    	exit(EXIT_FAILURE);
    }
    conf->db_address = malloc(50);
    if (conf->address == NULL) {
    	perror("in malloc");
    	exit(EXIT_FAILURE);
    }
    conf->topics = malloc(50*sizeof(char *));
    if (conf->topics == NULL) {
    	perror("in malloc");
    	exit(EXIT_FAILURE);
    }
    int i = 0;
    for (i=0; i<50; i++) {
    	conf->topics[i] = malloc(100);
    	if (conf->topics[i] == NULL) {
    		perror("in malloc");
    		exit(EXIT_FAILURE);
    	}
    }
    conf->qos = 0;
    conf->n_topics = 0;
}

//Clean the string from tab and line feed fonts
char * string_cleaner(char * str) {
    int dim = strlen(str) + 1;
    int i = 0;
    for (i=0; i<dim; i++) {
    	//Delete if font is tab or line feed
    	if (str[i] == 10 || str[i] == 9) {
    		str[i] = 0;
    		break;
    	}
    }
    return str;
}

//Frees the memory occupied by the configuration parameters
void configuration_free(struct configuration * conf) {
	free(conf->address);
	free(conf->clientid);
	free(conf->db_address);
	int i = 0;
	for (i=0; i<50; i++) {
		free(conf->topics[i]);
	}
	free(conf->topics);
}

//Parses the configuration file
int configuration_parsing(struct configuration * conf, char * filename) {
	//File descriptor for the file
	FILE * fdconf = 0;
	//Buffer that will contains the lines of the file
	char ** bufconf = malloc(100*sizeof(char *));
	if (bufconf == NULL) {
		perror("in malloc");
		exit(EXIT_FAILURE);
	}
	int i = 0;
	int c = 0;
	int topic = 0;
	//Initialization of buffer for the lines of the file
	for (i=0; i<100; i++) {
		bufconf[i] = malloc(99*sizeof(char));
		c = 0;
		for (c=0; c<99; c++) {
			bufconf[i][c] = 0;
		}
	}
	fdconf = fopen(filename, "r");
	char * var;
	i = 0;
	int p = 0;
	char * sup = malloc(10*sizeof(char));
	//While the end of the file isn't reached
	while (!feof(fdconf)) {
		if (fgets(bufconf[i], 99, fdconf) == NULL) {
			break;
		}
		//Case comment line: don't increase i
    	if (bufconf[i][0] == '#') {
    		c = 0;
    		for (c=0; c<81; c++) {
    			bufconf[i][c] = 0;
    		}
        }
		else {
			p = 0;
			//Break the line at the first space
			var = strtok(bufconf[i], " ");
			var = string_cleaner(var);
			//Check which case it is
			if (strcmp(var, "address") == 0) {
				while (var != NULL) {
					if (p == 2) strcpy(conf->address, var);
					var = strtok(NULL, " ");
					p++;
				}
				conf->address = string_cleaner(conf->address);
				conf->address = strtok(conf->address, " ");
			}
			else if (strcmp(var, "dbaddress") == 0) {
				while (var != NULL) {
					if (p == 2) strcpy(conf->db_address, var);
					var = strtok(NULL, " ");
					p++;
				}
				conf->db_address = string_cleaner(conf->db_address);
				conf->db_address = strtok(conf->db_address, " ");
			}

			else if (strcmp(var, "clientid") == 0) {
				while (var != NULL) {
					if (p == 2) strcpy(conf->clientid, var);
					var = strtok(NULL, " ");
					p++;
				}
				conf->clientid = string_cleaner(conf->clientid);
				conf->clientid = strtok(conf->clientid, " ");
			}
			else if (strcmp(var, "qos") == 0) {
				while (var != NULL) {
					if (p == 2) strcpy(sup, var);
					var = strtok(NULL, " ");
					p++;
				}
				conf->qos = atoi(sup);
			}
			else if (strcmp(var, "topic") == 0) {
				conf->n_topics++;
				while (var != NULL) {
					if (p == 2) strcpy(conf->topics[topic], var);
					var = strtok(NULL, " ");
					p++;
				}
				conf->topics[topic] = string_cleaner(conf->topics[topic]);
				conf->topics[topic] = strtok(conf->topics[topic], " ");
				topic++;
			}
		}
	}

	//Allocated memory free
	for (i=0; i<100; i++) {
		free(bufconf[i]);
	}
	free(bufconf);
	free(sup);
	return 0;
}