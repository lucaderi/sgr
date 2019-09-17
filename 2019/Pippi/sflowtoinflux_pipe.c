#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#define TAGS_CSAMPLE " -L unixSecondsUTC,agent,ifIndex,networkType,ifSpeed,ifDirection,ifStatus,ifInOctets,ifInUcastPkts,ifInMulticastPkts,ifInBroadcastPkts,ifInDiscards,ifInErrors,ifInUnknownProtos,ifOutOctets,ifOutUcastPkts,ifOutMulticastPkts,ifOutBroadcastPkts,ifOutDiscards,ifOutErrors,ifPromiscuousMode"
#define MAXLINE 400
#define MAXTAG 100
#define MAXTIME 12

int main(int argc, char *argv[])
{
    FILE *fdcount, *fdconf;
    int i;
    char *line, *value, *query, *query_t, *temp, *timestamp, *toolcmd;
    char *tags[20] = {"Agent=", ",ifIndex=", " ifType=", " ifSpeed=", " ifDirection=", " ifStatus=", " ifInOctets=", " ifInUcastPkts=", " ifInMulticastPkts=", " ifInBroadcastPkts=", " ifInDiscards=", " ifInErrors=", " ifInUnknownProtos=", " ifOutOctets=", " ifOutUcastPkts=", " ifOutMulticastPkts=", " ifOutBroadcastPkts=", " ifOutDiscards=", " ifOutErrors=", " ifPromiscuousMode="};

    toolcmd = malloc(sizeof(char) * MAXLINE);
    query = malloc(sizeof(char) * MAXLINE);
    query_t = malloc(sizeof(char) * MAXLINE);
    temp = malloc(sizeof(char) * MAXLINE);
    line = malloc(sizeof(char) * MAXLINE);
    timestamp = malloc(sizeof(char) * MAXTAG);
    fflush(NULL);

    //<CONF PARSING>
    fdconf = fopen("./conf.ini", "r");
    if (fdconf != NULL)
    {
        while (!feof(fdconf))
        {
            if (fgets(line, MAXLINE, fdconf) != NULL)
            {
                if (line[0] != '#')
                {
                    value = strtok(line, "=");
                    if (strcmp(value, "DATABASE") == 0)
                    {
                        value = strtok(NULL, "\n");
                        sprintf(query_t, "curl -i -XPOST \'%s\' --data-binary \'Flow,", value);
                    }
                    else
                    {
                        if (strcmp(value, "PATH") == 0)
                        {
                            value = strtok(NULL, "\n");
                            sprintf(toolcmd, "%s -p ", value);
                        }
                        else
                        {
                            if (strcmp(value, "PORT") == 0)
                            {
                                value = strtok(NULL, "\n");
                                strcat(toolcmd, value);
                                strcat(toolcmd, TAGS_CSAMPLE);
                            }
                        }
                    }
                }
            }
        }
    }
    //</CONF PARSING>

    fdcount = popen(toolcmd, "r");
    while (1)
    {
        if (fdcount != NULL)
        {
            while (!feof(fdcount))
            {
                if (fgets(line, MAXLINE, fdcount) != NULL)
                {
                    value = strtok(line, ",");
                    strcpy(query, query_t);
                    strcpy(timestamp, value);
                    strcat(timestamp, "000000000");
                    for (i = 0; i < 19 && value != NULL; i++)
                    {
                        value = strtok(NULL, ",");
                        if (i == 0 || i == 1)
                        {
                            strcat(query, tags[i]);
                            strcat(query, value);
                            strcpy(temp, query);
                        }
                        else
                        {
                            strcat(query, tags[i]);
                            strcat(query, value);
                            strcat(query, " ");
                            strcat(query, timestamp);
                            strcat(query, "\'");
                            system(query);
                            strcpy(query, temp);
                        }
                    }
                }
            }
        }
    }
    free(line);
    free(temp);
    free(query);
    free(timestamp);
    free(toolcmd);
    pclose(fdcount);
    return 0;
}