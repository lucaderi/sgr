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
    char *line, *value, *query, *query_t, *temp, *timestamp, *toolcmd, *address, *org, *bucket, *token;
    char *tags[20] = {"Agent=", ",ifIndex=", " ifType=", " ifSpeed=", " ifDirection=", " ifStatus=", " ifInOctets=", " ifInUcastPkts=", " ifInMulticastPkts=", " ifInBroadcastPkts=", " ifInDiscards=", " ifInErrors=", " ifInUnknownProtos=", " ifOutOctets=", " ifOutUcastPkts=", " ifOutMulticastPkts=", " ifOutBroadcastPkts=", " ifOutDiscards=", " ifOutErrors=", " ifPromiscuousMode="};

    toolcmd = malloc(sizeof(char) * MAXLINE);
    query = malloc(sizeof(char) * MAXLINE);
    query_t = malloc(sizeof(char) * MAXLINE);
    temp = malloc(sizeof(char) * MAXLINE);
    line = malloc(sizeof(char) * MAXLINE);
    timestamp = malloc(sizeof(char) * MAXTAG);
    address = malloc(sizeof(char) * MAXLINE);
    org = malloc(sizeof(char) * MAXLINE);
    bucket = malloc(sizeof(char) * MAXLINE);
    token = malloc(sizeof(char) * MAXLINE);
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
                        value = strtok(NULL, "\r\n");
                        strcat(address, value);
                        // sprintf(query_t, "curl --request POST \'%s\' --header \'Authorization: Token j66isSIJjLe1lMjxzhFz0_Ov1n2QQLwa4BXPtNlKs83qgSExp2bHaxJslLv-ZN6H5Xn00F6C88TPKAzfk9nOkQ==\' --data-binary \'sflow,", value);
                    }
                    else
                    {
                        if (strcmp(value, "PATH") == 0)
                        {
                            value = strtok(NULL, "\r\n");
                            sprintf(toolcmd, "%s -p ", value);
                        }
                        else
                        {
                            if (strcmp(value, "PORT") == 0)
                            {
                                value = strtok(NULL, "\r\n");
                                strcat(toolcmd, value);
                                strcat(toolcmd, TAGS_CSAMPLE);
                            }
                            else
                            {
                                if (strcmp(value, "ORG") == 0)
                                {
                                    value = strtok(NULL, "\r\n");
                                    strcat(org, value);
                                }
                                else
                                {
                                    if (strcmp(value, "BUCKET") == 0)
                                    {
                                        value = strtok(NULL, "\r\n");
                                        strcat(bucket, value);
                                    }
                                    else
                                    {
                                        if (strcmp(value, "TOKEN") == 0)
                                        {
                                            value = strtok(NULL, "\r\n");
                                            strcat(token, value);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        sprintf(query_t, "curl --request POST \'%sapi/v2/write?org=%s&bucket=%s&precision=ns\' --header \'Authorization: Token %s\' --data-binary \'sflow,", address, org, bucket, token);
        printf("DEBUG: Query: %s\n", query_t);
        fflush(NULL);
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
                            if (i == 0)
                            {
                                printf("DEBUG: Agent: %s\n", value);
                                fflush(NULL);
                            }
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