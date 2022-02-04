#ifndef IP_MAC_LIST_H
#define IP_MAC_LIST_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <arpa/inet.h>

// return value of loockUp
#define NEW_DEV 1         // MAC not found in hashTable
#define OLD_DEV_SAME_IP 2 // MAC found with same IP
#define OLD_DEV_NEW_IP 3  // MAC found with different IP

#define HASHSIZE 100


typedef enum { true, false} boolean;

typedef struct devCnctdList{
  unsigned char mac[6];   // MAC
  struct in_addr ip;      // Last IP associated with the MAC
  time_t timestamp;       // Time the MAC was last observed
  long occ;               // #occurrance of the MAC
  boolean firstTimeSeen;  // True if the MAC has never been seen before
  boolean abnormal;       // True if the MAC was found more times with dfferent IP, during the same scan
  boolean currentScan;    // True if the MAC was found in current scan
  struct devCnctdList *next;
} devCnctdList_t;

/* hash: form hash value from mac string s */
unsigned hash(unsigned char *s);

/* lookup: look for mac s in the hashtable */
int lookup(unsigned char *mac, struct in_addr ip);

/*insert: insert (mac,timestamp,ip) in the hashtable */
int insert(unsigned char *mac, struct in_addr ip, time_t timestamp);

/*logDevices: trasverse hashtable and print on log.txt MAC IP LASTSEEN OCCURENCE %OCCURRENCE VENDOR FLAG NEW DEV*/
void logDevices();

/*loadHt: load mac ip timestamp and number of occurences in the hastable from a .csv file, return an error if something goes wrong, */
int loadHt(char *);

/*storeHt: writes in a.csv file every element contained in the hashtable, return an error if something goes wrong, */
int storeHt(char *);

/*destroyHt: frees memory allocated from hashtable, return an error if something goes wrong*/
int destroyHt();

/*printMAC: auxiliary function used to print mac with the column notation*/
void printMAC(unsigned char *mac);

/*printHT: DEBUG function used to print to stdout The hastable*/
void printHT();

/*equalsMac: checks if 2 mac are equal or not*/
int equalsMac(const unsigned char *s1, const unsigned char *s2, int length);

/*macToStr: convert a mac to the correspondent string*/
char* macToStr(unsigned char* addr);

/*strToMac: convert a string to the correspondent mac*/
unsigned char* strToMac(char* str);

/*initializeScanTime: set the time of the fist scan*/
void initializeScanTime();

#endif
