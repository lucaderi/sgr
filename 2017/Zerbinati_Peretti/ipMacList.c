#define _XOPEN_SOURCE 500
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include "ipMacList.h"
#include <inttypes.h>
#include <limits.h>
#include "macToVendor.h"
#include <arpa/inet.h>

#define LOGFILE "log.txt"
#define TEMPFILE "#temp.txt#"

static devCnctdList_t * ht[HASHSIZE] = {NULL};
static time_t initScanTime;
static long scan_count = 0;

/**
 * printDevCnctdList() prints a devCnctdList element
 */
void printDevCnctdList(devCnctdList_t e) {
  struct tm *timestamp_tm;
  char timestamp_buf[256] = {0};
  timestamp_tm = localtime(&(e.timestamp));
  strftime(timestamp_buf, 256, "%s", timestamp_tm);

  fprintf(stdout, "ELEMENT: %s, %s, %s\n", timestamp_buf, inet_ntoa(e.ip), macToStr(e.mac));
}

/* equalsMAC() compares 2 MACs. Return 0 if equals */
int equalsMac(const unsigned char *s1, const unsigned char *s2, int length) {
    for (int i = 0; i < length; i++) {
        if (s1[i] != s2[i])
            return -1;
    }
    return 0;
}

/**
 * macToStr() converts from a MAC to String in human-readable notation
 */
char* macToStr(unsigned char* addr)
{
    static char str[18];
    if(addr == NULL) return "";
    snprintf(str, sizeof(str), "%02x:%02x:%02x:%02x:%02x:%02x",
             addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    return str;
}

/**
 * strToMac() convers from a MAC String to MAC
 */
unsigned char* strToMac(char* str) {
  static unsigned char addr[6];
  sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &addr[0], &addr[1], &addr[2], &addr[3], &addr[4], &addr[5]);
  return addr;
}

/**
 * hash() calculates hash value starting from a MAC
 */
unsigned hash(unsigned char* mac) {
  unsigned hashval = 0;
  for(int i=0; i<6; i++) {
    hashval = mac[i] + 23 * hashval;
  }
  // printf("hashval: %u\n", hashval % HASHSIZE);
  return hashval % HASHSIZE;
}

/**
 * lookup() look for MAC mac in the Hash Table
 */
int lookup(unsigned char *mac, struct in_addr ip){
  devCnctdList_t *lst;
  boolean currentScan;
  for(lst = ht[hash(mac)]; lst !=NULL; lst = lst->next){
      lst->currentScan = true;
      if(equalsMac(mac, lst->mac, 6) == 0){
        // MAAC already exits
        if(ip.s_addr == lst->ip.s_addr){
          // same IP
          if(difftime(lst->timestamp, initScanTime) < 0){
            lst->occ++;
            lst->timestamp = time(NULL);
          }
          return OLD_DEV_SAME_IP;
        }else{
          // different IP
          if(difftime(lst->timestamp, initScanTime) < 0){ // difftime(t1, t0) = t1 - t0
            // the device with this MAC probably changed IP between the current scan and the old one. Not an error
            lst->occ++;
            lst->timestamp = time(NULL);
            //fprintf(stdout, "INSERT:  IP OLD_DEV_NEW_IP: %s\n", ip);
          }else{
            // the same MAC got different IPs: Anomaly
            lst->abnormal = true;
            lst->occ++; // in this case we actually have many occurrances in the same scan
          }
          return OLD_DEV_NEW_IP;
        }
      }
    }
    return NEW_DEV; // MAC not in Hash Table
  }

/**
 * insert() inserts (mac,timestamp,ip) in the Hash Table, initializes abnormal to false,
 * initializes firstTimeSeen to true and currentScan to true
 */
int insert(unsigned char *mac, struct in_addr ip, time_t timestamp){
  unsigned hashval;
  boolean currentScan;
  int lu = lookup(mac, ip);
  if(lu == NEW_DEV){ // not found
    // allocate memory for the element (will be free by main thread)
    devCnctdList_t *lst = (devCnctdList_t*) malloc(sizeof(devCnctdList_t));
    memcpy(lst->mac, mac, 6*sizeof(unsigned char));
    lst->ip = ip;
    lst->timestamp = timestamp;
    lst->occ = 1;
    lst->firstTimeSeen = true;
    lst->abnormal = false;
    lst->currentScan = true;
    if(lst->mac == NULL) return -1;
    hashval = hash(mac);
    lst->next = ht[hashval];
    ht[hashval] = lst;
  }
  return 0;
}

/**
 * storeHt() stores the dump of the HashTable in a file
 */
int storeHt(char* file_name) {
  FILE *fp;
  devCnctdList_t *currHt;
  struct tm *timestamp_tm;
  char timestamp_buf[256] = {0};
  char* mac_str;

  fp = fopen(file_name, "w");
  if(fp== NULL) {
    fprintf(stdout, "Error opening File\n");
    return -1;
  }
  scan_count++;
  fprintf(fp, "%lu\n", scan_count);
  for (int i = 0; i < HASHSIZE; i++) {
    currHt=ht[i];
    while(currHt != NULL) {
      timestamp_tm = localtime(&(currHt->timestamp));
      strftime(timestamp_buf, 256, "%s", timestamp_tm);
      mac_str = macToStr(currHt->mac);
      fprintf(fp, "%s,%s,%s,%ld\n", timestamp_buf, inet_ntoa(currHt->ip), mac_str, currHt->occ);
      currHt = currHt->next;
    }
  }
  fclose(fp);
  return 0;
}

/**
 * destroyHt() frees all the memory occupied by the Hash Table
 */
int destroyHt() {
  devCnctdList_t *currHt, *nextHt;
    for (int i=0; i < HASHSIZE; i++) {
      currHt = ht[i];
      while(currHt != NULL) {
	      nextHt = currHt->next;
	      free(currHt);
        currHt = nextHt;
      }
   }
   return 0;
 }

/**
 * loadHt() loads the HashTable from the dump file
 */
int loadHt(char *fileName){
  FILE *fp;
  const size_t line_size = 200;
  char* line = malloc(line_size);
  char *mac;
  time_t timestamp;
  char *ip_str;
  char *occ_str;
  long occ;
  boolean currentScan;

  struct tm time_tm = {0};
  char *timestamp_str;

  fp = fopen(fileName, "r");
  if (fp == NULL) {
      fprintf(stdout, "Creating File %s\n", fileName);
      fp = fopen(fileName, "w+");
       if (fp == NULL) {
          fprintf(stdout, "Error opening File\n");
          free(line);
          return -1;
      }
  }

  if (fgets(line, line_size, fp) != NULL)
    scan_count = strtol(line, NULL, 10);
  else
    scan_count = 0;

  while (fgets(line, line_size, fp) != NULL) {
    unsigned hashval;
    timestamp_str = strtok(line, ",");
    ip_str = strtok(NULL, ",");
    mac = strtok(NULL, ",");
    occ_str = strtok(NULL, "\n");
    // printf("%s %s %s %s\n", timestamp_str, ip_str, mac, occ_str);
    occ = atol(occ_str);
    if(strptime(timestamp_str, "%s", &time_tm) == NULL) return -1;
    timestamp = mktime(&time_tm);
    // every entry is a new element
    devCnctdList_t *newEl = (devCnctdList_t *) malloc(sizeof(devCnctdList_t));
    unsigned char* mac_addr = strToMac(mac);
    memcpy(newEl->mac, mac_addr, 6*sizeof(unsigned char));
    struct in_addr ip;
    inet_aton(ip_str, &ip);
    newEl->ip = ip;
    newEl->timestamp = timestamp;
    newEl->occ = occ;
    newEl->firstTimeSeen = false;
    newEl->abnormal = false;
    newEl->currentScan = false; // will be flagged true if found in the scan
    hashval = hash(newEl->mac);
    newEl->next = ht[hashval];
    ht[hashval] = newEl;
  }
  free(line);
  fclose(fp);
  return 0;
}

/**
 * logDevices() prepend the log of the current scan to the file descriptor fpLog
 */
void logDevices() {
  FILE *fpLog, *fpTemp;
  char vendor[100];
  devCnctdList_t *curr;
  int a;

  char buf[80];
  time_t initT = initScanTime;
  strftime(buf, sizeof(buf),"%a %Y-%m-%d %H:%M:%S %Z", localtime(&initT));

  /* scrivo sul file temporaneo */
  fpTemp = fopen(TEMPFILE, "ab+");
  if (fpTemp == NULL) {
    fprintf(stderr, "Error opening ");
    return;
  }
  fprintf(fpTemp, "##########################################################################  Scan Started At:  %s ########################################################################## \n\n", buf);
  fprintf(fpTemp, "MAC\t\t\t\t    IP\t\t\t\tLAST SEEN\t        OCCURRENCE\t %% OCCURRENCE\t\t\t\t   VENDOR\n");
  for (int i=0; i<HASHSIZE; i++) {
    for(curr= ht[i]; curr!=NULL; curr= curr->next) {
      if(curr->currentScan == true){
        /* associo il vendor ad ogni mac */
        macToVendor(vendor, curr->mac);
        /* formatto la stringa time */
        struct tm *infotime = localtime(&(curr->timestamp));
        char* time_str = asctime(infotime);
        time_str[strlen(time_str)-1] = 0;
        float occ_rate = ((float)curr->occ / scan_count) * 100;
        fprintf(fpTemp, "%s\t\t%s\t\t%s\t   %ld\t\t     %.1f%%\t\t", macToStr(curr->mac), inet_ntoa(curr->ip), time_str, curr->occ, occ_rate);

        if( vendor != NULL) {
          fprintf(fpTemp, "\t%s\t", vendor);
        }
        if( curr->firstTimeSeen == true) {
          fprintf(fpTemp, "  NEW DEVICE");
        }
        if( curr->abnormal == true) {
          fprintf(fpTemp, "\tMORE IP WITH SAME MAC");
        }
        fprintf(fpTemp, "\n");
     }
   }
  }
  fprintf(fpTemp, "\n############################################################################     Scan Total Number :%ld     ##########################################################################################\n\n", scan_count);
  fprintf(fpTemp, "\n");
  fpLog = fopen(LOGFILE, "ab+");
  if (fpLog == NULL) {
    fprintf(stderr, "Error opening ");
    fclose(fpTemp);
    return;
  }

  int line_size = 200;
  char line[line_size];
  while (fgets(line, line_size, fpLog) != NULL) {
   //  if (strstr(line, "MAC") == NULL)
      fprintf(fpTemp, "%s", line);
  }
  fclose(fpLog);
  fclose(fpTemp);
  // sovrascrivo
  rename(TEMPFILE, LOGFILE);
}


/**
 * printHT() prints all element of the Hash Table (used for debug)
 */
void printHT() {
  printf("PRINTING HT IN MEMORY...\n");
  devCnctdList_t *currHt;
  struct tm *timestamp_tm;
  char timestamp_buf[256] = {0};
  for (int i = 0; i < HASHSIZE; i++) {
    currHt=ht[i];
    while(currHt != NULL) {
      timestamp_tm = localtime(&(currHt->timestamp));
      strftime(timestamp_buf, 256, "%s", timestamp_tm);
      fprintf(stdout, "- %s,%s,%s, occurences: %ld \n", timestamp_buf, inet_ntoa(currHt->ip), macToStr(currHt->mac), currHt->occ);
      currHt = currHt->next;
    }
  }
}

/**
 * initializeScanTime() initializes the scantime to the current timestamp
 */
void initializeScanTime(){
  initScanTime = time(NULL);
}
