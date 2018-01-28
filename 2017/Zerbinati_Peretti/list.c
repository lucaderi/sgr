#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#define OUI "oui/oui.csv"

/* https://stackoverflow.com/questions/19300596/implementation-of-tolower-function-in-c */
int toLower(int chr)//touches only one character per call
{
    return (chr >='A' && chr<='Z') ? (chr + 32) : (chr);
}

int strncmp_nocase(const char s1[], const char s2[], int l) {
  int i=0;
  for(i=0; i<l; i++) {
    if ( tolower(s1[i]) != tolower(s2[i])) return -1;
  }
  return 0;
}

char* macToVendor(char* vendor, unsigned char* mac_addrs) {
  FILE *fp;
  const size_t line_size = 200;
  char* line;
  char* tk_mac = NULL;
  char *tk_vndr;
  int i;
  char short_mac[6];
  // tk_vndr = (char*) malloc(100*sizeof(char));

  sprintf(short_mac, "%02x%02x%02x",
        (unsigned char) mac_addrs[0],
        (unsigned char) mac_addrs[1],
        (unsigned char) mac_addrs[2]);
  /* convert MAC to uppercase string (6 chars) */
  for (i=0;i<6; i++) {
          short_mac[i] = toupper(short_mac[i]);
  }
  line = malloc(line_size);
  if (line == NULL) {
    fprintf(stderr, "Error malloc macToVendor");
    return NULL;
  }
  fp = fopen(OUI, "r");
  if (fp == NULL) {
    fprintf(stdout, "Error opening File");
    free(line);
    return NULL;
  }

  /* la fgets si ferma ad una newline o EOF */
  while (fgets(line, line_size, fp) != NULL) {
    tk_mac = strtok(line, ",");
    if ( strncmp(tk_mac, short_mac, 6) == 0) {
      tk_vndr = strtok(NULL, "\n");
      strcpy(vendor, tk_vndr);
      free(line);
      fclose(fp);
      return tk_vndr;
    }
  }
  free(line);
  fclose(fp);
  return tk_vndr;
}
