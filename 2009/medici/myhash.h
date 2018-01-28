/*
 * myhash.h
 *
 *  Created on: 30-mag-2009
 *      Author: Gianluca Medici 275788
 */

#ifndef MYHASH_H_
#define MYHASH_H_
#include <stdio.h>   /* gets */
#include <stdlib.h>  /* atoi, malloc */
#include <string.h>  /* strcpy */
#include "uthash.h"

#define CITYMAX_LENGTH		20

struct nationHash {
	char countryId [3];			 /* key */
	unsigned int numberPkt;
	struct cityHash * listaCitta;
	char * countryName;
	UT_hash_handle hh; 			/* makes this structure hashable */
};
struct cityHash{
	char cityName[CITYMAX_LENGTH];		/* key */
	float latitude;
	float longitude;
	unsigned int numberPkt;
	UT_hash_handle hh; 					/* makes this structure hashable */
};

int addCity(struct cityHash * citylist, const char* name, float latitude,
		float longitude);
int addnumPKTandCity(struct nationHash ** ipDistribution, const char* country_Id, const char* countryName, const char* cityName, float latitude,
		float longitude);
int addnumPKT(struct nationHash ** ipDistribution, const char* country_Id, int numPkt);
struct cityHash *find_city(struct cityHash *listCity, const char* city_name);
struct nationHash *find_Nation(struct nationHash ** ipDistribution, const char* country_id);
void delete_nation(struct nationHash ** ipDistribution, struct nationHash *id);
void delete_all(struct nationHash ** ipDistribution);
void print_nations(struct nationHash ** ipDistribution);
void print_nationsAndCity(struct nationHash ** ipDistribution);
void sort_by_name(struct nationHash ** ipDistribution);
void sort_by_numPKT(struct nationHash ** ipDistribution);
unsigned int countNations(struct nationHash ** ipDistribution);
unsigned int countCities(struct cityHash* listaCity);
#endif /* MYHASH_H_ */
