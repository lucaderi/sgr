/*
 * hash.c
 *
 *  Created on: 30-mag-2009
 *      Author: Gianluca Medici 275788
 */
#include "myhash.h"
#include "sysmacro.h"
//struct nationHash * ipDistribution=NULL;


/* Copy at most n characters into the dest buffer,
 * if the src buffer is bigger than n dest[n] is set to '\0' and return -1
 * else return the number of characters effectively copied in dest including the added '\0' at the end */
static int mystrncpy(char * dest, const char *src, size_t n) {
	size_t i;
	for (i = 0; i < n && src[i] != '\0'; i++) {
		dest[i] = src[i];
	}
	dest[i]='\0';
	return (src[i] == '\0') ? i : -1;

}

int addCity(struct cityHash * citylist, const char* name, float latitude,
		float longitude){
	struct cityHash * s = NULL;

	s = malloc(sizeof(struct cityHash));
	IFNULL(s,"FAILED to allocate new memory, addCity");
	IFERROR( mystrncpy(s->cityName, name, CITYMAX_LENGTH) , "City name too long! truncated" );
			s->latitude = latitude;
			s->longitude = longitude;
			s->numberPkt = 1;
			HASH_ADD_STR( citylist, cityName, s ); /* cityName: name of key field */
return 1;
}


int addnumPKTandCity(struct nationHash ** ipDistribution, const char* country_Id, const char* countryName, const char* cityName, float latitude,
		float longitude) {
	struct nationHash *s;
	struct cityHash *t;
	int len=strlen(countryName);
	s = malloc(sizeof(struct nationHash));
	s->listaCitta=NULL;
	IFNULL(s, "FAILED to allocate new memory, addnumPKTandCity");
	s->countryName=malloc(sizeof(char)*(len+1));
	IFNULL(s, "FAILED to allocate new memory, addnumPKTandCity country name");

	strcpy(s->countryId, country_Id);
	s->numberPkt = 1;
	IFERROR( mystrncpy(s->countryName, countryName, len+1) , "Country name too long! truncated");



	if (cityName != NULL) {//&& latitude != NULL && longitude != NULL
		t = malloc(sizeof(struct cityHash));
		IFNULL(t, "FAILED to allocate new memory, addnumPKTandCity");

		IFERROR( mystrncpy(t->cityName, cityName, CITYMAX_LENGTH) , "City name too long! truncated");

		t->latitude = latitude;
		t->longitude = longitude;
		t->numberPkt = 1;

		HASH_ADD_STR(s->listaCitta, cityName, t);
	}
	HASH_ADD_STR( *ipDistribution, countryId, s ); /* contryId: name of key field */
	return 1;
}

int addnumPKT(struct nationHash ** ipDistribution, const char* country_Id, int numPkt) {
	struct nationHash *s;

	s = malloc(sizeof(struct nationHash));

	strcpy(s->countryId, country_Id);
	s->numberPkt = numPkt;
	HASH_ADD_STR( *ipDistribution, countryId, s ); /* contryId: name of key field */
	return 1;
}

struct cityHash *find_city(struct cityHash *listCity, const char* city_name){
	struct cityHash *s;

		HASH_FIND_STR( listCity, city_name, s ); /* s: output pointer */
		return s;
}

struct nationHash *find_Nation(struct nationHash ** ipDistribution, const char* country_id) {
	struct nationHash *s;

	HASH_FIND_STR( *ipDistribution, country_id, s ); /* s: output pointer */
	return s;
}
static void delete_allCity(struct cityHash* listaCity){
	struct cityHash * current_;

	while(listaCity){
		current_=listaCity;/* grab pointer to first item */
		HASH_DEL(listaCity,current_);/* delete it (listaCity advances to next) */
		free(current_);
	}
}

void delete_nation(struct nationHash ** ipDistribution, struct nationHash *id) {
	HASH_DEL( *ipDistribution, id); /* id: pointer to delete */
	free(id->countryName);
	if(id->listaCitta != NULL){
		delete_allCity(id->listaCitta);
	}
	free(id);
}

void delete_all(struct nationHash ** ipDistribution) {
	struct nationHash *current_;

	while (*ipDistribution) {
		current_ = *ipDistribution; /* grab pointer to first item */
		free(current_->countryName);
		if(current_->listaCitta != NULL){
			delete_allCity(current_->listaCitta);
		}
		HASH_DEL(*ipDistribution,current_); /* delete it (ipDistribution advances to next) */
		free(current_); /* free it */
	}
}


void print_nations(struct nationHash ** ipDistribution) {
	struct nationHash *s;

	for (s = *ipDistribution; s != NULL; s = s->hh.next) {
		printf("Nation id %s: num packets %d\n", s->countryId, s->numberPkt);
	}
}

void print_nationsAndCity(struct nationHash ** ipDistribution) {
	struct nationHash *s;
	int i=0;
	for (s = *ipDistribution; s != NULL; s = s->hh.next) {
		i=HASH_COUNT(s->listaCitta);
		printf("Nation id %s: num packets %d num cities %d\n", s->countryId, s->numberPkt, i);
	}
}

int name_sort(struct nationHash *a, struct nationHash *b) {
	return strcmp(a->countryId, b->countryId);
}

int numPKT_sort(struct nationHash *a, struct nationHash *b) {
	return (b->numberPkt - a->numberPkt);
}

void sort_by_name(struct nationHash ** ipDistribution) {
	HASH_SORT(*ipDistribution, name_sort);
}

void sort_by_numPKT(struct nationHash ** ipDistribution) {
	HASH_SORT(*ipDistribution, numPKT_sort);
}

unsigned int countNations(struct nationHash ** ipDistribution){
	return HASH_COUNT((*ipDistribution));
}

unsigned int countCities(struct cityHash* listaCity){
	return HASH_COUNT(listaCity);
}
