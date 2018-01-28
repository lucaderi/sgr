/********************************************************************
Count-Min Sketches

G. Cormode 2003,2004

Updated: 2004-06 Added a floating point sketch and support for 
                 inner product point estimation
Initial version: 2003-12

This work is licensed under the Creative Commons
Attribution-NonCommercial License. To view a copy of this license,
visit http://creativecommons.org/licenses/by-nc/1.0/ or send a letter
to Creative Commons, 559 Nathan Abbott Way, Stanford, California
94305, USA. 
*********************************************************************/

#include <stdlib.h>
#include "prng.h"
#include "countmin.h"

#define min(x,y)	((x) < (y) ? (x) : (y))
#define max(x,y)	((x) > (y) ? (x) : (y))

double eps;	               /* 1+epsilon = approximation factor */
double delta;                  /* probability of failure */

//int bits=32;

/************************************************************************/
/* Routines to support Count-Min sketches                               */
/************************************************************************/

CM_type * CM_Init(int width, int depth, int seed)
{     // Initialize the sketch based on user-supplied size
  CM_type * cm;
  int j;
  prng_type * prng;

  cm=(CM_type *) malloc(sizeof(CM_type));
  prng=prng_Init(-abs(seed),2); 
  // initialize the generator to pick the hash functions

  if (cm && prng)
    {
      cm->depth=depth;
      cm->width=width;
      cm->count=0;
      cm->counts=(int **)calloc(sizeof(int *),cm->depth);
      cm->counts[0]=(int *)calloc(sizeof(int), cm->depth*cm->width);
      cm->hasha=(unsigned int *)calloc(sizeof(unsigned int),cm->depth);
      cm->hashb=(unsigned int *)calloc(sizeof(unsigned int),cm->depth);
      if (cm->counts && cm->hasha && cm->hashb && cm->counts[0])
	{
	  for (j=0;j<depth;j++)
	    {
	      cm->hasha[j]=prng_int(prng) & MOD;
	      cm->hashb[j]=prng_int(prng) & MOD;
	      // pick the hash functions
	      cm->counts[j]=(int *) cm->counts[0]+(j*cm->width);
	    }
	}
      else cm=NULL;
    }
  return cm;
}

CM_type * CM_Copy(CM_type * cmold)
{     // create a new sketch with the same parameters as an existing one
  CM_type * cm;
  int j;

  if (!cmold) return(NULL);
  cm=(CM_type *) malloc(sizeof(CM_type));
  if (cm)
    {
      cm->depth=cmold->depth;
      cm->width=cmold->width;
      cm->count=0;
      cm->counts=(int **)calloc(sizeof(int *),cm->depth);
      cm->counts[0]=(int *)calloc(sizeof(int), cm->depth*cm->width);
      cm->hasha=(unsigned int *)calloc(sizeof(unsigned int),cm->depth);
      cm->hashb=(unsigned int *)calloc(sizeof(unsigned int),cm->depth);
      if (cm->counts && cm->hasha && cm->hashb && cm->counts[0])
	{
	  for (j=0;j<cm->depth;j++)
	    {
	      cm->hasha[j]=cmold->hasha[j];
	      cm->hashb[j]=cmold->hashb[j];
	      cm->counts[j]=(int *) cm->counts[0]+(j*cm->width);
	    }
	}
      else cm=NULL;
    }
  return cm;
}

void CM_Destroy(CM_type * cm)
{     // get rid of a sketch and free up the space
  if (!cm) return;
  if (cm->counts)
    {
      if (cm->counts[0]) free(cm->counts[0]);
      free(cm->counts);
      cm->counts=NULL;
    }
  if (cm->hasha) free(cm->hasha); cm->hasha=NULL;
  if (cm->hashb) free(cm->hashb); cm->hashb=NULL;
  free(cm);  cm=NULL;
}

int CM_Size(CM_type * cm)
{ // return the size of the sketch in bytes
  int counts, hashes, admin;
  if (!cm) return 0;
  admin=sizeof(CM_type);
  counts=cm->width*cm->depth*sizeof(int);
  hashes=cm->depth*2*sizeof(unsigned int);
  return(admin + hashes + counts);
}

void CM_Update(CM_type * cm, unsigned int item, int diff)
{
  int j;

  if (!cm) return;
  cm->count+=diff;
  for (j=0;j<cm->depth;j++)
    cm->counts[j][hash31(cm->hasha[j],cm->hashb[j],item) % cm->width]+=diff;
  /* this can be done more efficiently if the width is a power of two
  
   qui viene calcolato una funzione hash sull'item da aggiornare, 
   il punto è che se trovo che questo item è un frequent item non ho la possibilità di 
   identificare chi era.*/
}

int CM_PointEst(CM_type * cm, unsigned int query)
{
  // return an estimate of the count of an item by taking the minimum
  int j, ans;

  if (!cm) return 0;
  ans=cm->counts[0][hash31(cm->hasha[0],cm->hashb[0],query) % cm->width];
  for (j=1;j<cm->depth;j++)
    ans=min(ans,cm->counts[j][hash31(cm->hasha[j],cm->hashb[j],query)%cm->width]);
  // this can be done more efficiently if the width is a power of two
  return (ans);
}

int CM_Compatible(CM_type * cm1, CM_type * cm2)
{ // test whether two sketches are comparable (have same parameters)
  int i;
  if (!cm1 || !cm2) return 0;
  if (cm1->width!=cm2->width) return 0;
  if (cm1->depth!=cm2->depth) return 0;
  for (i=0;i<cm1->depth;i++)
    {
      if (cm1->hasha[i]!=cm2->hasha[i]) return 0;
      if (cm1->hashb[i]!=cm2->hashb[i]) return 0;
    }
  return 1;
}

int CM_InnerProd(CM_type * cm1, CM_type * cm2)
{ // Estimate the inner product of two vectors by comparing their sketches
  int i,j, tmp, result;

  result=0;
  if (CM_Compatible(cm1,cm2))
    {
      for (i=0;i<cm1->width;i++)
	result+=cm1->counts[0][i]*cm2->counts[0][i];
      for (j=1;j<cm1->depth;j++)
	{
	  tmp=0;
	  for (i=0;i<cm1->width;i++)
	    tmp+=cm1->counts[j][i]*cm2->counts[j][i];
	  result=min(tmp,result);
	}
    }
  return result;
}

int CM_Residue(CM_type * cm, unsigned int * Q)
{
// CM_Residue computes the sum of everything left after the points 
// from Q have been removed
// Q is a list of points, where Q[0] gives the length of the list

  char * bitmap;
  int i,j;
  int estimate=0, nextest;

  if (!cm) return 0;
  bitmap=(char *) calloc(cm->width,sizeof(char));
  for (j=0;j<cm->depth;j++)
    {
      nextest=0;
      for (i=0;i<cm->width;i++)
	bitmap[i]=0;
      for (i=1;i<Q[0];i++)
	bitmap[hash31(cm->hasha[j],cm->hashb[j],Q[i]) % cm->width]=1;
      for (i=0;i<cm->width;i++)
	if (bitmap[i]==0) nextest+=cm->counts[j][i];
      estimate=maximum(estimate,nextest);
    }
  return(estimate);
}

