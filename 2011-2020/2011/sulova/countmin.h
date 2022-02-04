// Two different structures: 
//   1 -- The basic CM Sketch
//   2 -- The hierarchical CM Sketch: with log n levels, for range sums etc. 

#define min(x,y)	((x) < (y) ? (x) : (y))
#define maximum(x,y)	((x) > (y) ? (x) : (y))

typedef struct CM_type{
  long long count;
  int depth;
  int width;
  int ** counts;
  unsigned int *hasha, *hashb;
} CM_type;

typedef struct CMF_type{ // shadow of above stucture with floats
  double count;
  int depth;
  int width;
  double ** counts;
  unsigned int *hasha, *hashb;
} CMF_type;

extern CM_type * CM_Init(int, int, int);
extern CM_type * CM_Copy(CM_type *);
extern void CM_Destroy(CM_type *);
extern int CM_Size(CM_type *);

extern void CM_Update(CM_type *, unsigned int, int); 
extern int CM_PointEst(CM_type *, unsigned int);
extern int CM_PointMed(CM_type *, unsigned int);
extern int CM_InnerProd(CM_type *, CM_type *);
extern int CM_Residue(CM_type *, unsigned int *);
