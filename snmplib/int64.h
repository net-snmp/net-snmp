#ifndef INT64_INCLUDED
#define INT64_INCLUDED

typedef struct counter64 U64;

#define I64CHARSZ 21

void divBy10 (U64, U64 *, unsigned int *);
void multBy10 (U64, U64 *);
void incrByU16 (U64 *, unsigned int);
void incrByU32 (U64 *, unsigned int);
void zeroU64 (U64 *);
int isZeroU64 (U64 *);
void printU64 (char *, U64 *);
void printI64 (char *, U64 *);
void read64 (U64 *, char *);

#endif
