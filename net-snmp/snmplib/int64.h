#ifndef INT64_INCLUDED
#define INT64_INCLUDED

typedef struct counter64 U64;

#define I64CHARSZ 21

void divBy10 __P((U64, U64 *, unsigned int *));
void multBy10 __P((U64, U64 *));
void incrByU16 __P((U64 *, unsigned int));
void incrByU32 __P((U64 *, unsigned int));
void zeroU64 __P((U64 *));
int isZeroU64 __P((U64 *));
void printU64 __P((char *, U64 *));
void printI64 __P((char *, U64 *));
void read64 __P((U64 *, char *));

#endif
