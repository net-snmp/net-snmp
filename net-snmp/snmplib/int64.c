/** file: test.c - test of 64-bit integer stuff
*
*
* 21-jan-1998: David Perkins <dperkins@dsperkins.com>
*
*/

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "int64.h"

#define TRUE 1
#define FALSE 0

/** divBy10 - divide an unsigned 64-bit integer by 10
*
* call with:
*   u64 - number to be divided
*   pu64Q - location to store quotient
*   puR - location to store remainder
*
*/
void
divBy10(u64, pu64Q, puR)
  U64 u64;
  U64 *pu64Q;
  unsigned int *puR;
  
{
    unsigned long ulT;
    unsigned long ulQ;
    unsigned long ulR;


    /* top 16 bits */
    ulT = (u64.ulHi>>16) & 0x0ffff;
    ulQ = ulT/10;
    ulR = ulT%10;
    pu64Q->ulHi = ulQ<<16;

    /* next 16 */
    ulT = (u64.ulHi & 0x0ffff);
	ulT += (ulR<<16);
    ulQ = ulT/10;
    ulR = ulT%10;
    pu64Q->ulHi = pu64Q->ulHi | ulQ;

    /* next 16 */
    ulT = ((u64.ulLo>>16) & 0x0ffff) + (ulR<<16);
    ulQ = ulT/10;
    ulR = ulT%10;
    pu64Q->ulLo = ulQ<<16;

    /* final 16 */
    ulT = (u64.ulLo & 0x0ffff);
	ulT += (ulR<<16);
    ulQ = ulT/10;
    ulR = ulT%10;
    pu64Q->ulLo = pu64Q->ulLo | ulQ;

    *puR = (unsigned int)(ulR);


} /* divBy10 */


/** multBy10 - multiply an unsigned 64-bit integer by 10
*
* call with:
*   u64 - number to be multiplied
*   pu64P - location to store product
*
*/
void
multBy10(u64, pu64P)
  U64 u64;
  U64 *pu64P;
{
    unsigned long ulT;
    unsigned long ulP;
    unsigned long ulK;


    /* lower 16 bits */
    ulT = u64.ulLo & 0x0ffff;
    ulP = ulT * 10;
    ulK = ulP>>16;
    pu64P->ulLo = ulP & 0x0ffff;

    /* next 16 */
    ulT = (u64.ulLo>>16) & 0x0ffff;
    ulP = (ulT * 10) + ulK;
    ulK = ulP>>16;
    pu64P->ulLo = (ulP & 0x0ffff)<<16 | pu64P->ulLo;

    /* next 16 bits */
    ulT = u64.ulHi & 0x0ffff;
    ulP = (ulT * 10) + ulK;
    ulK = ulP>>16;
    pu64P->ulHi = ulP & 0x0ffff;

    /* final 16 */
    ulT = (u64.ulHi>>16) & 0x0ffff;
    ulP = (ulT * 10) + ulK;
    ulK = ulP>>16;
    pu64P->ulHi = (ulP & 0x0ffff)<<16 | pu64P->ulHi;


} /* multBy10 */


/** incrByU16 - add an unsigned 16-bit int to an unsigned 64-bit integer
*
* call with:
*   pu64 - number to be incremented
*   u16 - amount to add
*
*/
void
incrByU16(pu64, u16)
  U64 *pu64;
  unsigned int u16;
{
    unsigned long ulT1;
    unsigned long ulT2;
    unsigned long ulR;
    unsigned long ulK;


    /* lower 16 bits */
    ulT1 = pu64->ulLo;
    ulT2 = ulT1 & 0x0ffff;
    ulR = ulT2 + u16;
    ulK = ulR>>16;
    if (ulK == 0) {
        pu64->ulLo = ulT1 + u16;
        return;
    }

    /* next 16 bits */
    ulT2 = (ulT1>>16) & 0x0ffff;
    ulR = ulT2+1;
    ulK = ulR>>16;
    if (ulK == 0) {
        pu64->ulLo = ulT1 + u16;
        return;
    }
   
    /* next 32 - ignore any overflow */
    pu64->ulLo = (ulT1 + u16) & 0x0FFFFFFFFL;
    pu64->ulHi++;

} /* incrByV16 */

void
incrByU32(pu64, u32)
  U64 *pu64;
  unsigned int u32;
{
  unsigned int tmp;
  tmp = pu64->ulLo;
  pu64->ulLo += u32;
  if (pu64->ulLo < tmp)
    pu64->ulHi++;
}

/** zeroU64 - set an unsigned 64-bit number to zero
*
* call with:
*   pu64 - number to be zero'ed
*
*/
void
zeroU64(pu64)
  U64 *pu64;
{

    pu64->ulLo = 0;
    pu64->ulHi = 0;

} /* zeroU64 */


/** isZeroU64 - check if an unsigned 64-bit number is
*
* call with:
*   pu64 - number to be zero'ed
*
*/
int
isZeroU64(pu64)
  U64 *pu64;
{

    if ((pu64->ulLo == 0) && (pu64->ulHi == 0))
        return(TRUE);
    else
        return(FALSE);

} /* isZeroU64 */

char *
printU64(pu64)
  U64 *pu64;
{
  U64 u64a;
  U64 u64b;

#define I64CHARSZ 20
  static char aRes[I64CHARSZ+1];
  unsigned int u;
  int j;

  u64a.ulHi = pu64->ulHi;
  u64a.ulLo = pu64->ulLo;
  
  aRes[I64CHARSZ] = 0;
  for (j = 0; j < I64CHARSZ; j++) {
    divBy10(u64a, &u64b, &u);
    aRes[(I64CHARSZ-1)-j] = (char)('0' + u);
    u64a.ulHi = u64b.ulHi;
    u64a.ulLo = u64b.ulLo;
    if (isZeroU64(&u64a))
      break;
  }
  return &aRes[(I64CHARSZ-1)-j];
}

#ifdef TESTING
void
main(int argc, char *argv[])
{
    int i;
    int j;
    int l;
    unsigned int u;
    U64 u64a;
    U64 u64b;
#define MXSZ 20
    char aRes[MXSZ+1];


    if (argc < 2) {
        printf("This program takes numbers from the command line\n"
               "and prints them out.\n"
               "Usage: test <unsignedInt>...\n");
        exit(1);
    }

    aRes[MXSZ] = 0;

    for (i = 1; i < argc; i++) {
        l = strlen(argv[i]);
        zeroU64(&u64a);
        for (j = 0; j < l; j++) {
            if (!isdigit(argv[i][j])) {
                printf("Argument is not a number \"%s\"\n", argv[i]);
                exit(1);
            }
            u = argv[i][j] - '0';
            multBy10(u64a, &u64b);
            u64a = u64b;
            incrByU16(&u64a, u);
        }

        printf("number \"%s\" in hex is '%08x%08x'h\n",
                argv[i], u64a.ulHi, u64a.ulLo);

        printf("number is \"%s\"\n", printU64(&u64a));
        for (j = 0; j < MXSZ; j++) {
            divBy10(u64a, &u64b, &u);
            aRes[(MXSZ-1)-j] = (char)('0' + u);
            u64a = u64b;
            if (isZeroU64(&u64a))
                break;
        }

        printf("number is \"%s\"\n", &aRes[(MXSZ-1)-j]);
    }
	exit(0);
} /* main */
#endif /* TESTING */

/* file: test.c */

