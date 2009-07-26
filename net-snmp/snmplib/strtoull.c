/*
 * An implementation of strtoull() for MSVC.
 * See also http://www.opengroup.org/onlinepubs/000095399/functions/strtoul.html
 * for more information about strtoull().
 */

#include <net-snmp/net-snmp-config.h>

#if !HAVE_STRTOULL

#ifdef WIN32
#include <errno.h>
#include <ctype.h>
#endif

#if defined(_MSC_VER) && _MSC_VER < 1300
#ifndef ULLONG_MAX
#define ULLONG_MAX 0xffffffffffffffffui64
#endif
#endif

unsigned        __int64
strtoull(const char *nptr, char **endptr, int base)
{
    unsigned __int64 result = 0;
    const char     *p;
    int             sign = 1;

    if (base != 0 && (base < 2 || base > 36))
        goto invalid_input;

    p = nptr;

    /*
     * Process the initial, possibly empty, sequence of white-space characters.
     */
    while (isspace((unsigned char) (*p)))
        p++;

    /*
     * Determine sign.
     */
    if (*p == '+')
        p++;
    else if (*p == '-') {
        p++;
        sign = -1;
    }

    if (base == 0) {
        /*
         * Determine base.
         */
        if (*p == '0') {
            if (p[1] == 'x' || p[1] == 'X') {
                base = 16;
                p += 2;
            } else {
                base = 8;
                p++;
            }
        } else {
            base = 10;
        }
    } else if (base == 16) {
        /*
         * For base 16, skip the optional "0x" / "0X" prefix.
         */
        if (*p == '0' && (p[1] == 'x' || p[1] == 'X'))
            p += 2;
    }

    for (; *p; p++) {
        int             digit;
        digit = ('0' <= *p && *p <= '9') ? *p - '0'
            : ('a' <= *p && *p <= 'z') ? (*p - 'a' + 10)
            : ('A' <= *p && *p <= 'Z') ? (*p - 'A' + 10) : 36;
        if (digit < base) {
            unsigned __int64 new_result;
            new_result = result * base + digit;
            if (new_result < result)
                goto out_of_range;
            result = new_result;
        } else
            break;
    }

    if (endptr)
        *endptr = (char *) p;

    return sign > 0 ? result : -result;

  invalid_input:
    errno = EINVAL;
    if (endptr)
        *endptr = (char *) nptr;
    return 0;

  out_of_range:
    errno = ERANGE;
    if (endptr)
        *endptr = (char *) nptr;
    return ULLONG_MAX;
}

#ifdef STRTOULL_UNIT_TEST

#include <assert.h>
#include <stdio.h>

int main(int argc, char** argv)
{
  assert(strtoull("0x0", 0, 0) == 0);
  assert(strtoull("1", 0, 0) == 1);
  assert(strtoull("0x1", 0, 0) == 1);
  assert(strtoull("  -0666", 0, 0) == -0666);
  assert(strtoull("  -0x666", 0, 0) == -0x666);
  assert(strtoull("18446744073709551614", 0, 0) == 0xfffffffffffffffeULL);
  assert(strtoull("0xfffffffffffffffe", 0, 0) == 0xfffffffffffffffeULL);
  assert(strtoull("18446744073709551615", 0, 0) == 0xffffffffffffffffULL);
  assert(strtoull("0xffffffffffffffff", 0, 0) == 0xffffffffffffffffULL);
  assert(strtoull("18446744073709551616", 0, 0) == 0xffffffffffffffffULL);
  assert(strtoull("0x10000000000000000", 0, 0) == 0xffffffffffffffffULL);
  printf("Done.\n");
  return 0;
}

#endif

/*
 * Local variables:
 * compile-command: "gcc -Wall -Werror -D_MSC_VER=1200 -D__int64=\"long long\" -DSTROULL_UNIT_TEST=1 -g -o strtoull-unit-test strtoull.c && ./strtoull-unit-test"
 * End:
 */

#endif
