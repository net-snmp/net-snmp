/*
 * An implementation of strtoull() for compilers that do not have this
 * function, e.g. MSVC.
 * See also http://www.opengroup.org/onlinepubs/000095399/functions/strtoul.html
 * for more information about strtoull().
 */


/*
 * For MSVC, disable the warning "unary minus operator applied to unsigned
 * type, result still unsigned"
 */
#ifdef _MSC_VER
#pragma warning (disable: 4146)
#endif


#define __STDC_CONSTANT_MACROS  /* Enable UINT64_C in <stdint.h> */
#define __STDC_FORMAT_MACROS    /* Enable PRIu64 in <inttypes.h> */

#include <net-snmp/net-snmp-config.h>

#include <errno.h>
#include <ctype.h>
#include <limits.h>
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include <net-snmp/types.h>
#include <net-snmp/library/system.h>

/*
 * UINT64_C: C99 macro for the suffix for uint64_t constants. 
 */
#ifndef UINT64_C
#ifdef _MSC_VER
#define UINT64_C(c) c##ui64
#else
#define UINT64_C(c) c##ULL
#endif
#endif

/*
 * According to the C99 standard, the constant ULLONG_MAX must be defined in
 * <limits.h>. Define it here for pre-C99 compilers.
 */
#ifndef ULLONG_MAX
#define ULLONG_MAX UINT64_C(0xffffffffffffffff)
#endif

#ifdef STRTOULL_UNIT_TEST
uint64_t
my_strtoull(const char *nptr, char **endptr, int base)
#else
uint64_t
strtoull(const char *nptr, char **endptr, int base)
#endif
{
    uint64_t        result = 0;
    const char     *p;
    const char     *first_nonspace;
    const char     *digits_start;
    int             sign = 1;
    int             out_of_range = 0;

    if (base != 0 && (base < 2 || base > 36))
        goto invalid_input;

    p = nptr;

    /*
     * Process the initial, possibly empty, sequence of white-space characters.
     */
    while (isspace((unsigned char) (*p)))
        p++;

    first_nonspace = p;

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
            if ((p[1] == 'x' || p[1] == 'X')) {
                if (isxdigit((unsigned char)(p[2]))) {
                    base = 16;
                    p += 2;
                } else {
                    /*
                     * Special case: treat the string "0x" without any further
                     * hex digits as a decimal number.
                     */
                    base = 10;
                }
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
        if (*p == '0' && (p[1] == 'x' || p[1] == 'X')
            && isxdigit((unsigned char)(p[2]))) {
            p += 2;
        }
    }

    digits_start = p;

    for (; *p; p++) {
        int             digit;
        digit = ('0' <= *p && *p <= '9') ? *p - '0'
            : ('a' <= *p && *p <= 'z') ? (*p - 'a' + 10)
            : ('A' <= *p && *p <= 'Z') ? (*p - 'A' + 10) : 36;
        if (digit < base) {
            if (! out_of_range) {
                if (result > ULLONG_MAX / base
                    || result * base > ULLONG_MAX - digit) {
                    out_of_range = 1;
                }
                result = result * base + digit;
            }
        } else
            break;
    }

    if (p > first_nonspace && p == digits_start)
        goto invalid_input;

    if (p == first_nonspace)
        p = nptr;

    if (endptr)
        *endptr = (char *) p;

    if (out_of_range) {
        errno = ERANGE;
        return ULLONG_MAX;
    }

    return sign > 0 ? result : -result;

  invalid_input:
    errno = EINVAL;
    if (endptr)
        *endptr = (char *) nptr;
    return 0;
}

#if defined(STRTOULL_UNIT_TEST)

#include <stdio.h>
#include <stdlib.h>

#ifndef PRIu64
#ifdef _MSC_VER
#define PRIu64 "I64u"
#else
#define PRIu64 "llu"
#endif
#endif

struct strtoull_testcase {
    /*
     * inputs 
     */
    const char     *nptr;
    int             base;
    /*
     * expected outputs 
     */
    int             expected_errno;
    int             expected_end;
    uint64_t        expected_result;
};

static const struct strtoull_testcase test_input[] = {
    {"0x0", 0, 0, 3, 0},
    {"1", 0, 0, 1, 1},
    {"0x1", 0, 0, 3, 1},
    {"  -0666", 0, 0, 7, -0666},
    {"  -0x666", 0, 0, 8, -0x666},
    {"18446744073709551614", 0, 0, 20, UINT64_C(0xfffffffffffffffe)},
    {"0xfffffffffffffffe", 0, 0, 18, UINT64_C(0xfffffffffffffffe)},
    {"18446744073709551615", 0, 0, 20, UINT64_C(0xffffffffffffffff)},
    {"0xffffffffffffffff", 0, 0, 18, UINT64_C(0xffffffffffffffff)},
    {"18446744073709551616", 0, ERANGE, 20, UINT64_C(0xffffffffffffffff)},
    {"0x10000000000000000", 0, ERANGE, 19, UINT64_C(0xffffffffffffffff)},
    {"ff", 16, 0, 2, 255},
    {"0xff", 16, 0, 4, 255},
    {" ", 0, 0, 0, 0},
    {"0x", 0, 0, 1, 0},
    {"0x", 8, 0, 1, 0},
    {"0x", 16, 0, 1, 0},
    {"zyyy", 0, 0, 0, 0},
    {"0xfffffffffffffffff", 0, ERANGE, 19, ULLONG_MAX},
    {"0xfffffffffffffffffz", 0, ERANGE, 19, ULLONG_MAX}
};

int
main(void)
{
    int             failure_count = 0;
    unsigned int    i;

    for (i = 0; i < sizeof(test_input) / sizeof(test_input[0]); i++) {
        const struct strtoull_testcase *const p = &test_input[i];
        char           *endptr;
        uint64_t        result;

        errno = 0;
        result = my_strtoull(p->nptr, &endptr, p->base);
        if (errno != p->expected_errno) {
            failure_count++;
            printf("test %d failed (input \"%s\"): expected errno %d"
                   ", got errno %d\n",
                   i, p->nptr, p->expected_errno, errno);
        }
        if (result != p->expected_result) {
            failure_count++;
            printf("test %d failed (input \"%s\"): expected result %" PRIu64
                   ", got result %" PRIu64 "\n",
                   i, p->nptr, p->expected_result, result);
        }
        if (endptr - p->nptr != p->expected_end) {
            failure_count++;
            printf("test %d failed (input \"%s\"): expected end %d,"
                   " got end %d\n",
                   i, p->nptr, p->expected_end, (int) (endptr - p->nptr));
        }

#if HAVE_STRTOULL
        errno = 0;
        result = strtoull(p->nptr, &endptr, p->base);
        if (errno != p->expected_errno) {
            failure_count++;
            printf("test %d (input \"%s\"): expected errno %d"
                   ", libc strtoull() returned errno %d\n",
                   i, p->nptr, p->expected_errno, errno);
        }
        if (result != p->expected_result) {
            failure_count++;
            printf("test %d (input \"%s\"): expected result %" PRIu64
                   ", libc strtoull() returned result %" PRIu64 "\n",
                   i, p->nptr, p->expected_result, result);
        }
        if (endptr - p->nptr != p->expected_end) {
            failure_count++;
            printf("test %d (input \"%s\"): expected end %d,"
                   " libc strtoull() returned end %d\n",
                   i, p->nptr, p->expected_end, (int) (endptr - p->nptr));
        }
#endif
    }
    if (failure_count == 0)
        printf("All %d tests passed.\n", i);
    return 0;
}

#endif /* defined(STRTOULL_UNIT_TEST) */

/*
 * Local variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * compile-command: "gcc -Wall -Werror -DSTRTOULL_UNIT_TEST=1 -I../include -g -o strtoull-unit-test strtoull.c && ./strtoull-unit-test"
 * End:
 */
