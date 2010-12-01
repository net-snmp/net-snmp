#ifndef NETSNMP_LIBRARY_TESTING_H
#define NETSNMP_LIBRARY_TESTING_H

/* These are macros used for the net-snmp testing infrastructure; see
   the "testing" subdirectory of the source code for details. */

static int __test_counter = 0;
static int __did_plan = 0;

#define OK(isok, description) { printf("%s %d - %s\n", ((isok) ? "ok" : "not ok"), ++__test_counter, description); }

#define OKF(isok, description) { printf("%s %d - \n", ((isok) ? "ok" : "not ok"), ++__test_counter); printf description; printf("\n"); }

#define PLAN(number) { printf("1..%d\n", number); __did_plan = 1;}

#endif /* NETSNMP_LIBRARY_TESTING_H */
