#ifndef _GETOPT_H_
#define _GETOPT_H_ 1

extern int getopt(int, char *const *, const char *);
extern char *optarg;
extern int optind, opterr, optopt, optreset;

#endif
