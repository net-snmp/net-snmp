/*
 *  Host Resources MIB - utility functions interface - hr_utils.h
 *
 */

extern u_char * date_n_time __P(( time_t* when, int* length ));
extern time_t ctime_to_timet __P(( char* string ));
