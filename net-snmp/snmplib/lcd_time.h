/*
 * lcd_time.h
 */

#ifndef _LCD_TIME_H
#define _LCD_TIME_H



/*
 * Macros and definitions.
 */
typedef struct enginetime_struct {
	u_char		*engineID;
	u_int		 engineID_len;

	u_int		 engineTime;
	u_int		 engineBoot;

	struct timeval	 lastReceivedEngineTime;

	struct enginetime_struct	*next;
} enginetime, *Enginetime;



/*
 * Prototypes.
 */
int	get_enginetime __P((	u_char *engineID,	u_int engineID_len,
				u_int	*enginetime,	u_int *engineboot));


int	get_enginetime_byIP __P((
				struct in_addr engineIP,
				u_int   *enginetime,    u_int *engineboot));

		/* FIX	-- use sockaddr instead? */

int	set_enginetime __P((	u_char *engineID,	u_int engineID_len,
				u_int   enginetime,	u_int engineboot));

#endif /* _LCD_TIME_H */

