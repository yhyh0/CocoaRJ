/* This file comes from APUE, slightly edited by NetXRay@byhh */

#ifndef MYERR_H
#define MYERR_H

#include	<stdio.h>
#include	<stdlib.h>
#include 	<string.h>
#include	<errno.h> 	/* for definition of errno */
#include	<stdarg.h>		/* ANSI C header file */

void	err_dump(const char *, ...);
void	err_msg(const char *, ...);
void	err_quit(const char *, ...);
void	err_ret(const char *, ...);
void	err_sys(const char *, ...);

#endif /* MYERR_H*/
