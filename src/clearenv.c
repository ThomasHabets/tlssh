/**
 * @file src/clearenv.c
 * clearenv() function doesn't exist everywhere since it's not in POSIX.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

static const int ISO_C_forbids_an_empty_source_file = 1;

#ifndef HAVE_CLEARENV

/**
 * @todo Verify that this works, and that putenv() works after this is
 *       called. Method suggested by Linux clearenv(3) manpage.
 */
int
clearenv(void)
{
	environ = NULL;
}

#endif
