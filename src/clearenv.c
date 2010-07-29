/**
 * @file src/clearenv.c
 * clearenv() function doesn't exist everywhere since it's not in POSIX.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

static const int ISO_C_forbids_an_empty_source_file = 1;

#ifndef HAVE_CLEARENV

#include<stdio.h>
#include<string.h>

extern char **environ;

/** Unset all environment variables
 *
 * OpenBSD doesn't seem to handle environ == NULL, so that's not an
 * option.
 *
 * So we'll do it the hard way.
 *
 * Go through all environment variables and unset them. Ignore (skip)
 * all environ entries what have no equal sign (because then we can't
 * know what the name part is.
 *
 * @return 0 on success, non-zero on error
 */
int
clearenv(void)
{
        int n = 0;  /* iterator while going through environ */
        char *p;    /* temporary buffer */
        char *pe;   /* pointer to the equal sign in temporary buffer */

        if (!environ) {
                return 0;
        }

        while (environ[n] && *environ[n]) {
                p = strdup(environ[n]);
                if (!p) {
                        return 1;
                }

                pe = index(p, '=');
                if (pe) {
                        *pe = 0;
                        unsetenv(p);
                        n = 0;
                } else {
                        n++;
                }
                free(p);
        }
	return 0;
}

#endif

/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
