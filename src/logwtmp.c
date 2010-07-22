/**
 * @file src/logwtmp.c
 * For systems that don't have logwtmp()
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

static const int ISO_C_forbids_an_empty_source_file = 1;

#ifndef HAVE_LOGWTMP

/**
 * log a utmp structure based on line, name and host
 *
 * @param[in] line  TTY that was logged into (eg pts/4)
 * @param[in] name  Name of user that logged in
 * @param[in] host  Where user logged in from
 *
 * @todo Implement me
 */
void
logwtmp(const char *line, const char *name, const char *host)
{
}

#endif
/**
 * Local Variables:
 * mode: c
 * c-basic-offset: 2
 * fill-column: 79
 * End:
 */
