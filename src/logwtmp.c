#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

static const int ISO_C_forbids_an_empty_source_file = 1;

#ifndef HAVE_LOGWTMP
/**
 * Local Variables:
 * mode: c
 * c-basic-offset: 2
 * fill-column: 79
 * End:
 */
void
logwtmp(const char *line, const char *name, const char *host)
{
}

#endif
