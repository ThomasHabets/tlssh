// -*- c++ -*-
/**
 * @file src/xgetpwnam.c
 * Portable getpwnam_r()
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "xgetpwnam.h"

/** portable xgetpwnam_r()
 *
 * There are two getpwnam_r() implementations. POSIX and DRAFT. This wrapper
 * presents POSIX no matter what the backend is.
 * POSIX: Linux
 * DRAFT: Solaris
 */
int
xgetpwnam_r(const char *name, struct passwd *pwbuf,
            char *buf, size_t buflen, struct passwd **pwbufp)
{
#ifdef HAVE_GETPW_R_POSIX
        return getpwnam_r(name, pwbuf, buf, buflen, pwbufp);
#elif defined(HAVE_GETPW_R_DRAFT)
        int ret;
        *pwbufp = 0;
        ret = !getpwnam_r(name, pwbuf, buf, buflen);
        if (!ret) {
                *pwbufp = pwbuf;
        }
        return ret;
#else
#error "System doesn't seem to have getpwnam_r(). Not POSIX nor DRAFT."
#endif
}
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
