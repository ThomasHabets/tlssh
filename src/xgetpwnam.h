// -*- c++ -*-
/**
 * @file src/xgetpwnam.h
 * Portable getpwnam_r()
 */
#include <sys/types.h>
#include <pwd.h>

#ifdef __cplusplus
extern "C" {
#endif

int xgetpwnam_r(const char *name, struct passwd *pwbuf,
		char *buf, size_t buflen, struct passwd **pwbufp);

#ifdef __cplusplus
}
#endif
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
