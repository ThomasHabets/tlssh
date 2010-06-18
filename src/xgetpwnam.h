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
