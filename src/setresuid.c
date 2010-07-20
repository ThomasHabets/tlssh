#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <unistd.h>

#ifndef HAVE_SETRESUID
int setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	return setuid(ruid);
}
#endif

#ifndef HAVE_SETRESGID
int setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
	return setgid(rgid);
}
#endif
