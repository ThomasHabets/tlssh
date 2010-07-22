/**
 * @file src/setresuid.c
 * Portable implementation of the Linux-specific setresuid
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <unistd.h>

#ifndef HAVE_SETRESUID
/**
 * Set all manner of uids to given values at the same time
 *
 * @param[in] ruid  Real uid
 * @param[in] euid  Effective uid
 * @param[in] suid  Saved uid
 *
 * @return 0 on success
 */
int
setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	return setuid(ruid);
}
#endif

#ifndef HAVE_SETRESGID
/**
 * Set all manner of gids to given values at the same time
 *
 * @param[in] rgid  Real gid
 * @param[in] egid  Effective gid
 * @param[in] sgid  Saved gid
 *
 * @return 0 on success
 */
int
setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
	return setgid(rgid);
}
#endif
