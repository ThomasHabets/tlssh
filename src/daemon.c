#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include<unistd.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>

static const int ISO_C_forbids_an_empty_source_file = 1;

#ifndef HAVE_DAEMON

/**
 *
 */
int
daemon(int nochdir, int noclose)
{
	pid_t pid;
	int fd;

	fd = open("/dev/null", O_RDWR);
	if (fd < 0) {
		return -1;
	}

	pid = fork();
	switch (pid) {
	case -1:
		return -1;
	case 0:
		break;
	default:
		_exit(2);
	}

	if (!nochdir) {
		chdir("/");
	}

	if (!noclose) {
		close(0);
		close(1);
		close(2);
		dup2(fd, 0);
		dup2(fd, 1);
		dup2(fd, 2);
		close(fd);
	}
	setsid();
}


/**
 * Local Variables:
 * mode: c
 * c-basic-offset: 2
 * fill-column: 79
 * End:
 */

#endif
