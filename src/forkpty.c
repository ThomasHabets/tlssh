#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

static const int ISO_C_forbids_an_empty_source_file = 1;

#ifndef HAVE_FORKPTY

#ifdef HAVE_PTY_H
#include<pty.h>
#endif

pid_t
forkpty(int *amaster, char *name, struct termios *termp,
	struct winsize *winp)
{
  int aslave;
  pid_t pid;

  if (openpty(amaster, aslave, name, termp, winp)) {
    goto errout;
  }

  pid = fork(0);

  if (pid < 0) {
    goto errout_fork;
  }

  if (!pid) {
    close(*amaster);
    if (login_tty(aslave)) {
      _exit(1);
    }
  } else {
    close(aslave);
  }

  return pid;

 errout_fork:
  close(*amaster);
  close(aslave);
 errout:
  return -1;
}
/**
 * Local Variables:
 * mode: c
 * c-basic-offset: 2
 * fill-column: 79
 * End:
 */

#endif
