/**
 * @file src/forkpty.c
 * forkpty() for OSs that don't have it.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

static const int ISO_C_forbids_an_empty_source_file = 1;

#ifndef HAVE_FORKPTY

#ifdef HAVE_PTY_H
#include<pty.h>
#endif

#include<stdlib.h>
#include<unistd.h>
#include<termios.h>

#include"login_tty.h"

/**
 * fork() a child that has a newly connected terminal pair as controlling
 * terminal.
 *
 * Both parent and child of fork() returns.
 *
 * @param[in] amaster   In parent process, this is the master side of the tty
 * @param[in] name      Store name of new tty here (done by openpty())
 * @param[in] termp     Initial terminal settings for tty (openpty() again)
 * @param[in] winp      Initial terminal window size (openpty())
 */
pid_t
forkpty(int *amaster, char *name, struct termios *termp,
	struct winsize *winp)
{
  int aslave;
  pid_t pid;

  if (openpty(amaster, &aslave, name, termp, winp)) {
    goto errout;
  }

  pid = fork();

  if (pid < 0) {
    goto errout_fork;
  }

  if (!pid) {
    //close(*amaster); // FIXME: this isn't needed, or even correct, is it?
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
