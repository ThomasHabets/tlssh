/**
 * @file src/cfmakeraw.c
 * cfmakeraw() for systems that don't have it
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef HAVE_CFMAKERAW
#include <termios.h>
#include <string.h>

/**
 * Set terminal (termios struct) to "raw" mode.
 * exact settings here taken from Linux manpage.
 */
void
cfmakeraw(struct termios *termios_p)
{
        memset(0, &termios_p, sizeof(struct termios));
        termios_p->c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP
                                | INLCR | IGNCR | ICRNL | IXON);
        termios_p->c_oflag &= ~OPOST;
        termios_p->c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
        termios_p->c_cflag &= ~(CSIZE | PARENB);
        termios_p->c_cflag |= CS8;
}

#endif

/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
