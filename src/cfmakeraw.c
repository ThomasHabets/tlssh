#include <termios.h>

#ifndef HAVE_CFMAKERAW
/**
 *
 */
void
cfmakeraw(struct termios *termios_p)
{
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
