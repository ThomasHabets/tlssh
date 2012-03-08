#include "sslsocket.h"

unsigned long
SSLSocket::threadid_callback()
{
        return (unsigned long)&errno;
}

/**
 *
 */
void
SSLSocket::locking_callback(int mode, int n, const char *file, int line)
{
}

/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
