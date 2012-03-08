#include<mutex>

#include<openssl/crypto.h>

#include "sslsocket.h"

namespace {
  std::mutex locking_func_lock;
}

/**
 * FIXME: this assumes that a pointer cast to unsigned long is unique
 * enough.
 */
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
        static std::mutex *locks = NULL;

        locking_func_lock.lock();
        if (!locks) {
                locks = new std::mutex[CRYPTO_num_locks()];
        }
        locking_func_lock.unlock();

        if (mode & CRYPTO_LOCK) {
                locks[n].lock();
        } else {
                locks[n].unlock();
        }
}

/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
