// -*- c++ -*-
/**
 * @file src/util.h
 * Random utility functions
 */
#include<pwd.h>
#include<sys/types.h>

#include<string>
#include<vector>

#define FINALLY(a,b) try { a } catch(...) { b; throw; }

struct passwd xgetpwnam(const std::string &name, std::vector<char> &buffer);
std::string xwordexp(const std::string &in);
std::vector<std::string> tokenize(const std::string &s);
std::string trim(const std::string &str);

#ifndef HAVE_BASENAME
char *basename (const char *filename);
#endif


extern "C" {
#ifndef HAVE_CFMAKERAW
        void cfmakeraw(struct temios *termios_p);
#endif
#ifndef HAVE_CFMAKERAW
        pid_t forkpty(int *amaster, char *name, struct termios *termp,
                      struct winsize *winp);
#endif
#ifndef HAVE_SETRESUID
        int setresuid(uid_t ruid, uid_t euid, uid_t suid);
#endif
#ifndef HAVE_SETRESGID
        int setresgid(gid_t rgid, gid_t egid, gid_t sgid);
#endif

#ifndef HAVE_CLEARENV
        int clearenv(void);
#endif
#ifndef HAVE_LOGWTMP
        void logwtmp(const char *line, const char *name, const char *host);
#endif

};

/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
