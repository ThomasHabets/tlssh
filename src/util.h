// -*- c++ -*-
// tlssh/src/util.h

#include<pwd.h>
#include<sys/types.h>

#include<string>
#include<vector>

struct passwd xgetpwnam(const std::string &name, std::vector<char> &buffer);
std::string xwordexp(const std::string &in);
std::vector<std::string> tokenize(const std::string &s);
std::string trim(const std::string &str);

/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
