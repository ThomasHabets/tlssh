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

/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
