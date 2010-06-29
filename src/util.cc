#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include<wordexp.h>

#include"util.h"

std::string
xwordexp(const std::string &in)
{
	wordexp_t p;
	char **w;
	int i;

	if (wordexp(in.c_str(), &p, 0)) {
		throw "FIXME: wordexp()";
	}

	if (p.we_wordc != 1) {
		throw "FIXME: wordexp() nmatch != 1";
	}

	std::string ret(p.we_wordv[0]);
	wordfree(&p);
	return ret;
}

