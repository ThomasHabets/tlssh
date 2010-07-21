/**
 * @file src/util.cc
 * Random utility functions
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include<stdio.h>
#include<wordexp.h>

#include"mywordexp.h"
#include"util.h"
#include"xgetpwnam.h"
#include"errbase.h"

SysLogger::SysLogger(const std::string &inid, int fac)
        :id(inid)
{
        set_logmask(::setlogmask(0));
        openlog(id.c_str(), LOG_CONS | LOG_NDELAY | LOG_PID, fac);
}

void
Logger::copyterminal(int prio, const char *fmt, va_list ap) const
{
        va_list ap2;
        if (!flag_copyterminal) {
                return;
        }
        va_copy(ap2,ap);
        vfprintf(stderr, fmt, ap); // BUG HERE
        fprintf(stderr, "\n");
}

StreamLogger::StreamLogger(std::ostream &os, const std::string timestring)
        :os(os),
         timestring(timestring)
{
        os << "starting logging..." << std::endl;
}

void
StreamLogger::vlog(int prio, const char *fmt, va_list ap) const
{
        char tbuf[1024];
        struct tm tm;
        time_t t;
        time(&t);
        localtime_r(&t, &tm);
        if (!strftime(tbuf, sizeof(tbuf),
                      timestring.c_str(), &tm)) {
                strcpy(tbuf, "0000-00-00 00:00:00 UTC ");
        }
        os << tbuf << fmt << std::endl;
}


/**
 *
 */
std::string
xwordexp(const std::string &in)
{
	wordexp_t p;
        std::string ret;

	if (wordexp(in.c_str(), &p, 0)) {
		THROW(Err::ErrBase, "wordexp(" + in + ")");
	}

	if (p.we_wordc != 1) {
                wordfree(&p);
		THROW(Err::ErrBase, "wordexp(" + in + ") nmatch != 1");
	}
        try {
                ret = p.we_wordv[0];
        } catch(...) {
                wordfree(&p);
                throw;
        }
        wordfree(&p);
	return ret;
}

/**
 * FIXME: handle doublequotes
 */
std::vector<std::string>
tokenize(const std::string &s)
{
	std::vector<std::string> ret;
	size_t end;
	size_t start = 0;

	for (;;) {
		// find beginning of word
		start = s.find_first_not_of(" \t", start);
		if (std::string::npos == start) {
			return ret;
		}

		// find end of word
		end = s.find_first_of(" \t", start);
		if (std::string::npos == end) {
			ret.push_back(s.substr(start));
			break;
		}
		ret.push_back(trim(s.substr(start, end-start)));
		start = end;
	}
	return ret;
}

/**
 *
 */
std::string
trim(const std::string &str)
{
	size_t startpos = str.find_first_not_of(" \t");
	if (std::string::npos == startpos) {
		return "";
	}

	size_t endpos = str.find_last_not_of(" \t");

	return str.substr(startpos, endpos-startpos+1);
}

/**
 *
 */
struct passwd
xgetpwnam(const std::string &name, std::vector<char> &buffer)
{
	buffer.reserve(1024);
	struct passwd pw;
	struct passwd *ppw = 0;
	if (xgetpwnam_r(name.c_str(), &pw, &buffer[0], buffer.capacity(), &ppw)
	    || !ppw) {
                // don't throw the name. It may be a password written
                // as a name by mistake
		THROW(Err::ErrBase, "xgetpwnam()");
	}

	return pw;
}

char*
gnustyle_basename(const char *fn)
{
        char *p = strrchr(fn, '/');
        return p ? p + 1 : (char *)fn;
}

/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
