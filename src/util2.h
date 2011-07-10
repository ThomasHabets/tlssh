// -*- c++ -*-
/**
 * @file src/util2.h
 * Random utility functions
 */
#ifndef __INCLUDE_UTIL_H__
#define __INCLUDE_UTIL_H__


#include<pwd.h>
#include<sys/types.h>

#include<string>
#include<vector>
#include<list>
#include<fstream>

#define FINALLY(a,b) try { a } catch(...) { b; throw; } b;

#include<stdarg.h>
#include<syslog.h>
#include<iostream>
#include<time.h>
#include<limits.h>

#define LOGGER_H_LOGLEVEL(n,v) void \
n(const char *fmt, ...) const \
{ \
	va_list ap; \
	va_start(ap, fmt); \
	vlog(v, fmt, ap); \
	va_end(ap); \
}

#ifndef LOG_AUTHPRIV
#define LOG_AUTHPRIV LOG_AUTH
#endif

/**
 * Abstract base logger class.
 @code
 Logger *log = new StreamLogger(std::cerr);
 log.warning("Hello %s", "World");
 @endcode
 */
class Logger {
private:
	Logger(const Logger&);
	Logger&operator=(const Logger&);
        int logmask;

        typedef std::pair<Logger*, bool> attached_entry_t;
        typedef std::list<attached_entry_t> attached_t;
        attached_t attached;

        static bool isOwner(const attached_entry_t &e) { return e.second; }
public:
        Logger():logmask(~0) {}
        virtual ~Logger();
	LOGGER_H_LOGLEVEL(emerg, LOG_EMERG);
	LOGGER_H_LOGLEVEL(alert, LOG_ALERT);
	LOGGER_H_LOGLEVEL(crit, LOG_CRIT);
	LOGGER_H_LOGLEVEL(err, LOG_ERR);
	LOGGER_H_LOGLEVEL(warning, LOG_WARNING);
	LOGGER_H_LOGLEVEL(notice, LOG_NOTICE);
	LOGGER_H_LOGLEVEL(info, LOG_INFO);
	LOGGER_H_LOGLEVEL(debug, LOG_DEBUG);

        void attach(Logger *, bool ownership=false);
        void detach(Logger *);
        void detach_all();

        virtual void set_logmask(int m) { logmask = m; }
        int get_logmask() const { return logmask; }

        void vlog(int prio, const char *fmt, va_list ap) const;
        virtual void log(int prio, const std::string &str) const = 0;
};

/** Logger class that logs to syslog
 *
 */
class SysLogger: public Logger {
        const std::string id;
public:
	SysLogger(const std::string &id, int fac);

	virtual ~SysLogger()
	{
		closelog();
	}

        void
        set_logmask(int m)
        {
                Logger::set_logmask(m);
                ::setlogmask(get_logmask());
        }

	void
	log(int prio, const std::string &str) const
	{
                syslog(prio, "%s", str.c_str());
	}
};

/** Logger class that logs to an std::ostream
 *
 */
class StreamLogger: public Logger {
	std::ostream &os;
	std::string timestring;
public:
	StreamLogger(std::ostream &os,
		     const std::string timestring = "%Y-%m-%d %H:%M:%S %Z ");

	void log(int prio, const std::string &str) const;
};

class FileLogger: public Logger {
        std::string filename;
        std::ofstream file;
        StreamLogger streamlogger;
public:
        FileLogger(const std::string &filename);
        void log(int prio, const std::string &str) const;
};

struct passwd xgetpwnam(const std::string &name, std::vector<char> &buffer);
std::string xwordexp(const std::string &in);
std::vector<std::string> tokenize(const std::string &s,
                                  size_t max_splits=INT_MAX);
std::string trim(const std::string &str);
std::string xsprintf(const char *fmt, ...);
std::string xvsprintf(const char *fmt, va_list ap);

char *gnustyle_basename(const char *filename);

extern "C" {
#ifndef HAVE_CFMAKERAW
        void cfmakeraw(struct termios *termios_p);
#endif
#ifndef HAVE_FORKPTY
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
#ifndef HAVE_DAEMON
        int daemon(int nochdir, int noclose);
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
#endif
