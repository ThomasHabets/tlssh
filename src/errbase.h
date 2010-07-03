// -*- c++ -*-
#include<errno.h>
#include<string.h>

#include<string>
#include<sstream>
#include<vector>
#include<exception>

#define THROW(a, ...) throw a(__FILE__, __LINE__, __VA_ARGS__)

namespace Err {
	class ErrBase: public std::exception {
        protected:
		std::string file;
		int line;
		std::string msg;
		std::string verbose;
        public:
		ErrBase(const std::string &file,
			int line,
			const std::string &msg)
			:file(file),line(line),msg(msg)
		{
			std::stringstream s;
			s << line;
			verbose = file + ":" + s.str() + ": a" + msg;
		}
		virtual ~ErrBase()throw() {}
		virtual const char *what() const throw()
		{
			return msg.c_str();
		}
		virtual const char* what_verbose() const throw()
		{
			return verbose.c_str();
		}
	};
        class ErrSys: public ErrBase {
                std::string errstr;
                int serrno;
        public:
                ErrSys(const std::string &f,
                       int l,
                       const std::string &m)
                        :ErrBase(f,l,m)
                {
                        serrno = errno;
                        errstr = strerror(errno);
                        msg += " :" + errstr;
                }
                virtual ~ErrSys()throw() {}
};
};
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
