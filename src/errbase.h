// -*- c++ -*-
/**
 * \file src/errbase.h
 * Base exception classes
 */
#ifndef __INCLUDE_ERRBASE_H__
#define __INCLUDE_ERRBASE_H__

#include<errno.h>
#include<string.h>

#include<string>
#include<sstream>
#include<vector>
#include<exception>

#if 0
// FIXME: handle the case that there is no __PRETTY_FUNCTION__
//#define __PRETTY_FUNCTION__ __func__
#endif

#define THROW_MKERR Err::ErrData(__FILE__, \
                                 __LINE__, \
                                 __func__, \
                                 __PRETTY_FUNCTION__)
#define THROW0(a)     throw a(THROW_MKERR)
#define THROW(a, ...) throw a(THROW_MKERR, __VA_ARGS__)

/** Base exception classes
 */
namespace Err {
        /**
         * Extra error information provided by THROW macro.
         */
        struct ErrData {
                std::string file;
                std::string func;
                std::string prettyfunc;
                int line;
                ErrData(const std::string &file,
                        int line,
                        const std::string &func,
                        const std::string &prettyfunc
                        )
                        :file(file),
                         func(func),
                         prettyfunc(prettyfunc),
                         line(line)
                {
                }
        };

        /**
         * Base class for all exceptions
         */
	class ErrBase: public std::exception {
        protected:
                const ErrData errdata;
		std::string msg;
		std::string verbose;
        public:
		ErrBase(const ErrData &errdata,
			const std::string &msg)
			:errdata(errdata),msg(msg)
		{
			std::stringstream s;
			s << errdata.line;
			verbose = errdata.file + ":" + s.str() + "("
                                + errdata.prettyfunc + "): " + msg;
		}
		virtual ~ErrBase() throw() {}
		virtual const char *what() const throw()
		{
			return msg.c_str();
		}
		virtual std::string what_verbose() const throw()
		{
			return verbose;
		}
	};

        /**
         * System call errors
         */
        class ErrSys: public ErrBase {
                std::string errstr;
                int serrno;
        public:
                ErrSys(const ErrData &errdata,
                       const std::string &m)
                        :ErrBase(errdata, m)
                {
                        serrno = errno;
                        errstr = strerror(errno);
                        msg += " :" + errstr;
                }
                virtual ~ErrSys()throw() {}
        };
}
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
#endif
