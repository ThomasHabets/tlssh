// -*- c++ -*-
#define THROW(a, ...) throw a(__FILE__, __LINE__, __VA_ARGS__)
#include<string>
#include<sstream>
#include<vector>
#include<exception>

namespace Err {
	class ErrBase: public std::exception {
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
};
