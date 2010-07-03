// -*- c++ -*-

#ifndef __INCLUDE_FDWRAP_H__
#define __INCLUDE_FDWRAP_H__

#include<exception>
#include<string>

/**
 *
 */
class FDWrap {
	int fd;
public:
	FDWrap(int fd = -1)
		:fd(fd)
	{
	}
	~FDWrap()
	{
		close();
	}
	void close()
	{
		if (fd > 0) {
			::close(fd);
			forget();
		}
	}

	int get() const
	{
		return fd;
	}

	int set(int n)
	{
		close();
		fd = n;
	}
	void forget()
	{
		fd = -1;
	}

	bool valid()
	{
		return fd != -1;
	}

	class ErrBase: public std::exception {
		std::string msg;
	public:
		ErrBase(const std::string &e):msg(e){}
		~ErrBase() throw() {}
	};
	class ErrEOF: public ErrBase {
	public:
		ErrEOF(): ErrBase("EOF") {}
	};
	
	std::string read(size_t m = 4096);
	size_t write(const std::string &);
	void full_write(const std::string &);
};

/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
#endif
