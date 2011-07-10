// -*- c++ -*-
/**
 * \file src/fdwrap.h
 * File descriptor wrapper
 */
#ifndef __INCLUDE_FDWRAP_H__
#define __INCLUDE_FDWRAP_H__

#include<unistd.h>
#include<exception>
#include<string>

#include"errbase.h"

/**
 * Wrap file descriptor in a class
 */
class FDWrap {
	int fd;
        bool autoclose;
public:
	FDWrap(int fd = -1, bool autoclose = true)
		:fd(fd),autoclose(autoclose)
	{
	}
	~FDWrap()
	{
                if (autoclose) {
                        close();
                }
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

	void set(int n)
	{
		close();
		fd = n;
	}
	int forget()
	{
                int ret = fd;
		fd = -1;
                return ret;
	}

	bool valid()
	{
		return fd != -1;
	}

        void set_close_on_exec(bool);

        /**
         * Exception base class
         */
	class ErrBase: public Err::ErrBase {
	public:
		ErrBase(const Err::ErrData &e, const std::string &s)
                        :Err::ErrBase(e, s) {}
		virtual ~ErrBase() throw() {}
	};

        /**
         * Exception for end of file
         */
	class ErrEOF: public ErrBase {
	public:
		ErrEOF(const Err::ErrData &e): ErrBase(e, "EOF") {}
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
