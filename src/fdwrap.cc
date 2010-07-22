/**
 * \file src/fdwrap.cc
 * File descriptor wrapper
 */
#include<vector>
#include<string>

#include"fdwrap.h"

/**
 * read at most 'm' bytes from fd
 *
 * @param[in] m   Max bytes to read
 *
 * @return Data read. At least 1 byte.
 *
 * On error or EOF, throws exception
 */
std::string
FDWrap::read(size_t m)
{
	ssize_t n;
	std::vector<char> buf(m);
	n = ::read(fd, &buf[0], m);
	if (n < 0) {
		THROW(ErrBase, "read()");
	}
	if (!n) {
		THROW0(ErrEOF);
	}
	return std::string(&buf[0], &buf[n]);
}

/**
 * try to write some data
 *
 * @param[in] data  Data to be written
 *
 * @return Number of bytes written. May be 0.
 *
 * On error, throws exception.
 */
size_t
FDWrap::write(const std::string &data)
{
	ssize_t n;
	n = ::write(fd, data.data(), data.length());
	if (n < 0) {
		THROW(ErrBase, "write()");
	}
	return n;
}

/**
 * write some data. all of it. Keep retrying until it's all written.
 *
 * @param[in] data to be written
 *
 * On error, throws exception.
 */
void
FDWrap::full_write(const std::string &data)
{
        size_t n;
        for (n = 0; n < data.size();) {
                n += write(data.substr(n));
        }
}

/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
