// 
#include<vector>
#include<string>

#include"fdwrap.h"

/**
 *
 */
std::string
FDWrap::read(size_t m)
{
	ssize_t n;
	std::vector<char> buf(m);
	n = ::read(fd, &buf[0], m);
	if (n < 0) {
		throw ErrBase("read");
	}
	return std::string(&buf[0], &buf[n]);
}

/**
 *
 */
size_t
FDWrap::write(const std::string &data)
{
	ssize_t n;
	n = ::write(fd, data.data(), data.length());
	if (n < 0) {
		throw ErrBase("write");
	}
	if (!n) {
		throw ErrEOF();
	}
	return n;
}

/**
 *
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
