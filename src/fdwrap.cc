// 
#include<vector>
#include<string>

#include"fdwrap.h"

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

size_t
FDWrap::write(const std::string &data)
{
	ssize_t n;
	n = ::write(fd, data.data(), data.length());
	if (n < 0) {
		throw ErrBase("write");
	}
	return n;
}
