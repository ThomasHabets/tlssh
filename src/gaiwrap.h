// -*- c++ -*-
// tlssh/src/gaiwrap.cc
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

/**
 *
 */
class GetAddrInfo {
	struct addrinfo *addrs;
public:
	class ErrBase: public std::exception {
		const std::string msg;
	public:
		ErrBase(const std::string &m): msg(m) {}
		~ErrBase() throw() {}
	};
	GetAddrInfo(const std::string &host,
		    const std::string &port,
		    const struct addrinfo *hints);
	~GetAddrInfo();

	struct addrinfo *fixme() { return addrs; }
};

/**
 *
 */
GetAddrInfo::~GetAddrInfo()
{
	if (addrs) {
		freeaddrinfo(addrs);
	}
	addrs = 0;
}

/**
 *
 */
GetAddrInfo::GetAddrInfo(const std::string &host,
			 const std::string &port,
			 const struct addrinfo *hints)
	:addrs(0)
{
	int gerr;
	gerr = getaddrinfo(host.empty() ? NULL : host.c_str(),
			   port.c_str(),
			   hints,
			   &addrs);
	if (gerr) {
		throw ErrBase("getaddrinfo");
	}
}

/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
