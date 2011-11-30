#include"gaiwrap.h"

/**
 * Clean up getaddrinfo() struct
 */
GetAddrInfo::~GetAddrInfo()
{
	if (addrs) {
		freeaddrinfo(addrs);
	}
	addrs = 0;
}

/**
 * Create GetAddrInfo object to resolve host or address
 *
 * @param[in] host Hostname or address
 * @param[in] port Port name or number
 * @param[in] hints Hints of address family and somesuch
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
