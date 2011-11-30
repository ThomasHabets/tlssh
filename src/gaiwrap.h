// -*- c++ -*-
/**
 * @file src/gaiwrap.h
 * getaddrinfo() wrapper
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include<string>

/**
 * getaddrinfo() wrapper
 *
 @code
 struct addrinfo hints;
 memset(&hints, 0, sizeof(hints));
 GetAddrInfo gai("www.sunet.se", "www", &hints);
 // something something gai.fixme()
 @endcode
 *
 */
class GetAddrInfo {
	struct addrinfo *addrs;
        GetAddrInfo(const GetAddrInfo&);
        GetAddrInfo &operator=(const GetAddrInfo&);
public:
        /**
         * Exception base class. Not using Err::ErrBase because this file
         * is copied from project to project.
         */
	class ErrBase: public std::exception {
		const std::string msg;
	public:
		ErrBase(const std::string &m): msg(m) {}
		virtual ~ErrBase() throw() {}
		virtual const char *what() const throw()
		{
			return msg.c_str();
		}
	};
	GetAddrInfo(const std::string &host,
		    const std::string &port,
		    const struct addrinfo *hints);
	~GetAddrInfo();

	const struct addrinfo *get_results() const { return addrs; }
};
/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
