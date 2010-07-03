/* -*- c++ -*- */
// tlssh/src/socket.h
#include<errno.h>

#include<exception>
#include<string>
#include"fdwrap.h"

/**
 *
 */
class Socket {
protected:
	FDWrap fd;
	bool debug;
        std::string tcpmd5;
	int create_socket(const struct addrinfo*);
public:
	class ErrBase: public std::exception {
	protected:
		std::string msg;
	public:
		ErrBase(const std::string &s):msg(s){}
		~ErrBase() throw() {}
		const char *what() const throw() { return msg.c_str(); }
	};
	class ErrSys: public ErrBase {
                int myerrno;
	public:
		ErrSys(const std::string &s)
                        :ErrBase(s)
                {
                        myerrno = errno;
                        msg += std::string(": ") + strerror(myerrno);
                }
	};
	class ErrPeerClosed: public ErrBase {
	public:
		ErrPeerClosed():ErrBase("Peer closed"){}
	};

	Socket(int infd = -1);
	virtual ~Socket();

	void set_debug(bool v) {debug = v;}
	bool get_debug() const { return debug; }

	int getfd() const;
	void forget(); 
        void close();

        void set_nodelay(bool);
        void set_keepalive(bool);

        void set_tcp_md5(const std::string &);
        void set_tcp_md5_sock();

	int setsockopt_reuseaddr();
	int listen_any(int port); /* FIXME: change to string and GAI */
	void connect(const std::string &host, const std::string &port);

	virtual std::string read(size_t m = 4096);
	virtual size_t write(const std::string &);

        void full_write(const std::string &);
};

/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
