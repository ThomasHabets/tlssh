/* -*- c++ -*- */
// tlssh/src/socket.h
#include<errno.h>

#include<exception>
#include<string>

#include"fdwrap.h"
#include"errbase.h"

/**
 *
 */
class Socket {
protected:
	FDWrap fd;
	bool debug;
        std::string tcpmd5;
	void create_socket(const struct addrinfo*);
public:
	class ErrBase: public Err::ErrBase {
	public:
		ErrBase(const Err::ErrData &errdata,
                        const std::string &m
                        ):Err::ErrBase(errdata,m){}
		virtual ~ErrBase() throw() {}
	};
	class ErrSys: public ErrBase {
                int myerrno;
	public:
		ErrSys(const Err::ErrData &errdata,
                       const std::string &m)
                        :ErrBase(errdata, m)
                {
                        myerrno = errno;
                        msg += std::string(": ") + strerror(myerrno);
                }
	};
	class ErrPeerClosed: public ErrBase {
	public:
		ErrPeerClosed(const Err::ErrData &errdata)
                        : ErrBase(errdata,"Peer closed") {}
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
	void set_reuseaddr(bool);

        void set_tcp_md5(const std::string &);
        void set_tcp_md5_sock();

	void listen_any(int af, const std::string &port);
	void connect(int af, const std::string &host, const std::string &port);

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
