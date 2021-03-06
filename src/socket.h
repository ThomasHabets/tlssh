/* -*- c++ -*- */
/**
 * \file src/socket.h
 * Socket class
 */
#include<errno.h>

#include<exception>
#include<string>

#include"fdwrap.h"
#include"errbase.h"

/**
 * TCP Socket class
 @code
 Socket sock;
 sock.connect(AF_UNSPEC, "www.sunet.se", "www");
 sock.set_keepalive(true);
 @endcode
 @code
 Socket sock;
 sock.listen(AF_UNSPEC, "", "12345");
 FDWrap clifd;
 clifd.set(sock.accept());
 Socket newsock(clifd.getfd());
 clifd.forget();
 newsock.write("Hello World");
 @endcode
 */
class Socket {
protected:
	FDWrap fd;
        int connected_af_;
	bool debug;
        std::string tcpmd5;
	void create_socket(const struct addrinfo*);
public:
        /**
         * Base exception class for Socket
         */
	class ErrBase: public Err::ErrBase {
	public:
		ErrBase(const Err::ErrData &errdata,
                        const std::string &m
                        ):Err::ErrBase(errdata, m){}
		virtual ~ErrBase() throw() {}
	};
        /**
         * System call error
         */
	class ErrSys: public ErrBase {
                int myerrno;
	public:
		ErrSys(const Err::ErrData &errdata,
                       const std::string &m)
                        :ErrBase(errdata, m)
                {
                        myerrno = errno;
                        msg += std::string(": ") + strerror(myerrno);
                        verbose += std::string(": ") + strerror(myerrno);
                }
	};
        /**
         * Peer closed exception
         */
	class ErrPeerClosed: public ErrBase {
	public:
		ErrPeerClosed(const Err::ErrData &errdata)
                        : ErrBase(errdata,"Peer closed") {}
	};

	Socket(int infd = -1);
	virtual ~Socket() throw();

	void set_debug(bool v) {debug = v;}
	bool get_debug() const { return debug; }

	int getfd() const;
        void setfd(int) throw();
	void forget();
        void close();

        void set_nodelay(bool);
        void set_keepalive(bool);
	void set_reuseaddr(bool);
        void set_close_on_exec(bool);

        void set_tos(int tos);

        void set_tcp_md5(const std::string &);
        void set_tcp_md5_sock(const struct sockaddr *sa, socklen_t salen, bool fullmatch);

        std::string get_peer_addr_string() const;

        int accept();
	void listen(int af, const std::string &host, const std::string &port);
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
