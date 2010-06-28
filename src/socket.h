/* -*- c++ -*- */
#include<exception>
#include<string>
#include "fdwrap.h"

class Socket {
protected:
	FDWrap fd;
	bool debug;

	int create_socket();
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
	public:
		ErrSys(const std::string &s):ErrBase(s){}
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

	int setsockopt_reuseaddr();
	int listen_any(int port); /* FIXME: change to string and GAI */
	void connect(const std::string &host, const std::string &port);

	virtual std::string read(size_t m = 4096);
	virtual size_t write(const std::string &);
};

