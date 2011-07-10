// -*- c++ -*-
/**
 * @file src/tlssh.h
 * TLSSH client and server header file
 */
#define BEGIN_NAMESPACE(a) namespace a {
#define END_NAMESPACE(a) }
#define BEGIN_LOCAL_NAMESPACE() namespace {
#define END_LOCAL_NAMESPACE() }

#include<vector>
#include<string>
#include<inttypes.h>

#include"fdwrap.h"
#include"errbase.h"
#include"util2.h"


extern Logger *logger;

/***********************************************************************
 * common tlssh client and server part
 */
BEGIN_NAMESPACE(tlssh_common)

#pragma pack(1)
/**
 * Interpret As Command
 *
 */
enum {
        IAC_WINDOW_SIZE = 1,
        IAC_ECHO_REQUEST = 2,
        IAC_ECHO_REPLY = 3,
        IAC_LITERAL = 255,
};
typedef union {
        struct {
                uint8_t iac;
                uint8_t command;
                union {
                        struct {
                                uint16_t cols;
                                uint16_t rows;
                        } window_size;
                        uint32_t echo_cookie;
                } commands;
        } s;
        char buf[];
} IACCommand;
#pragma pack()

typedef std::pair<std::vector<IACCommand>,std::string> parsed_buffer_t;

void print_copying();
void print_version();
std::string iac_echo_reply(uint32_t cookie);
std::string iac_echo_request(uint32_t cookie);
parsed_buffer_t parse_iac(std::string &buffer);

extern const int iac_len[256];


END_NAMESPACE(tlssh_common)


/*************************************************************************
 * tlsshd server part
 */
BEGIN_NAMESPACE(tlsshd)
/**
 * TLSSH server options
 */
struct Options {
	std::string listen;
	std::string port;
	std::string certfile;
	std::string keyfile;
	std::string clientcafile;
	std::string clientcrl;
	std::string clientcapath;
	std::string clientdomain;
	std::string config;
	std::string cipher_list;
	std::string tcp_md5;
	std::string chroot;
        int verbose;
        bool daemon;
        int af;
        uint32_t keepalive;
};
extern Options options;
extern std::string protocol_version;
END_NAMESPACE(tlsshd)

BEGIN_NAMESPACE(tlsshd_shellproc)
int forkmain(const struct passwd *pw, int fd_control);
END_NAMESPACE(tlsshd_shellproc)

BEGIN_NAMESPACE(tlsshd_sslproc)
int forkmain(FDWrap&fd);
END_NAMESPACE(tlsshd_sslproc)


/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 */
