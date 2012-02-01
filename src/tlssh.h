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
#include<sys/types.h>
#include<sys/socket.h>

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

const std::string DEFAULT_LISTEN       = "::";
const std::string DEFAULT_PORT         = "12345";
const std::string DEFAULT_CERTFILE     = "/etc/tlssh/tlsshd.crt";
const std::string DEFAULT_KEYFILE      = "/etc/tlssh/tlsshd.key";
const std::string DEFAULT_CLIENTCAFILE = "/etc/tlssh/ClientCA.crt";
const std::string DEFAULT_CLIENTCRL    = "";
const std::string DEFAULT_CLIENTCAPATH = "";
const std::string DEFAULT_CLIENTDOMAIN = "";
const std::string DEFAULT_CONFIG       = "/etc/tlssh/tlsshd.conf";
const std::string DEFAULT_CIPHER_LIST  = "HIGH:!ADH:!LOW:!MD5:@STRENGTH";
const std::string DEFAULT_TCP_MD5      = "tlssh";
const std::string DEFAULT_CHROOT       = "/var/empty";
const unsigned    DEFAULT_VERBOSE      = 0;
const bool        DEFAULT_DAEMON       = true;
const int         DEFAULT_AF           = AF_UNSPEC;
const uint32_t    DEFAULT_KEEPALIVE    = 60;

/**
 * TLSSH server options
 */
struct Options {
        typedef std::pair<bool, std::string> Optional;

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
        Optional privkey_engine;
        Optional privkey_password;
        Optional tpm_srk_password;
        int verbose;
        bool daemon;
        int af;
        uint32_t keepalive;

        Options()
                : listen(         DEFAULT_LISTEN),
                  port(           DEFAULT_PORT),
                  certfile(       DEFAULT_CERTFILE),
                  keyfile(        DEFAULT_KEYFILE),
                  clientcafile(   DEFAULT_CLIENTCAFILE),
                  clientcrl(      DEFAULT_CLIENTCRL),
                  clientcapath(   DEFAULT_CLIENTCAPATH),
                  clientdomain(   DEFAULT_CLIENTDOMAIN),
                  config(         DEFAULT_CONFIG),
                  cipher_list(    DEFAULT_CIPHER_LIST),
                  tcp_md5(        DEFAULT_TCP_MD5),
                  chroot(         DEFAULT_CHROOT),
                  privkey_engine(std::make_pair(false, "")),
                  privkey_password(std::make_pair(false, "")),
                  tpm_srk_password(std::make_pair(false, "")),
                  verbose(        DEFAULT_VERBOSE),
                  daemon(         DEFAULT_DAEMON),
                  af(             DEFAULT_AF),
                  keepalive(      DEFAULT_KEEPALIVE)
        {
        }


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
