// -*- c++ -*-
/**
 * @file src/tlssh.h
 * TLSSH header file
 */
#define BEGIN_NAMESPACE(a) namespace a {
#define END_NAMESPACE(a) }
#define BEGIN_LOCAL_NAMESPACE() namespace {
#define END_LOCAL_NAMESPACE() }

#include"fdwrap.h"
#include"errbase.h"

BEGIN_NAMESPACE(tlssh_common)

void print_copying();
void print_version();

#pragma pack(1)
/**
 * Interpret As Command
 *
 * Inline commands structure. For now only "change window size".
 */
typedef union {
        struct {
                uint8_t iac;
                uint8_t command;
                union {
                        struct {
                                uint16_t cols;
                                uint16_t rows;
                        } ws;
                        char terminal[32];
                } commands;
        } s;
        char buf[];
} IACCommand;
#pragma pack()

END_NAMESPACE(tlssh_common)

BEGIN_NAMESPACE(tlsshd)
/**
 * TLSSHD Daemon options
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
