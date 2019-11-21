tlssh/README

  By Thomas Habets <thomas@habets.se> 2010-2019


# What is it?
It's like SSH but based on TLS. And you only log in using client
certificates, never usernames or passwords.


# Why?
I often find that OpenSSH is too big, has too many features that can
subvert security. Yet it doesn't have the features that I want.

I wanted a minimal crypto layer on top of the SSL crypto model.


# Compared to OpenSSH
Pros:
* TCP-MD5
* Write contents of local file as if I typed it (not done yet, but
  OpenSSH don't want it)
* xmodem file xfer (not done yet)
* TLS is the only manner of authentication = only thing security
  depends on (besides kernel, firmware and hardware that are all out of scope)
* CA model. Server can have VeriSign signed server cert.
* Expiring & revoking keys (OpenSSH certificates have this now)
* Can store private keys in TPM.

Cons:
* Less portable
* Less tested
* Less audited
* Fewer features (channels, etc). This is on purpose.
* Requires CA
* SSL data structs are pure madness, odds of OpenSSL being perfect
  when parsing them is less than 100%


# Where can I get it?
http://github.com/ThomasHabets/tlssh
`git clone git://github.com/ThomasHabets/tlssh.git`


# Installing
See the `INSTALL.md` file.


# Notes
* Support for TCP MD5 in Linux is always on since 2.6.27
* Cacert.org Class 1 CRL: http://crl.cacert.org/revoke.crl
* Telnet protocol RFC: http://www.faqs.org/rfcs/rfc854.html


--------------------------------------------------------------------------
Send questions/suggestions/patches/rants/0days to synscan@googlegroups.com
