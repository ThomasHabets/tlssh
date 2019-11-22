tlssh/INSTALL


# Dependencies
openssl 1.1+

On Debian: `apt-get install libssl-dev`


# Installing - short version

```
./configure
make
make install
mkdir /etc/tlssh
```

Put client-signing CA cert (cert, not private key) in `/etc/tlssh/ClientCA.crt`.

Install server cert in `/etc/tlssh/tlsshd.key` and `/etc/tlssh/tlssd.crt`.

```
/usr/local/sbin/tlsshd
```

# Creating certs

Easiest is to use `easy-rsa`.
```
easy-rsa init-pki
easy-rsa build-ca
easy-rsa build-server-full shell.example.com nopass
easy-rsa build-client-full thomas.clients.examle.com
```

## Real server cert

```
openssl req -nodes -newkey rsa:2048 -keyout tlsshd.key -out tlsshd.csr
```

Send `tlsshd.csr` (NOT `tlsshd.key`) to your CA to have it signed. You will get
back `tlsshd.crt`.

Put `tlsshd.key` and tlsshd.crt in `/etc/tlssh/`.

# Configuring

## Configure server

```
cp pki/issued/shell.example.com.crt /etc/tlssh/tlsshd.crt
cp pki/private/shell.example.com.key /etc/tlssh/tlsshd.key
cp pki/ca.crt /etc/tlssh/ClientCA.crt
echo ClientDomain client.example.com >> /etc/tlssh/tlsshd.conf
```

## Configure client

```
mkdir ~/.tlssh/keys
cp pki/issued/shell.example.com.crt ~/.tlssh/keys/default.crt
cp pki/private/shell.example.com.key ~/.tlssh/keys/default.key
cp pki/ca.crt /etc/tlssh/ServerCA.crt    # Unless you use a real server cert.
```

# Hints for compiling on different systems

YMMV. Feedback is welcome.

Solaris:

```
./configure LDFLAGS="-L/opt/csw/lib -R/opt/csw/lib" \
            CPPFLAGS="-I/opt/csw/include"
```


--------------------------------------------------------------------------
Send questions/suggestions/patches/rants/0days to synscan@googlegroups.com
