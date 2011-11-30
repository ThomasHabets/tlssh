#include<sys/types.h>
#include<sys/socket.h>

#include<iostream>
#include<thread>

#include<gtest/gtest.h>

#include"util2.h"
#include"sslsocket.h"

Logger *logger = NULL;

class AutoJoin {
public:
  AutoJoin(std::thread *thread): thread_(thread) {}
  ~AutoJoin()
  {
    thread_->join();
  }
private:
  AutoJoin(const AutoJoin&);
  AutoJoin& operator=(const AutoJoin&);
  std::thread *thread_;
};


class SSLSocketTest: public ::testing::Test {
 protected:
  SSLSocket sc_, sl_;
  void connect_tcp()
  {
    sl_.listen(AF_UNSPEC, "", "12345");
    sc_.connect(AF_UNSPEC, "localhost", "12345");
  }

  void set_certs(SSLSocket&ss)
  {
    ss.ssl_set_cafile("testdata/client.crt");
    ss.ssl_set_certfile("testdata/server.crt");
    ss.ssl_set_keyfile("testdata/server.key");

    sc_.ssl_set_cafile("testdata/server.crt");
    sc_.ssl_set_certfile("testdata/client.crt");
    sc_.ssl_set_keyfile("testdata/client.key");
  }


 public:
  SSLSocketTest()
  {
    logger = new StreamLogger(std::cerr);
    sc_.set_debug(true);
    sl_.set_debug(true);
  }
  ~SSLSocketTest()
  {
    delete logger;
  }


  void client_loopdata()
  {
    try {
      sc_.ssl_connect("localhost");
      sc_.write("OK " + sc_.read());
    } catch (...) {
    }
  }
  void client_handshake()
  {
    try {
      sc_.ssl_connect("localhost");
    } catch (...) {
    }
  }
};

TEST_F(SSLSocketTest, Listen)
{
  SSLSocket sock;
  sock.listen(AF_UNSPEC, "", "12345");
}

TEST_F(SSLSocketTest, ReadBeforeAnything)
{
  SSLSocket sock;
  EXPECT_THROW(sock.read(), SSLSocket::ErrSSL);
}

TEST_F(SSLSocketTest, WriteBeforeAnything)
{
  SSLSocket sock;
  EXPECT_THROW(sock.write("foo"), SSLSocket::ErrSSL);
}

TEST_F(SSLSocketTest, WriteBeforeAccept)
{
  connect_tcp();
  EXPECT_THROW(sc_.write("x"), SSLSocket::ErrSSL);
}

TEST_F(SSLSocketTest, WriteBeforeHandshake)
{
  connect_tcp();

  SSLSocket ss;
  ss.setfd(sl_.accept());

  EXPECT_THROW(sc_.write("x"), SSLSocket::ErrSSL);
}

TEST_F(SSLSocketTest, HandshakeBeforeLoadcert)
{
  connect_tcp();

  SSLSocket ss;
  ss.setfd(sl_.accept());

  EXPECT_THROW(ss.ssl_accept(),
               SSLSocket::ErrSSL);
}

TEST_F(SSLSocketTest, NonExistingCertFile)
{
  connect_tcp();

  SSLSocket ss;
  ss.setfd(sl_.accept());

  set_certs(ss);
  ss.ssl_set_cafile("foo");
  sc_.ssl_set_cafile("foo");
  std::thread th;
  {
    AutoJoin aj(&th);
    th = std::thread(&SSLSocketTest::client_handshake, this);
    EXPECT_THROW(ss.ssl_accept(),
		 SSLSocket::ErrSSL);
  }
}

TEST_F(SSLSocketTest, BogusCipherList)
{
  connect_tcp();

  SSLSocket ss;
  ss.ssl_set_cipher_list(".*uhtneos.*");
  sc_.ssl_set_cipher_list(".*uhtneos.*");
  ss.setfd(sl_.accept());

  set_certs(ss);
  std::thread th;
  {
    AutoJoin aj(&th);
    th = std::thread(&SSLSocketTest::client_handshake, this);
    EXPECT_THROW(ss.ssl_accept(),
		 SSLSocket::ErrSSL);
  }
}

TEST_F(SSLSocketTest, Handshake)
{
  connect_tcp();

  SSLSocket ss;
  ss.setfd(sl_.accept());

  set_certs(ss);

  std::thread th;
  {
    AutoJoin aj(&th);
    th = std::thread(&SSLSocketTest::client_handshake, this);
    ss.ssl_accept();
  }
}

TEST_F(SSLSocketTest, LoopData)
{
  connect_tcp();

  SSLSocket ss;
  ss.setfd(sl_.accept());

  set_certs(ss);
  std::thread th;
  {
    AutoJoin aj(&th);

    th = std::thread(&SSLSocketTest::client_loopdata, this);
    ss.ssl_accept();
    ss.write("x");
    EXPECT_EQ("OK x", ss.read());
  }
}

TEST_F(SSLSocketTest, WriteToClosed)
{
  connect_tcp();

  SSLSocket ss;
  ss.setfd(sl_.accept());
  set_certs(ss);

  std::thread th;
  {
    AutoJoin aj(&th);

    th = std::thread(&SSLSocketTest::client_loopdata, this);
    ss.ssl_accept();
    ss.write("x");
    EXPECT_EQ("OK x", ss.read());
  }
  sc_.shutdown();
  std::vector<char> testdata(1000000);
  EXPECT_THROW(ss.full_write(std::string(testdata.begin(),
					 testdata.end())),
	       SSLSocket::ErrSSL);
}

int main(int argc, char **argv) {
  signal(SIGPIPE, SIG_IGN);

  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
