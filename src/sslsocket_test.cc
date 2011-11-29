#include<sys/types.h>
#include<sys/socket.h>

#include<iostream>
#include<thread>

#include<gtest/gtest.h>

#include"util2.h"
#include"sslsocket.h"

Logger *logger = NULL;

class SSLSocketTest: public ::testing::Test {
 protected:
  SSLSocket sc_, sl_;
  void connect_tcp()
  {
    sl_.listen(AF_UNSPEC, "", "12345");
    sc_.connect(AF_UNSPEC, "localhost", "12345");
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
};

TEST_F(SSLSocketTest, Listen)
{
  SSLSocket sock;
  sock.listen(AF_UNSPEC, "", "12345");
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

void
client(SSLSocket* sock)
{
  try {
    sock->ssl_connect("localhost");
  } catch (const Socket::ErrBase &e) {
    std::cerr << "Client died:\n" << e.what_verbose() << std::endl;
    throw;
  } catch (...) {
    std::cerr << "Client died oddly\n";
    throw;
  }
}

TEST_F(SSLSocketTest, Handshake)
{
  connect_tcp();

  SSLSocket ss;
  ss.setfd(sl_.accept());

  std::thread th;
  try {
    ss.ssl_set_cafile("testdata/client.crt");
    ss.ssl_set_certfile("testdata/server.crt");
    ss.ssl_set_keyfile("testdata/server.key");

    sc_.ssl_set_cafile("testdata/server.crt");
    sc_.ssl_set_certfile("testdata/client.crt");
    sc_.ssl_set_keyfile("testdata/client.key");

    th = std::thread(client, &sc_);
    ss.ssl_accept();
  } catch (const Socket::ErrBase &e) {
    std::cerr << "Server died:\n";
    std::cerr << e.what_verbose() << std::endl;
    throw;
  } catch (...) {
    std::cerr << "Server died oddly\n";
    throw;
  }
  th.join();
}

TEST_F(SSLSocketTest, DISABLED_LoopData)
{
  connect_tcp();

  SSLSocket ss;
  ss.setfd(sl_.accept());

  ss.ssl_accept();
  ss.ssl_connect("localhost");

  sc_.write("x");
  EXPECT_EQ("x", ss.read(1));
  std::cerr << "1\n";

  ss.write("y");
  EXPECT_EQ("y", sc_.read(1));
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
