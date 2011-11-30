#include<sys/types.h>
#include<sys/socket.h>

#include<iostream>

#include<gtest/gtest.h>

#include"socket.h"
#include"gaiwrap.h"

TEST(Socket, Debug)
{
  Socket sock;
  EXPECT_EQ(false, sock.get_debug());

  sock.set_debug(true);
  EXPECT_EQ(true, sock.get_debug());

  sock.set_debug(false);
  EXPECT_EQ(false, sock.get_debug());
}

TEST(Socket, FdOps)
{
  Socket sock(123);
  EXPECT_EQ(123, sock.getfd());

  sock.forget();
  EXPECT_EQ(-1, sock.getfd());
}

TEST(Socket, Listen)
{
  Socket sock;
  sock.listen(AF_UNSPEC, "", "12345");
  EXPECT_LE(0, sock.getfd());
}

TEST(Socket, ReuseAddrBeforeSocket)
{
  Socket sock;
  EXPECT_THROW(sock.set_reuseaddr(true),
	       Socket::ErrSys);
}

TEST(Socket, InvalidAF)
{
  Socket sock;
  EXPECT_THROW(sock.listen(-1, "", "12345"),
	       GetAddrInfo::ErrBase);
}

TEST(Socket, InvalidBindAddress)
{
  Socket sock;
  EXPECT_THROW(sock.listen(AF_UNSPEC, "1.1.1.1", "12345"),
	       Socket::ErrSys);
}

TEST(Socket, ListenPortBusy)
{
  Socket sock1;
  Socket sock2;
  sock1.listen(AF_UNSPEC, "", "12345");
  EXPECT_THROW(sock2.listen(AF_UNSPEC, "", "12345"),
	       Socket::ErrSys);
}

TEST(Socket, ConnectOpen)
{
  Socket sock;
  sock.connect(AF_UNSPEC, "localhost", "ssh");
  EXPECT_LE(0, sock.getfd());
}

TEST(Socket, ConnectClosed)
{
  Socket sock;
  EXPECT_THROW(sock.connect(AF_UNSPEC, "localhost", "telnet"),
               Socket::ErrSys);
}

TEST(Socket, AcceptOnNonlisten)
{
  Socket s1;
  EXPECT_THROW(s1.accept(),
	       Socket::ErrSys);
}

TEST(Socket, PeerWhenNotInit)
{
  Socket sock;
  EXPECT_THROW(sock.get_peer_addr_string(),
	       Socket::ErrSys);
}

TEST(Socket, PeerWhenNotConnected)
{
  Socket sock;
  sock.listen(AF_UNSPEC, "", "12345");
  EXPECT_THROW(sock.get_peer_addr_string(),
	       Socket::ErrSys);
}

TEST(Socket, LoopData)
{
  Socket s1;
  Socket s2;
  s1.listen(AF_UNSPEC, "", "12345");
  s2.connect(AF_UNSPEC, "127.0.0.1", "12345");

  Socket serv;
  serv.setfd(s1.accept());

  std::string peer(s2.get_peer_addr_string());
  EXPECT_EQ("127.0.0.1", peer);

  serv.write("x");
  EXPECT_EQ("x", s2.read(1));

  s2.write("y");
  EXPECT_EQ("y", serv.read(1));
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
