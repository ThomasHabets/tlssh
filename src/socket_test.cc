#include<sys/types.h>
#include<sys/socket.h>

#include<iostream>

#include<gtest/gtest.h>

#include"socket.h"

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

TEST(Socket, LoopData)
{
  Socket s1;
  Socket s2;
  s1.listen(AF_UNSPEC, "", "12345");
  s2.connect(AF_UNSPEC, "localhost", "12345");

  // FIXME: use .accept() when it's implemented.
  struct sockaddr sa;
  socklen_t salen = sizeof(sa);
  Socket serv(accept(s1.getfd(), &sa, &salen));

  serv.write("x");
  EXPECT_EQ("x", s2.read(1));

  s2.write("y");
  EXPECT_EQ("y", serv.read(1));
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
