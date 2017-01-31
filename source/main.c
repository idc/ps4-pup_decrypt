#include <assert.h>

#include "ps4.h"

#define DEBUG_SOCKET
#include "defines.h"

void decrypt_pups();

int sock;

int _main(void)
{
  initKernel();
  initLibc();
  initNetwork();
  initJIT();
  initPthread();

#ifdef DEBUG_SOCKET
  struct sockaddr_in server;

  server.sin_len = sizeof(server);
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = IP(192, 168, 0, 4);
  server.sin_port = sceNetHtons(9023);
  memset(server.sin_zero, 0, sizeof(server.sin_zero));
  sock = sceNetSocket("debug", AF_INET, SOCK_STREAM, 0);
  sceNetConnect(sock, (struct sockaddr *)&server, sizeof(server));

  int flag = 1;
  sceNetSetsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
#endif

  decrypt_pups();

  printfsocket("Bye!\n");

#ifdef DEBUG_SOCKET
  sceNetSocketClose(sock);
#endif
  return 0;
}
