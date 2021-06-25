#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

int
main() {
  /* IP アドレス、ポート番号、ソケット */
  char destination[80];
  unsigned short port = 9876;
  int dstSocket;

  /* sockaddr_in 構造体 */
  struct sockaddr_in dstAddr;

  /* 各種パラメータ */
  int status;
  int numsnt;
  char *toSendText = "This is a test";

  /************************************************************/
  /* 相手先アドレスの入力 */
  printf("Connect to ? : (name or IP address) ");
  scanf("%s", destination);

  /* sockaddr_in 構造体のセット */
  memset(&dstAddr, 0, sizeof(dstAddr));
  dstAddr.sin_port = htons(port);
  dstAddr.sin_family = AF_INET;
  stAddr.sin_addr.s_addr = inet_addr(destination);
 
  /* ソケット生成 */
  dstSocket = socket(AF_INET, SOCK_STREAM, 0);

  /* 接続 */
  printf("Trying to connect to %s: \n", destination);
  connect(dstSocket, (struct sockaddr *) &dstAddr, sizeof(dstAddr));

  /* パケット送出 */
  for(i=0; i<10; i++) {
    printf("sending...\n");
    send(dstSocket, toSendText, strlen(toSendText)+1, 0);
    sleep(1);
  }

  /* ソケット終了 */
  close(dstSocket);
}

