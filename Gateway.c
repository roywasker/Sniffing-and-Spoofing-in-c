#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 9998
#define BUFFSIZE 1024

int main(int argc, char *argv[]){
    if(argc!=2){
        printf("you need provide a host name \n");
        exit(1);
    }
    int sockin= socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(sockin < 0){
        printf("Could not create socket in\n");
        exit(1);
    }

    struct sockaddr_in serverin;
    memset((char *)&serverin, 0, sizeof(serverin));
    serverin.sin_family = AF_INET;
    serverin.sin_port = htons(PORT);
    serverin.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sockin, (struct sockaddr *)&serverin, sizeof(serverin)) == -1){
        printf("bind failed \n");
        exit(1);
    }

    int sockout= socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(sockout < 0){
        printf("Could not create socket out \n");
        exit(1);
    }

    struct sockaddr_in serverout;
    memset(&serverout, 0, sizeof(serverout));
    serverout.sin_family = AF_INET;
    serverout.sin_port = htons(PORT+1);
    int rval = inet_pton(AF_INET, argv[1], &serverout.sin_addr);
    if (rval <= 0)
    {
        printf("inet pton failed\n");
        exit(1);
    }

    char buffer[BUFFSIZE];
    struct sockaddr_in clientAddress;
    socklen_t clientAddressLen = sizeof(clientAddress);

    while (1){

        memset(buffer, '\0', sizeof (buffer));
        memset((char *)&clientAddress, 0, sizeof(clientAddress));
        clientAddressLen = sizeof(clientAddress);

        int recvlen = recvfrom(sockin, buffer, sizeof(buffer) -1, 0, (struct sockaddr *) &clientAddress, &clientAddressLen);
        if(recvlen<0){
            printf("recv from failed \n");
            break;
        }

        float randnum = ((float)random())/((float)RAND_MAX);
        if(randnum > 0.5) {
            printf("%s\n",buffer);
            int sendlen  = sendto(sockout, buffer, recvlen, 0, (struct sockaddr *) &serverout, sizeof (serverout));
            if (sendlen < 0 ) {
                printf("send to failed \n");
                break;
            }
        } else{
            printf("lost packet\n");
        }
    }

    close(sockin);
    close(sockout);
    return 0;
}