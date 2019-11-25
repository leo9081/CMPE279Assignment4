// Client side C/C++ program to demonstrate Socket programming 
#include <stdio.h> 
#include <sys/socket.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
#include <string.h> 
#define PORT 8080 

#include <sys/prctl.h>
#include <seccomp.h>
#include <linux/seccomp.h>
#include <unistd.h>
#include <fcntl.h>
 

#include <stddef.h>


#include "seccomp-bpf.h"


static int install_syscall_filter(void)
{
    struct sock_filter filter[] = {
        /* Validate architecture. */
        VALIDATE_ARCHITECTURE,
        /* Grab the system call number. */
        EXAMINE_SYSCALL,
        /* List allowed syscalls. */
        ALLOW_SYSCALL(execve),
        ALLOW_SYSCALL(brk),
        ALLOW_SYSCALL(access),
        ALLOW_SYSCALL(fstat),
        ALLOW_SYSCALL(openat),
        ALLOW_SYSCALL(mmap),
        ALLOW_SYSCALL(close),
        ALLOW_SYSCALL(read),
        ALLOW_SYSCALL(arch_prctl),
        ALLOW_SYSCALL(mprotect),
	ALLOW_SYSCALL(munmap),
        ALLOW_SYSCALL(socket),
        ALLOW_SYSCALL(write),
        ALLOW_SYSCALL(connect),
        ALLOW_SYSCALL(sendto),
        ALLOW_SYSCALL(lseek),
        ALLOW_SYSCALL(exit_group),
        ALLOW_SYSCALL(exit),
        KILL_PROCESS,
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("prctl(NO_NEW_PRIVS)");
        goto failed;
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
        perror("prctl(SECCOMP)");
        goto failed;
    }
    return 0;

failed:
    if (errno == EINVAL)
        fprintf(stderr, "SECCOMP_FILTER is not available. :(\n");
    return 1;
}

int main(int argc, char const *argv[]) 
{ 

    prctl(PR_SET_NO_NEW_PRIVS, 1);
    if (install_syscall_filter())
        return 1;


    struct sockaddr_in address; 
    int sock = 0, valread; 
    struct sockaddr_in serv_addr; 
    char *hello = "Hello from client"; 
    char buffer[4096] = {0}; 
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    { 
        printf("\n Socket creation error \n"); 
        return -1; 
    } 
   
    memset(&serv_addr, '0', sizeof(serv_addr)); 
   
    serv_addr.sin_family = AF_INET; 

	int portNumber = 8080;
	printf("\nPlease Enter the portNumber you want to use: \n");
	scanf("%d",&portNumber);

    serv_addr.sin_port = htons(portNumber); 
       
    // Convert IPv4 and IPv6 addresses from text to binary form 
    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0)  
    { 
        printf("\nInvalid address/ Address not supported \n"); 
        return -1; 
    } 
   
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
    { 
        printf("\nConnection Failed \n"); 
        return -1; 
    } 
    send(sock , hello , strlen(hello) , 0 ); 
    printf("Hello message sent\n"); 

    if ((valread = read( sock , buffer, 4096)) == -1){
	printf("Buffer overflow, please increase your buffer\n");
	return 0;
    }
    //valread = read( sock , buffer, 1024); 
    printf("server has sent: %s\n",buffer ); 
    return 0; 
} 
