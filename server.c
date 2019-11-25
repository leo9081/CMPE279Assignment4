// Server side C/C++ program to demonstrate Socket programming 
#include <unistd.h> 
#include <stdio.h> 
#include <sys/socket.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
#include <string.h>

#include <sys/prctl.h>
#include <seccomp.h>
#include <linux/seccomp.h>
#include <unistd.h>

#define PORT 8080

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
	ALLOW_SYSCALL(openat),
        ALLOW_SYSCALL(access),
        ALLOW_SYSCALL(fstat),
        ALLOW_SYSCALL(mmap),
        ALLOW_SYSCALL(close),
        ALLOW_SYSCALL(read),
        ALLOW_SYSCALL(arch_prctl),
        ALLOW_SYSCALL(mprotect),
	ALLOW_SYSCALL(munmap),
	ALLOW_SYSCALL(prctl),
	ALLOW_SYSCALL(seccomp),

        ALLOW_SYSCALL(socket),
	ALLOW_SYSCALL(setsockopt),
	ALLOW_SYSCALL(bind),
	ALLOW_SYSCALL(listen),

	ALLOW_SYSCALL(accept),
	ALLOW_SYSCALL(clone),
	ALLOW_SYSCALL(dup),
	ALLOW_SYSCALL(wait4),
	ALLOW_SYSCALL(lseek),
	ALLOW_SYSCALL(exit_group),
        ALLOW_SYSCALL(write),

	//child process addtion
        ALLOW_SYSCALL(connect),
        ALLOW_SYSCALL(sendto),
        ALLOW_SYSCALL(chdir),
	ALLOW_SYSCALL(chroot),
        ALLOW_SYSCALL(stat),
        ALLOW_SYSCALL(setgroups),
	ALLOW_SYSCALL(setgid),
        ALLOW_SYSCALL(setresgid),
        ALLOW_SYSCALL(setuid),
	ALLOW_SYSCALL(setresuid),
        ALLOW_SYSCALL(getcwd),
        ALLOW_SYSCALL(getuid),
	ALLOW_SYSCALL(getgid),
        ALLOW_SYSCALL(fcntl),
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

if(argc < 2){
printf("int the parent %d\n", argc);
    int server_fd, new_socket, valread; 
    struct sockaddr_in address; 
    int opt = 1; 
    int addrlen = sizeof(address); 
    //char buffer[1024] = {0}; 
    //char *hello = "Hello from server"; 
       
    // Creating socket file descriptor 
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) 
    { 
        perror("socket failed"); 
        exit(EXIT_FAILURE); 
    } 
       
    // Forcefully attaching socket to the port 8080 
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, 
                                                  &opt, sizeof(opt))) 
    { 
        perror("setsockopt"); 
        exit(EXIT_FAILURE); 
    } 
    address.sin_family = AF_INET; 
    address.sin_addr.s_addr = INADDR_ANY; 
	
	int portNumber = 8080;
	printf("\nPlease Enter the port number you want to use: \n");
	scanf("%d",&portNumber);

    address.sin_port = htons( portNumber ); 
       
    // Forcefully attaching socket to the port 8080 
    if (bind(server_fd, (struct sockaddr *)&address,  
                                 sizeof(address))<0) 
    { 
        perror("bind failed"); 
        exit(EXIT_FAILURE); 
    } 
    if (listen(server_fd, 3) < 0) 
    { 
        perror("listen"); 
        exit(EXIT_FAILURE); 
    } 
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address,  
                       (socklen_t*)&addrlen))<0) 
    { 
        perror("accept"); 
        exit(EXIT_FAILURE); 
    } 
    

	FILE *fs;
	char fs_name[100]="";
	printf("\nPlease Enter the file name you want to send: \n");
	scanf("%s",&fs_name);

	fs=fopen(fs_name,"r");
	if(fs == NULL){
		perror("\nFile Open unsuccess!"); 
        	exit(EXIT_FAILURE);
	}
	

	int fff = fileno(fs);

	char fpd[12];
	sprintf(fpd, "%d", fff);


    pid_t childPid;
    childPid = fork();
    if(childPid==0){
	char str[12];
	sprintf(str, "%d", new_socket);
	execl("server", "server", str, fpd, NULL);
	/*valread = read( new_socket , buffer, 1024); 
    	printf("%s\n",buffer ); 
    	send(new_socket , hello , strlen(hello) , 0 ); 
    	printf("Hello message sent\n");
	exit(0);*/ 
    }else{
	int returnStatus;
    	waitpid(childPid,&returnStatus,0);
	printf("Child process return status: %d\n",returnStatus);
    }
    }else{
	printf("int the child %d\n", argc);

 	pid_t childPid2;
    	childPid2 = fork();
    	if(childPid2==0){
		char str[12];
		int new_socket = atoi(argv[1]);
		sprintf(str, "%d", new_socket);
		execl("dpchild", "dpchild", str, argv[2], NULL);
    	}else{
		int returnStatus;
    		waitpid(childPid2,&returnStatus,0);
		printf("Child process return status: %d\n",returnStatus);
    	}
    }
    return 0; 
} 
