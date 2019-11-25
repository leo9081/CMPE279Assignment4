#include <unistd.h> 
#include <stdio.h> 
#include <sys/socket.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
#include <string.h> 
#include <pwd.h>
#include <grp.h>
#include <ctype.h>

#include <sys/prctl.h>
#include <seccomp.h>
#include <linux/seccomp.h>


int droproot;
int root_dropped;
char *user = "nobody";		/* User to switch to */
char *group = "nogroup";		/* group to switch to */
const char *chrootdir = "/home/osboxes/Documents/GitRepo/CMPE279Assignment3/jail" ;	/* directory to chroot to */
uid_t sw_uid;
gid_t sw_gid;
char *endp;
struct group *gr;
struct passwd *pw;
int errno;
#define LENGTH 512

int main(int argc, char const *argv[]) { 



	char cwd[1000];
	getcwd(cwd, sizeof(cwd));
	printf("Initial user: %d\n", getuid() );
	printf("Initial group: %d\n", getgid() );
	printf("Initial working dir: %s\n", cwd );

	FILE *fs = fdopen(atoi(argv[2]),"r");
	
	if (user == NULL) {
		printf("Need user name to drop root privileges (see -u flag!)");
		exit(-1);
	}

	if (user != NULL) {
		if (isdigit((unsigned char)*user)) {
			sw_uid = (uid_t)strtoul(user, &endp, 0);
			if (*endp != '\0')
				getUser();
			if ((pw = getpwuid(sw_uid)) != NULL) {
				free(user);
				user = strdup(pw->pw_name);
				sw_gid = pw->pw_gid;
			} else {
				errno = 0;
				printf("Cannot find user ID %s", user);
				exit (-1);
			}
		} else {getUser();}
	}
		
	if (group != NULL) {
		if (isdigit((unsigned char)*group)) {
			sw_gid = (gid_t)strtoul(group, &endp, 0);
			if (*endp != '\0') {getGroup();}
		} else {getGroup();}
				
	}

	if (chrootdir) {
		if (chdir(chrootdir)) {
			printf("Cannot chdir() to `%s': %m", chrootdir);
			exit (-1);
		}
		if (chroot(chrootdir)) {
			printf("Cannot chroot() to `%s': %m", chrootdir);
			exit (-1);
		}
		if (chdir("/")) {
			printf("Cannot chdir() to`root after chroot(): %m");
			exit (-1);
		}
	}

	getcwd(cwd, sizeof(cwd));
	printf("current working dir: %s\n", cwd); 

		if (user && initgroups(user, sw_gid)) {
			printf("Cannot initgroups() to user `%s': %m", user);
			exit (-1);
		}
		if (group && setgid(sw_gid)) {
			printf("Cannot setgid() to group `%s': %m", group);
			exit (-1);
		}
		if (group && setegid(sw_gid)) {
			printf("Cannot setegid() to group `%s': %m", group);
			exit (-1);
		}
		if (group) {
			if (0 != setgroups(1, &sw_gid)) {
				printf("setgroups(1, %d) failed: %m", sw_gid);				
				exit (-1);
			}
		}
		else if (pw)
			if (0 != initgroups(pw->pw_name, pw->pw_gid)) {
				printf("initgroups(<%s>, %d) filed: %m", pw->pw_name, pw->pw_gid);
				exit (-1);
			}
		if (user && setuid(sw_uid)) {
			printf("Cannot setuid() to user `%s': %m", user);
			exit (-1);
		}
		if (user && seteuid(sw_uid)) {
			printf("Cannot seteuid() to user `%s': %m", user);
			exit (-1);
		}

	printf("current user: %d\n", sw_uid );
	printf("current group: %d\n", sw_gid );

    	printf("Sending file to the Client... \n");
    	
	if(fs == NULL){
        	printf("ERROR: File input.txt not found.\n");
        	exit(1);
    	}

    	char sdbuf[LENGTH];

    	bzero(sdbuf, LENGTH); 
    	int fs_block_sz;
	
	int new_socket = atoi(argv[1]);
    	
	while((fs_block_sz = fread(sdbuf, sizeof(char), LENGTH, fs)) > 0){
        	if(send(new_socket, sdbuf, fs_block_sz, 0) < 0){
            		fprintf(stderr, "ERROR: Failed to send file. (errno = %d)\n", errno);
            		break;
        	}
        	bzero(sdbuf, LENGTH);
    	}
    
	printf("Ok File from Client was Sent!\n");


	return 0;
}

void getUser(){
	errno = 0;
	if ((pw = getpwnam(user)) != NULL) {
		sw_uid = pw->pw_uid;
		sw_gid = pw->pw_gid;
	} else {
		if (errno){
			printf("getpwnam(%s) failed: %m", user);
		}else{
			printf("Cannot find user `%s'", user);
			exit (-1);
		}	
	}	
}

void getGroup(){
	if ((gr = getgrnam(group)) != NULL) {
		sw_gid = gr->gr_gid;
	} else {
		errno = 0;
		printf("Cannot find group `%s'", group);
		exit (-1);
	}
}



