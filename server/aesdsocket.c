#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <syslog.h>
#include <signal.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>

#include "aesdsocket.h"

#define PORT "9000"  // the port users will be connecting to

#define BACKLOG 10   // how many pending connections queue will hold

#define FILEPATH "/var/tmp/aesdsocketdata"

#define BUFSIZE 1048576

volatile static int work_state = 1;

int g_fd, g_sfd, g_scfd;//File descriptors for aesdsocketdata file, socket and connection

int main(int argc, char** argv){    
	openlog(NULL, LOG_CONS | LOG_PID, LOG_INFO);
	syslog(LOG_INFO, "Initialise server");
	
	if(init_server(argc, argv)){
		closelog();
		return -1;
	}
	
	struct sigaction action;
	memset(&action, 0, sizeof(sigaction));
	action.sa_handler = signal_handler;
	sigaction(SIGINT, &action, NULL);
	sigaction(SIGTERM, &action, NULL);
	
	
	int sockfd, new_fd;  // listen on sock_fd, new connection on new_fd
  
  g_sfd = init_socket();
  sockfd = g_sfd;
  
  if(sockfd == -1){
		syslog(LOG_ERR, "init_socket FAILED");
		closelog();
		return -1;
  }
  
	syslog(LOG_INFO, "Socked inited sockfd=%d", sockfd);
	
  if (listen(sockfd, BACKLOG)) {
		syslog(LOG_ERR, "listen FAILED");
		closelog();
    return -1;
  }
  
  struct sockaddr_storage their_addr;
  socklen_t addr_size  = sizeof their_addr;
  char s[INET6_ADDRSTRLEN];
	int fd;
  int fflags = O_RDWR | O_APPEND | O_CREAT | O_TRUNC;
  
  g_fd = open(FILEPATH, fflags, 0666);
  fd = g_fd;
  if(fd == -1){
		syslog(LOG_ERR, "open FAILED error:%s", strerror(errno));
	  return -1;
	}
  
  while(work_state){
  	syslog(LOG_INFO, "Wait for connection");
    g_scfd = accept(sockfd, (struct sockaddr *)&their_addr, &addr_size);
    new_fd = g_scfd;
    inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr), s, sizeof s);
    syslog(LOG_INFO, "Accepted connection from %s; new_fd: %d", s, new_fd);
  	
    if(recieve_to_file(fd, new_fd)){
    	closelog();
    	close(fd);
    	close(new_fd);
    	close(sockfd);
    	return -1;
    }
		if(send_from_file(fd, new_fd)){
    	closelog();
    	close(fd);
    	close(new_fd);
    	close(sockfd);
    	return -1;
		}
  	close(new_fd);
    syslog(LOG_INFO, "Closed connection from %s", s);
  }
	close(fd);
	close(sockfd);
	closelog();
}

int write_to_file(int fd, const char* buf, size_t n_byte){
	int res, offset = 0, length = n_byte;
	while(work_state){
		res = write(fd, buf + offset, length);
		if(res == -1){
  		syslog(LOG_ERR, "write FAILED error:%s", strerror(errno));
			return -1;
		}
		offset += res;
		length -= res;
		if(offset == n_byte){
			break;
		}
	}
	return 0;
}

int send_to_socket(int sockfd, char* buf, size_t n_byte){
	int res, offset = 0, length = n_byte;
	while(work_state){
		res = send(sockfd, buf + offset, length, 0);
		if(res == -1){
  		syslog(LOG_ERR, "send FAILED");
			return -1;
		}
		offset += res;
		length -= res;
		if(offset == n_byte){
			break;
		}
	}
	return 0;
}

int send_from_file(int fd, int sockfd){
	char buf[BUFSIZE];
	int res, offset = 0; 
		
	while(work_state){
		res = pread(fd, buf, BUFSIZE, offset);
		if(res == -1){
			syslog(LOG_ERR, "read FAILED");
			return -1;
		}
		if(!res){
			break;
		}
		if(send_to_socket(sockfd, buf, res)){
			syslog(LOG_ERR, "send_to_socket FAILED");		
			return -1;
		}
		offset += res;
	}
	return 0;
}

int recieve_to_file(int fd, int sockfd){

  int res; 
  char buf[BUFSIZE];
	
	int flags = 0;

  
  while(work_state){
    res = recv(sockfd, buf, BUFSIZE, flags);
    flags = MSG_DONTWAIT;
    if(res == -1){
    	if(errno == EAGAIN || errno == EWOULDBLOCK){
    		break;
    	}
  		syslog(LOG_ERR, "recv FAILED");
  		syslog(LOG_ERR, "recv FAILED error:%s", strerror(errno));
		  return -1;
    }
    if(res == 0){
    	break;
    }
  	res = write_to_file(fd, buf, res);
  	if(res){
			syslog(LOG_ERR, "write_to_file FAILED");
    	return -1;
  	}
  }
  return 0;
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int init_server(int argc, char** argv){
	if(argc >= 2){
		syslog(LOG_INFO, "Daemon mode");
		if(!strcmp(argv[1], "-d")){
			pid_t pid;
			pid = fork();
			if(pid == -1){
				syslog(LOG_ERR, "fork FAILED");
				return -1;
			}		
			if(pid){
				syslog(LOG_INFO, "Daemon started with PID = %d", pid);
				closelog();
				exit(EXIT_SUCCESS);
			}
		}
		if(setsid() == -1){
			syslog(LOG_ERR, "setsid FAILED");
			return -1;
		}
		if(chdir("/") == -1){
			syslog(LOG_ERR, "chdir FAILED");
			return -1;
		}
		for (int i = 0; i < 3; i++){
			close (i);
		}
		open ("/dev/null", O_RDWR); /* stdin */
		dup (0); /* stdout */
		dup (0); /* stderror */
	}
	else{
		syslog(LOG_INFO, "Proces mode");
	}
	return 0;
}

int init_socket(){
	struct addrinfo hints, *servinfo, *p;
  
  int yes=1, sockfd;
  
//	hints.ai_family = AF_UNSPEC;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;


  if (getaddrinfo(NULL, PORT, &hints, &servinfo)) {
  	syslog(LOG_ERR, "getaddrinfo FAILED");
		return -1;
  }
  
  for(p = servinfo; p != NULL; p = p->ai_next) {
  	if(p->ai_family != AF_INET){
  		continue;
  	}
    syslog(LOG_INFO, "Try to get socket");
	  sockfd = socket(p->ai_family, p->ai_socktype,	p->ai_protocol);
    if (sockfd == -1) {
	  	syslog(LOG_WARNING, "socket FAILED");
	    continue;
	  }
		
	  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int))) {
			syslog(LOG_ERR, "setsockopt FAILED");
			return -1;
	  }

    if (bind(sockfd, p->ai_addr, p->ai_addrlen)) {
			close(sockfd);
			syslog(LOG_WARNING, "bind FAILED");
      continue;
    }

    break;
	}
	
	freeaddrinfo(servinfo);
	
	if (p == NULL)  {
		syslog(LOG_ERR, "No one socket are opened");
		return -1;
  }
  syslog(LOG_INFO, "Socket recieved");
  return sockfd;
}

void signal_handler(int signo){
	syslog(LOG_INFO, "Caught signal, exiting");
	work_state = 0;
	close(g_sfd);
	close(g_scfd);
	close(g_fd);
	unlink(FILEPATH);
	exit (EXIT_SUCCESS);
}
