#include <stdio.h>
#include <syslog.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char* argv[]){
	openlog(NULL, LOG_CONS, LOG_USER);
	if(argc < 2){
		syslog(LOG_ERR, "Wrong argument. Destination filepath expected\n");
		return 1;
	}
	if(argc < 3){
		syslog(LOG_ERR, "Wrong argument. The string for writing is not specified\n");
		return 1;
	}
	
	char* filepath = argv[1];
	char* str = argv[2];
	int fd = creat(filepath, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
	if(fd == -1){
		syslog(LOG_ERR, "Can`t create file %s\n", filepath);
		return 1;
	}
	syslog(LOG_DEBUG, "Writing %s to %s", str, filepath);
	ssize_t res = write(fd, str, strlen(str));
	if(res == -1){
		syslog(LOG_ERR, "Error while writung file %s\n", filepath);
		close(fd);
		return 1;
	}
	close(fd);
	closelog();
	return 0;
}
