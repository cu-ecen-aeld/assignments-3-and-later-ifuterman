void *get_in_addr(struct sockaddr *sa);
int write_to_file(int fd, const char* buf, size_t n_byte);
int init_server(int argc, char** argv);
int init_socket();
int recieve_to_file(int fd, int sockfd);
int send_from_file(int fd, int sockfd);
int send_to_socket(int sockfd, char* buf, size_t n_byte);
void signal_handler(int signo);
