#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdbool.h>
#include <pthread.h>

#define PORT 9000
#define PORT_STR "9000"
#define FILE_NAME "/var/tmp/aesdsocketdata"
#define BUFFER_SIZE 1024
#define BACKLOG 5
#define FILE_CHUNK_SIZE 4096

static volatile sig_atomic_t exit_flag = 0;

static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        exit_flag = 1;
        syslog(LOG_INFO, "Caught signal, exiting");
    }
}

static int ipaddr_to_str(struct sockaddr_in *addr, char *buf, size_t buflen) {
    if (inet_ntop(AF_INET, &addr->sin_addr, buf, buflen) == NULL) {
        return -1;
    }
    return 0;
}



static int append_packet_to_file(const char *filename, const char *data, size_t len) {
    int fd = open(filename, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        syslog(LOG_ERR, "Failed to open file: %s", filename);
        return -1;
    }

    ssize_t bytes_written = write(fd, data, len);
    if (bytes_written < 0 || (size_t)bytes_written != len) {
        syslog(LOG_ERR, "Failed to write to file: %s, %s", filename, strerror(errno));
        close(fd);
        return -1;
    }

    syslog(LOG_INFO, "Wrote %d bytes to %s", (int) bytes_written, filename);

    close(fd);
    return 0;
}

static int send_file_to_client(int client_sockfd, const char *filename) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        syslog(LOG_ERR, "Failed to open file: %s", filename);
        return -1;
    }

    char buffer[FILE_CHUNK_SIZE];
    ssize_t bytes_read;
    while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0) {
        ssize_t total_bytes_sent = 0;
        while (total_bytes_sent < bytes_read) {
            ssize_t bytes_sent = send(client_sockfd, buffer + total_bytes_sent, bytes_read - total_bytes_sent, 0);
            if (bytes_sent < 0) {
                syslog(LOG_ERR, "Failed to send file to client");
                close(fd);
                return -1;
            }
            total_bytes_sent += bytes_sent;
        }
    }
    if (bytes_read < 0) {
        syslog(LOG_ERR, "Failed to read from file: %s", filename);
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

// Thread data structure for joining later
struct thread_data {
    pthread_t thread_id;
    int client_fd;
    char client_ip[INET_ADDRSTRLEN];
    bool thread_complete;
    struct thread_data *next;
};

// Mutex for synchronizing access to temp file
static pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;

void *handle_client(void *arg) {
    struct thread_data *data = (struct thread_data *)arg;
    int client_sockfd = data->client_fd;

    // Handle client communication
    // Receive data from client until newline character is found
    char buffer[BUFFER_SIZE];
    char *packet = NULL;
    ssize_t packet_len = 0;
    int client_done = 0;
    
    while (!client_done && !exit_flag) {
        ssize_t bytes_received = recv(client_sockfd, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received < 0) {
            syslog(LOG_ERR, "Receive failed: %s", strerror(errno));
            break;
        } else if (bytes_received == 0) {
            // Connection closed by client
            client_done = 1;
            break;
        } else {
            char *tmp = realloc(packet, packet_len + bytes_received);
            if (tmp == NULL) {
                syslog(LOG_ERR, "Memory allocation failed");
                free(packet);
                packet = NULL;
                packet_len = 0;
                continue;
            }

            packet = tmp;
            memcpy(packet + packet_len, buffer, bytes_received);
            packet_len += bytes_received;
            
            ssize_t processed_up_to = 0;
            for (ssize_t i = 0; i < packet_len; i++) {
                if (packet[i] == '\n') {
                    ssize_t line_len = i - processed_up_to + 1;
                    pthread_mutex_lock(&file_mutex);
                    if (append_packet_to_file(FILE_NAME, packet + processed_up_to, line_len) != 0) {
                        syslog(LOG_ERR, "Failed to append data to file");
                    }
                    send_file_to_client(client_sockfd, FILE_NAME);
                    pthread_mutex_unlock(&file_mutex);
                    processed_up_to = i + 1;
                }
            }

            if (processed_up_to == packet_len) {
                free(packet);
                packet = NULL;
                packet_len = 0;
            } else if (processed_up_to > 0) {
                ssize_t remaining = packet_len - processed_up_to;
                memmove(packet, packet + processed_up_to, remaining);
                char *tmp2 = realloc(packet, remaining);
                if (tmp2 != NULL) {
                    packet = tmp2;
                }
                packet_len = remaining;
            }
        }
    }

    free(packet);
    syslog(LOG_INFO, "Closed connection from %s", data->client_ip);
    close(client_sockfd);
    return NULL;
}

void *timestamp_thread(void *arg) {
    while (!exit_flag) {
        time_t now = time(NULL);
        struct tm *tm_info = localtime(&now);

        char timestamp[128];
        strftime(timestamp, sizeof(timestamp),
                 "timestamp:%a, %d %b %Y %H:%M:%S %z\n",
                 tm_info);

        pthread_mutex_lock(&file_mutex);
        append_packet_to_file(FILE_NAME, timestamp, strlen(timestamp));
        pthread_mutex_unlock(&file_mutex);
        sleep(10);
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    openlog("aesdsocket", LOG_PID | LOG_CONS, LOG_USER);
    syslog(LOG_INFO, "Starting aesdsocket");

    bool daemon_mode = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0) {
            daemon_mode = true;
        } else {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            syslog(LOG_ERR, "Unknown argument: %s", argv[i]);
            closelog();
            return -1;
        }
    }

    // Set up signal handlers for SIGINT and SIGTERM
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    // Do not set SA_RESTART so blocking syscallis like accept() return with EINTR
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    // Create socket
    int sockfd;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        // Handle error
        syslog(LOG_ERR, "Socket creation failed: %s", strerror(errno));
        closelog();
        return -1;
    }

    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        // Handle error
        syslog(LOG_ERR, "Setsockopt failed: %s", strerror(errno));
        close(sockfd);
        closelog();
        return -1;
    }
    // Bind socket to port  
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    int result;
    result = bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (result < 0) {
        // Handle error
        syslog(LOG_ERR, "Bind failed: %s", strerror(errno));
        close(sockfd);
        closelog();
        return -1;
    }

    // Now fork and run in daemon mode if -d argument was provided
    if (daemon_mode) {
        pid_t pid = fork();
        if (pid < 0) {
            syslog(LOG_ERR, "Fork failed: %s", strerror(errno));
            close(sockfd);
            closelog();
            return -1;
        }
        if (pid > 0) {
            // Parent process, exit
            close(sockfd);
            closelog();
            return 0;
        }

        // Child process
        if (setsid() < 0) {
            syslog(LOG_ERR, "Setsid failed: %s", strerror(errno));
            close(sockfd);
            closelog();
            return -1;
        }

        // Change working directory to root
        if (chdir("/") < 0) {
            syslog(LOG_ERR, "Chdir failed: %s", strerror(errno));
            close(sockfd);
            closelog();
            return -1;
        }

        // Close standard file descriptors
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    }

    // Listen and accept a connection from client, log the IP address of the client
    result = listen(sockfd, BACKLOG);
    if (result < 0) {
        // Handle error
        syslog(LOG_ERR, "Listen failed: %s", strerror(errno));
        close(sockfd);
        closelog();
        return -1;
    }

    struct thread_data *head = NULL;

    pthread_t timer_thread_id;
    if (pthread_create(&timer_thread_id, NULL, timestamp_thread, NULL) != 0) {
        syslog(LOG_ERR, "Failed to create timer thread: %s", strerror(errno));
    }

    while(!exit_flag) {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        int client_sockfd = accept(sockfd, (struct sockaddr *)&client_addr, &client_addr_len);

        // Create a new thread for every client connection
        if (client_sockfd < 0) {
            if (errno == EINTR && exit_flag) {
                // Interrupted by signal, exit gracefully
                break;
            }
            syslog(LOG_ERR, "Accept failed: %s", strerror(errno));
            continue; // Continue to next iteration to accept new connections
        }

        struct thread_data *node = malloc(sizeof(*node));
        node->client_fd = client_sockfd;
        node->thread_complete = false;
        node->next = head;
        head = node;

        if (ipaddr_to_str(&client_addr, node->client_ip, sizeof(node->client_ip)) == 0) {
            syslog(LOG_INFO, "Accepted connection from %s", node->client_ip);
        } else {
            syslog(LOG_ERR, "Failed to convert client IP address to string");
        }

        if (pthread_create(&node->thread_id, NULL, handle_client, (void *)node) != 0) {
            syslog(LOG_ERR, "Failed to create thread: %s", strerror(errno));
            close(client_sockfd);
            node->thread_complete = true;
        }

        // Clean up completed threads
        struct thread_data **curr = &head;
        while (*curr) {
            if ((*curr)->thread_complete) {
                pthread_join((*curr)->thread_id, NULL);
                struct thread_data *tmp = *curr;
                *curr = (*curr)->next;
                free(tmp);
            } else {
                curr = &(*curr)->next;
            }
        }

        if (exit_flag) break;
    }

    pthread_join(timer_thread_id, NULL);

    close(sockfd);
    unlink(FILE_NAME);
    syslog(LOG_INFO, "Server exiting");
    closelog();    
    return 0;
}