#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <unistd.h>

#define NETLINK_USER 31
#define MAX_PAYLOAD 1024

struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nlh = NULL;
struct iovec iov;
struct msghdr msg;
int sock_fd;

void setup_netlink() {
    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (sock_fd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();

    bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0; // For Linux kernel
    dest_addr.nl_groups = 0; // Unicast

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
}

void send_and_receive(char *input,int pid,unsigned long offset) {
	char message[64];

    sprintf(message, "%s %lu %d", input,offset,pid);
    strcpy((char *)NLMSG_DATA(nlh), message);

    if (sendmsg(sock_fd, &msg, 0) < 0) {
        perror("sendmsg");
        exit(EXIT_FAILURE);
    }

    if (recvmsg(sock_fd, &msg, 0) < 0) {
        perror("recvmsg");
        exit(EXIT_FAILURE);
    }
    
    int received_data;
    memcpy(&received_data, NLMSG_DATA(nlh), sizeof(received_data));
    printf("Received message: %d\n", received_data);
}

int main() {
    setup_netlink();

    char input[32];

    int pid;
    
    unsigned long offset;

    printf("Enter a virtual address (in hexadecimal): ");

    scanf("%31s", input);

    printf("Enter the process ID: ");

    scanf("%d", &pid);

    printf("Enter the offset: ");

    scanf("%lu", &offset);



    send_and_receive(input,pid,offset);

    close(sock_fd);
    free(nlh);

    return 0;
}