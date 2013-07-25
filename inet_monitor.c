#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <netinet/in.h>

#include <linux/sock_diag.h>
#include <linux/inet_diag.h>

//Copied from libmnl source
#define SOCKET_BUFFER_SIZE (getpagesize() < 8192L ? getpagesize() : 8192L)

int main(int argc, char *argv[]){
    int nl_sock = 0, numbytes = 0;
    struct {
        struct nlmsghdr nlh;
        struct inet_diag_req_v2 conn_req;
    } req;
    struct msghdr msg;
    struct sockaddr_nl sa;
    struct iovec iov[2];

    uint8_t recv_buf[SOCKET_BUFFER_SIZE];

    //memset(&nlh, 0, sizeof(nlh));
    //memset(&conn_req, 0, sizeof(conn_req));
    memset(&msg, 0, sizeof(msg));
    memset(&sa, 0, sizeof(sa));
    memset(&req, 0, sizeof(req));
    memset(&req.conn_req, 0, sizeof(req.conn_req));

    //Create the monitoring socket
    if((nl_sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_INET_DIAG)) == -1){
        perror("socket: ");
        exit(EXIT_FAILURE);
    }

    //NOTE: Bytecode is an nlattr for the request
    req.conn_req.sdiag_family = AF_INET;
    req.conn_req.sdiag_protocol = IPPROTO_TCP;
    req.conn_req.idiag_states = 0xFFFF;

    //ext is a bitmask containing which extensions I might be interested in (I
    //guess?)

    //Interested in all connections
    
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(req.conn_req));
    req.nlh.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
    req.nlh.nlmsg_seq = 123456;

    //Avoid using compat by specifying family + protocol in header
    req.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;

    iov[0].iov_base = (void*) &req;
    iov[0].iov_len = sizeof(req);
    //iov[1].iov_base = (void*) &conn_req;
    //iov[1].iov_len = sizeof(conn_req);

    //No need to specify groups or pid. This message only has one receiver and
    //pid 0 is kernel
    sa.nl_family = AF_NETLINK;

    //Set essage correctly
    msg.msg_name = (void*) &sa;
    msg.msg_namelen = sizeof(sa);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
   
    numbytes = sendmsg(nl_sock, &msg, 0);
    fprintf(stderr, "%u %u %u\n", req.nlh.nlmsg_len, req.nlh.nlmsg_flags, req.nlh.nlmsg_type);
    fprintf(stderr, "Number of bytes sent: %d\n", numbytes);

    iov[0].iov_base = recv_buf;
    iov[0].iov_len = sizeof(recv_buf);

    while(1){
        numbytes = recvmsg(nl_sock, &msg, 0);
        fprintf(stderr, "Received %d bytes\n", numbytes);
        fprintf(stderr, "Type %u Error %d\n", req.nlh.nlmsg_type, NLMSG_DONE);
    }
}
