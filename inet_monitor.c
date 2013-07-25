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

int send_diag_msg(int sockfd){
    struct msghdr msg;
    struct nlmsghdr nlh;
    struct inet_diag_req_v2 conn_req;
    struct sockaddr_nl sa;
    struct iovec iov[2];

    memset(&msg, 0, sizeof(msg));
    memset(&sa, 0, sizeof(sa));
    memset(&nlh, 0, sizeof(nlh));
    memset(&conn_req, 0, sizeof(conn_req));

    //NOTE: Bytecode is an nlattr for the request
    conn_req.sdiag_family = AF_INET;
    conn_req.sdiag_protocol = IPPROTO_TCP;

    //I am interested in all states, see /include/net/tcp_states.h for
    //definitions
    conn_req.idiag_states = 0xFFFF;

    //ext is a bitmask containing which extensions I might be interested in (I
    //guess?)

    //Interested in all connections
    
    nlh.nlmsg_len = NLMSG_LENGTH(sizeof(conn_req));
    nlh.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;

    //Avoid using compat by specifying family + protocol in header
    nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;

    iov[0].iov_base = (void*) &nlh;
    iov[0].iov_len = sizeof(nlh);
    iov[1].iov_base = (void*) &conn_req;
    iov[1].iov_len = sizeof(conn_req);

    //No need to specify groups or pid. This message only has one receiver and
    //pid 0 is kernel
    sa.nl_family = AF_NETLINK;

    //Set essage correctly
    msg.msg_name = (void*) &sa;
    msg.msg_namelen = sizeof(sa);
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;
   
    return sendmsg(sockfd, &msg, 0);
}

int main(int argc, char *argv[]){
    int nl_sock = 0, numbytes = 0;
    struct nlmsghdr *nlh_reply;
    struct inet_diag_req_v2 *conn_reply;
    struct msghdr msg;
    struct iovec iov;

    uint8_t recv_buf[SOCKET_BUFFER_SIZE];

    //Create the monitoring socket
    if((nl_sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_INET_DIAG)) == -1){
        perror("socket: ");
        return EXIT_FAILURE;
    }

    if(send_diag_msg(nl_sock) < 0){
        perror("sendmsg: ");
        return EXIT_FAILURE;
    }

    iov.iov_base = recv_buf;
    iov.iov_len = sizeof(recv_buf);
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    while(1){
        numbytes = recvmsg(nl_sock, &msg, 0);
        fprintf(stderr, "Received %d bytes\n", numbytes);
        nlh_reply = (struct nlmsghdr*) recv_buf;

        while(NLMSG_OK(nlh_reply, numbytes)){
            if(nlh_reply->nlmsg_type == NLMSG_DONE)
                return;

            fprintf(stderr, "Message\n");
            nlh_reply = NLMSG_NEXT(nlh_reply, numbytes); 
        }
        //fprintf(stderr, "Type %u Error %d\n", req.nlh.nlmsg_type, NLMSG_DONE);
    }

    return EXIT_SUCCESS;
}
