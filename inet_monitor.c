/*This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or distribute this
software, either in source code form or as a compiled binary, for any purpose,
commercial or non-commercial, and by any means.

In jurisdictions that recognize copyright laws, the author or authors of this
software dedicate any and all copyright interest in the software to the public
domain. We make this dedication for the benefit of the public at large and to
the detriment of our heirs and successors. We intend this dedication to be an
overt act of relinquishment in perpetuity of all present and future rights to
this software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <linux/tcp.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <arpa/inet.h>
#include <pwd.h>

//Kernel TCP states. /include/net/tcp_states.h
enum{
    TCP_ESTABLISHED = 1,
    TCP_SYN_SENT,
    TCP_SYN_RECV,
    TCP_FIN_WAIT1,
    TCP_FIN_WAIT2,
    TCP_TIME_WAIT,
    TCP_CLOSE,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    TCP_LISTEN,
    TCP_CLOSING 
};

static const char* tcp_states_map[]={
    [TCP_ESTABLISHED] = "ESTABLISHED",
    [TCP_SYN_SENT] = "SYN-SENT",
    [TCP_SYN_RECV] = "SYN-RECV",
    [TCP_FIN_WAIT1] = "FIN-WAIT-1",
    [TCP_FIN_WAIT2] = "FIN-WAIT-2",
    [TCP_TIME_WAIT] = "TIME-WAIT",
    [TCP_CLOSE] = "CLOSE",
    [TCP_CLOSE_WAIT] = "CLOSE-WAIT",
    [TCP_LAST_ACK] = "LAST-ACK",
    [TCP_LISTEN] = "LISTEN",
    [TCP_CLOSING] = "CLOSING"
};

//There are currently 11 states, but the first state is stored in pos. 1.
//Therefore, I need a 12 bit bitmask
#define TCPF_ALL 0xFFF

//Copied from libmnl source
#define SOCKET_BUFFER_SIZE (getpagesize() < 8192L ? getpagesize() : 8192L)

//Example of diag_filtering, checks if destination port is <= 1000
//
//The easies way to understand filters, is to look at how the kernel
//processes them. This is done in the function inet_diag_bc_run() in
//inet_diag.c. The yes/no contains offsets to the next condition or aborts
//the loop by making the variable len in inet_diag_bc_run() negative. There
//are some limitations to the yes/no values, see inet_diag_bc_audit();
unsigned char create_filter(void **filter_mem){
    struct inet_diag_bc_op *bc_op = NULL;
    unsigned char filter_len = sizeof(struct inet_diag_bc_op)*2;
    if((*filter_mem = calloc(filter_len, 1)) == NULL)
        return 0;

    bc_op = (struct inet_diag_bc_op*) *filter_mem; 
    bc_op->code = INET_DIAG_BC_D_LE;
    bc_op->yes = sizeof(struct inet_diag_bc_op)*2;
    //Only way to stop loop is to make len negative
    bc_op->no = 12;

    //For a port check, the port to check for is stored in the no field of a
    //follow-up bc_op-struct.
    bc_op = bc_op+1;
    bc_op->no = 1000;

    return filter_len;
}

int send_diag_msg(int sockfd){
    struct msghdr msg;
    struct nlmsghdr nlh;
    //To request information about unix sockets, this would be replaced with
    //unix_diag_req, packet-sockets packet_diag_req.
    struct inet_diag_req_v2 conn_req;
    struct sockaddr_nl sa;
    struct iovec iov[4];
    int retval = 0;

    //For the filter
    struct rtattr rta;
    void *filter_mem = NULL;
    int filter_len = 0;

    memset(&msg, 0, sizeof(msg));
    memset(&sa, 0, sizeof(sa));
    memset(&nlh, 0, sizeof(nlh));
    memset(&conn_req, 0, sizeof(conn_req));

    //No need to specify groups or pid. This message only has one receiver and
    //pid 0 is kernel
    sa.nl_family = AF_NETLINK;

    //Address family and protocol we are interested in. sock_diag can also be 
    //used with UDP sockets, DCCP sockets and Unix sockets, to mention a few.
    //This example requests information about TCP sockets bound to IPv4
    //addresses.
    conn_req.sdiag_family = AF_INET;
    conn_req.sdiag_protocol = IPPROTO_TCP;

    //Filter out some states, to show how it is done
    conn_req.idiag_states = TCPF_ALL & 
        ~((1<<TCP_SYN_RECV) | (1<<TCP_TIME_WAIT) | (1<<TCP_CLOSE));

    //Request extended TCP information (it is the tcp_info struct)
    //ext is a bitmask containing the extensions I want to acquire. The values
    //are defined in inet_diag.h (the INET_DIAG_*-constants).
    conn_req.idiag_ext |= (1 << (INET_DIAG_INFO - 1));
    
    nlh.nlmsg_len = NLMSG_LENGTH(sizeof(conn_req));
    //In order to request a socket bound to a specific IP/port, remove
    //NLM_F_DUMP and specify the required information in conn_req.id
    nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;

    //Example of how to only match some sockets
    //In order to match a single socket, I have to provide all fields
    //sport/dport, saddr/daddr (look at dump_on_icsk)
    //conn_req.id.idiag_dport=htons(443);

    //Avoid using compat by specifying family + protocol in header
    nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    iov[0].iov_base = (void*) &nlh;
    iov[0].iov_len = sizeof(nlh);
    iov[1].iov_base = (void*) &conn_req;
    iov[1].iov_len = sizeof(conn_req);

    //Remove the if 0 to test the filter
#if 0
    if((filter_len = create_filter(&filter_mem)) > 0){
        memset(&rta, 0, sizeof(rta));
        rta.rta_type = INET_DIAG_REQ_BYTECODE;
        rta.rta_len = RTA_LENGTH(filter_len);
        iov[2] = (struct iovec){&rta, sizeof(rta)};
        iov[3] = (struct iovec){filter_mem, filter_len};
        nlh.nlmsg_len += rta.rta_len;
    }
#endif

    //Set essage correctly
    msg.msg_name = (void*) &sa;
    msg.msg_namelen = sizeof(sa);
    msg.msg_iov = iov;
    if(filter_mem == NULL)
        msg.msg_iovlen = 2;
    else
        msg.msg_iovlen = 4;
   
    retval = sendmsg(sockfd, &msg, 0);

    if(filter_mem != NULL)
        free(filter_mem);

    return retval;
}

void parse_diag_msg(struct inet_diag_msg *diag_msg, int rtalen){
    struct rtattr *attr;
    struct tcp_info *tcpi;
    char local_addr_buf[INET6_ADDRSTRLEN];
    char remote_addr_buf[INET6_ADDRSTRLEN];
    struct passwd *uid_info = NULL;

    memset(local_addr_buf, 0, sizeof(local_addr_buf));
    memset(remote_addr_buf, 0, sizeof(remote_addr_buf));

    //(Try to) Get user info
    uid_info = getpwuid(diag_msg->idiag_uid);

    if(diag_msg->idiag_family == AF_INET){
        inet_ntop(AF_INET, (struct in_addr*) &(diag_msg->id.idiag_src), 
            local_addr_buf, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, (struct in_addr*) &(diag_msg->id.idiag_dst), 
            remote_addr_buf, INET_ADDRSTRLEN);
    } else if(diag_msg->idiag_family == AF_INET6){
        inet_ntop(AF_INET6, (struct in_addr6*) &(diag_msg->id.idiag_src),
                local_addr_buf, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, (struct in_addr6*) &(diag_msg->id.idiag_dst),
                remote_addr_buf, INET6_ADDRSTRLEN);
    } else {
        fprintf(stderr, "Unknown family\n");
        return;
    }

    if(local_addr_buf[0] == 0 || remote_addr_buf[0] == 0){
        fprintf(stderr, "Could not get required connection information\n");
        return;
    } else {
        fprintf(stdout, "User: %s (UID: %u) Src: %s:%d Dst: %s:%d\n", 
                uid_info == NULL ? "Not found" : uid_info->pw_name,
                diag_msg->idiag_uid,
                local_addr_buf, ntohs(diag_msg->id.idiag_sport), 
                remote_addr_buf, ntohs(diag_msg->id.idiag_dport));
    }

    //Parse the attributes of the netlink message in search of the
    //INET_DIAG_INFO-attribute
    if(rtalen > 0){
        attr = (struct rtattr*) (diag_msg+1);

        while(RTA_OK(attr, rtalen)){
            if(attr->rta_type == INET_DIAG_INFO){
                //The payload of this attribute is a tcp_info-struct, so it is
                //ok to cast
                tcpi = (struct tcp_info*) RTA_DATA(attr);

                //Output some sample data
                fprintf(stdout, "\tState: %s RTT: %gms (var. %gms) "
                        "Recv. RTT: %gms Snd_cwnd: %u/%u\n",
                        tcp_states_map[tcpi->tcpi_state],
                        (double) tcpi->tcpi_rtt/1000, 
                        (double) tcpi->tcpi_rttvar/1000,
                        (double) tcpi->tcpi_rcv_rtt/1000, 
                        tcpi->tcpi_unacked,
                        tcpi->tcpi_snd_cwnd);
            }
            attr = RTA_NEXT(attr, rtalen); 
        }
    }
}

int main(int argc, char *argv[]){
    int nl_sock = 0, numbytes = 0, rtalen = 0;
    struct nlmsghdr *nlh;
    uint8_t recv_buf[SOCKET_BUFFER_SIZE];
    struct inet_diag_msg *diag_msg;

    //Create the monitoring socket
    if((nl_sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_INET_DIAG)) == -1){
        perror("socket: ");
        return EXIT_FAILURE;
    }

    //Send the request for the sockets we are interested in
    if(send_diag_msg(nl_sock) < 0){
        perror("sendmsg: ");
        return EXIT_FAILURE;
    }

    //The requests can (will in most cases) come as multiple netlink messages. I
    //need to receive all of them. Assumes no packet loss, so if the last packet
    //(the packet with NLMSG_DONE) is lost, the application will hang.
    while(1){
        numbytes = recv(nl_sock, recv_buf, sizeof(recv_buf), 0);
        nlh = (struct nlmsghdr*) recv_buf;

        while(NLMSG_OK(nlh, numbytes)){
            if(nlh->nlmsg_type == NLMSG_DONE)
                return EXIT_SUCCESS;

            if(nlh->nlmsg_type == NLMSG_ERROR){
                fprintf(stderr, "Error in netlink message\n");
                return EXIT_FAILURE;
            }

            diag_msg = (struct inet_diag_msg*) NLMSG_DATA(nlh);
            rtalen = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*diag_msg));
            parse_diag_msg(diag_msg, rtalen);

            nlh = NLMSG_NEXT(nlh, numbytes); 
        }
    }

    return EXIT_SUCCESS;
}
