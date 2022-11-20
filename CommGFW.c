#include <sys/time.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <gmssl/tls.h>
#include <gmssl/error.h>
#include <gmssl/mem.h>
#include <gmssl/sm2.h>

#define VERSION "2.2"
#define TIMEOUT  3
#define max(a,b) (a)>(b)?(a):(b)
#define MAXSIZE 10240
#define HOSTLEN 128
#define CONNECT_NUMBER 10

#define LOG_OFF             0
#define LOG_ERROR           1
#define LOG_NORMAL          2
#define LOG_DEBUG           3

void SIGALRM_FUN();
void usage(char *s);
void transdatas(int fd1, int fd2);
void ts2conn(int fd1,  int fd2);
int testifisvalue(char *str);
int bs2conn(int port1);
int bind2conns(int port1,char *host,int port2);
int create_socket();
int create_serv(int sockfd,int port);
int dnsResolve(const char *hostname, char *ip);
void make_nonblock(int fd);
void make_block(int fd);
int head2tlv(char *InBuf, char *sIp, int *port);
int RTrim(char *caDest);
int LTrim(char *caDest);
void set_socket_timeout(int fd);
int open_tcp_socket(char *hostname, int portnumber);
int bind_socket (int sockfd, const char *addr, int family);
static const char * get_gai_error (int n);
static const char * family_string (int af);

static int client_ciphers[] = { TLS_cipher_sm4_gcm_sm3 };
static int server_ciphers[] = { TLS_cipher_sm4_gcm_sm3 };
TLS_CTX ctx;
TLS_CONNECT conn;
char *gsLogFile ;

int main(int argc,char **argv)
{
    char **p;
    char host1[HOSTLEN],host2[HOSTLEN];
    int port1=0,port2=0,method=0;
    int length;

    p=argv;
    memset(host1,0,HOSTLEN);
    memset(host2,0,HOSTLEN);
    while(*p)
    {
        if(strcmp(*p,"-v")==0)
        {
            printf("Socket data transport tool.\r\nVersion:%s\r\n",VERSION);
            p++;
            continue;
        }
        if(strcmp(*p,"-h1")==0)
        {
            if(testifisvalue(*(p+1))==1)
            {
                length=(strlen(*(p+1))>HOSTLEN-1)?HOSTLEN-1:strlen(*(p+1));
                strncpy(host1,*(++p),length);
            }
            p++;
            continue;
        }
        if(strcmp(*p,"-h2")==0)
        {
            if(testifisvalue(*(p+1))==1)
            {
                length=(strlen(*(p+1))>HOSTLEN-1)?HOSTLEN-1:strlen(*(p+1));
                strncpy(host2,*(++p),length);
            }
            p++;
            continue;
        }
        if(strcmp(*p,"-p1")==0)
        {
            if(testifisvalue(*(p+1))==1)
                port1=atoi(*(++p));
            p++;
            continue;
        }
        if(strcmp(*p,"-p2")==0)
        {
            if(testifisvalue(*(p+1))==1)
                port2=atoi(*(++p));
            p++;
            continue;
        }
        if(strcmp(*p,"-m")==0)
        {
            if(testifisvalue(*(p+1))==1)
                method=atoi(*(++p));
            p++;
            continue;
        }
        p++;
    }
    signal(SIGCLD,SIG_IGN);
    switch(method)
    {
    case 0:
        usage(argv[0]);
        break;
    case 11:
        if((port1==0) || (port2==0))
        {
            printf("[ERROR]:must supply PORT1 and PORT2.\r\n");
            break;
        }
        if(strlen(host2)==0)
        {
            printf("[ERROR]:must supply HOST2.\r\n");
            break;
        }
        bind2conns(port1,host2,port2);
        break;
    case 21:
        if((port1==0) )
        {
            printf("[ERROR]:must supply PORT1 and PORT2.\r\n");
            break;
        }
        bs2conn(port1);
        break;
    default:
        usage(argv[0]);
    }
    return 0;
}

int testifisvalue(char *str)
{
    if(str == NULL ) return(0);
    if(str[0]=='-') return(0);
    return(1);
}

void usage(char *s)
{
    printf("Socket data transport tool\r\n");
    printf("by bkbll(bkbll@cnhonker.net)\r\n\r\n");
    printf("Usage:%s -m method [-h1 host1] -p1 port1 [-h2 host2] -p2 port2 [-v] [-log filename]\r\n",s);
    printf(" -v: version\r\n");
    printf(" -h1: host1\r\n");
    printf(" -h2: host2\r\n");
    printf(" -p1: port1\r\n");
    printf(" -p2: port2\r\n");
    printf(" -m: the action method for this tool\r\n");
}
int bs2conn(int port1)
{
    int sockfd,sockfd1,sockfd2;
    struct sockaddr_in remote;
    size_t size;
    size_t len = 0;
    int pid;
    int nRet = -1;
    char buffer[1024];
    char sTmpBuf[1024];
    char sReply[1024];
    char *p = NULL;
    char *b = NULL;
    struct hostent *ph;
    uint8_t *ip;
    char host[128], sIp[128];
    int  port2, nhttpflag=-1;;
    struct addrinfo hints, *res ;
    char portstr[8];
    char *ptr1 =NULL;
    char *ptr2 =NULL;
	gsLogFile = "server.log";

	char *certfile = "certs.pem";
	char *keyfile = "signkey.pem";
	char *pass = "1234";
	char *cacertfile = "cacert.pem";

	memset(&ctx, 0, sizeof(ctx));
	memset(&conn, 0, sizeof(conn));
	char *bind_to = getenv("JW_IP");

	if (tls_ctx_init(&ctx, TLS_protocol_tls13, TLS_server_mode) != 1
			|| tls_ctx_set_cipher_suites(&ctx, server_ciphers, sizeof(server_ciphers)/sizeof(int)) != 1
			|| tls_ctx_set_certificate_and_key(&ctx, certfile, keyfile, pass) != 1) {
		error_print();
		return -1;
	}
	if (cacertfile) {
		if (tls_ctx_set_ca_certificates(&ctx, cacertfile, TLS_DEFAULT_VERIFY_DEPTH) != 1) {
			error_print();
			return -1;
		}
	}
	if (tls_init(&conn, &ctx) != 1 ) 
	{
		error_print();
		return -1;
	}

    memset(buffer,0,1024);
    if((sockfd=create_socket())==0) exit(0);
    if(create_serv(sockfd,port1)==0)
    {
        perror("create_serv\n");
        close(sockfd1);
        exit(0);
    }
    while(1)
    {
        size=sizeof(struct sockaddr);
        //printf("waiting for response.........\n");
        if((sockfd1=accept(sockfd,(struct sockaddr *)&remote,(socklen_t *)&size))<0)
        {
			CommLog (gsLogFile, LOG_ERROR, __FILE__,__LINE__, "accept errno = [%d]", errno);
            continue;
        }
		CommLog (gsLogFile, LOG_ERROR, __FILE__,__LINE__, "accept a client from %s:%d\n",inet_ntoa(remote.sin_addr),ntohs(remote.sin_port));
        pid=fork();
        if(pid==0) 
        {
			set_socket_timeout(sockfd1);
			if (tls_set_socket(&conn, sockfd1) != 1) 
			{
				error_print();
				exit(-1);
			}
			if (tls_do_handshake(&conn) != 1) {
				error_print(); 
				exit(-1);
			}

            /*******************get ip port begin*****************************/
            memset(buffer,0x00, sizeof(buffer));
            memset(host,0x00, sizeof(host));
            memset(sIp, 0x00, sizeof(sIp));
			nRet = tls13_recv(&conn, (uint8_t *)buffer, sizeof(buffer), &len);
			if (nRet != 1)
			{
				error_print();
				printf("tls13_recv fail nRet = [%d]\n", nRet);
				exit(-1);
			}
			CommLog (gsLogFile, LOG_ERROR, __FILE__,__LINE__, "recv buffer= [%s]", buffer);
            if(memcmp(buffer, "CONNECT", 7) == 0 )
            {
                port2 = 443;
                p=strstr(&buffer[0], "\r\n");
                head2tlv(p+2, sIp, &port2);
                LTrim(sIp);
            }
            else if(memcmp(buffer, "GET", 3) == 0 )
            {
                ptr1 = strstr(buffer, "http://");
                ptr2 = strstr(ptr1+7, "/");
                strncpy(sIp, ptr1+7, ptr2-ptr1-7);
                port2 = 80;
                LTrim(sIp);
            }
            else
            {
                close(sockfd1);
				CommLog (gsLogFile, LOG_ERROR, __FILE__,__LINE__, "only support CONNECT GET");
                exit(-1);
            }
			CommLog (gsLogFile, LOG_ERROR, __FILE__,__LINE__, "make a connection to %s:%d....",sIp,port2);

			memset (&hints, 0, sizeof (struct addrinfo));
            hints.ai_family = AF_UNSPEC;
            //hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
			memset(portstr, 0x00, sizeof(portstr));
            snprintf (portstr, sizeof (portstr), "%d", port2);

			if (sigset(SIGTERM, SIGALRM_FUN) == SIG_ERR)
			{
				CommLog (gsLogFile, LOG_ERROR, __FILE__,__LINE__, "sigset error");
                exit(-1);

			}
			alarm(TIMEOUT);
            size = getaddrinfo (sIp, portstr, &hints, &res);
            if (size != 0) 
            {
				CommLog (gsLogFile, LOG_ERROR, __FILE__,__LINE__, "getaddrinfo error");
                exit (-1);
            }
            do {
                sockfd2 = socket (res->ai_family, res->ai_socktype, res->ai_protocol);
                if (sockfd2 < 0)
                {
					CommLog (gsLogFile, LOG_ERROR, __FILE__,__LINE__, "create socket error");
                    continue;      
                }
				/* Bind to the specified address */
                if (bind_to)
				{
                    if (bind_socket (sockfd, bind_to, res->ai_family) < 0) 
					{
                        close (sockfd2);
                        continue;       /* can't bind, so try again */
                    }
                } 
                set_socket_timeout(sockfd2);
                nRet = connect (sockfd2, res->ai_addr, res->ai_addrlen);
                if (nRet == 0)
                {
					CommLog (gsLogFile, LOG_ERROR, __FILE__,__LINE__, "connect success");
                    break;
                }
                else
                {
					//do nothing
                }
            } while ((res = res->ai_next) != NULL);
			alarm(0);
            if (res != NULL) 
            {
                memset(sReply , 0x00, sizeof(sReply));
                sprintf(sReply, "HTTP/1.1 200 Connection established\r\n\r\n");
				if (tls13_send(&conn, (uint8_t *)sReply, strlen(sReply), &size) != 1)
				{
					close(sockfd2);
					CommLog (gsLogFile, LOG_ERROR, __FILE__,__LINE__, "send error");
					exit(-1);
				}
                if (port2 == 80)
                {
                    len=write(sockfd2,buffer,len);
                }
				make_nonblock(sockfd2);
                ts2conn(sockfd1,sockfd2);
            }
            if (res == NULL) 
            {
                memset(sReply , 0x00, sizeof(sReply));
                sprintf(sReply, "Connection: close\r\n\r\n");
				if (tls13_send(&conn, (uint8_t *)sReply, strlen(sReply), &size) != 1)
				{
					close(sockfd2);
					CommLog (gsLogFile, LOG_ERROR, __FILE__,__LINE__, "send error");
					exit(-1);
				}
            }
        }
        else
        {
            close(sockfd1);
        }
    }
}

int bind2conns(int port1,char *host,int port2)
{
    int sockfd,sockfd1,sockfd2;
    struct sockaddr_in remote;
    size_t size;
    int pid;
    char buffer[1024];
    char *p=NULL;
    char sIp[32];
    size_t     len;

	char *certfile = "clientcert.pem";
	char *keyfile = "clientkey.pem";
	char *pass = "1234";
	char *cacertfile = "rootcacert.pem";

	gsLogFile = "client.log";

	memset(&ctx, 0, sizeof(ctx));
	memset(&conn, 0, sizeof(conn));

    memset(buffer,0,1024);
    if((sockfd=create_socket())==0) exit(0);

    if(create_serv(sockfd,port1)==0)
    {
        close(sockfd1);
        exit(0);
	}
	if (tls_ctx_init(&ctx, TLS_protocol_tls13, TLS_client_mode) != 1
			|| tls_ctx_set_cipher_suites(&ctx, client_ciphers, sizeof(client_ciphers)/sizeof(client_ciphers[0])) != 1) 
	{
		CommLog (gsLogFile, LOG_ERROR, __FILE__,__LINE__, "context init error");
		exit(0);
	}
	if (cacertfile) 
	{
		if (tls_ctx_set_ca_certificates(&ctx, cacertfile, TLS_DEFAULT_VERIFY_DEPTH) != 1) 
		{
			CommLog (gsLogFile, LOG_ERROR, __FILE__,__LINE__, "context init error");
			exit(0);
		}
	}
	if (certfile)
	{
		if (tls_ctx_set_certificate_and_key(&ctx, certfile, keyfile, pass) != 1) 
		{
			CommLog (gsLogFile, LOG_ERROR, __FILE__,__LINE__, "context init error");
			exit(0);
		}
	}
	if (tls_init(&conn, &ctx) != 1) 
	{
		CommLog (gsLogFile, LOG_ERROR, __FILE__,__LINE__, "tls_init error");
		exit(0);
	}
    while(1)
    {
        size=sizeof(struct sockaddr);
        //printf("waiting for response.........\n");
        if((sockfd1=accept(sockfd,(struct sockaddr *)&remote,(socklen_t *)&size))<0)
		{
			CommLog (gsLogFile, LOG_ERROR, __FILE__,__LINE__, "accept errno = [%d]", errno);
			continue;
		}
		CommLog (gsLogFile, LOG_ERROR, __FILE__,__LINE__, "accept a client from %s:%d\n",inet_ntoa(remote.sin_addr),ntohs(remote.sin_port));
        pid=fork();
        if(pid==0) 
		{
			len=1024;
			memset(buffer,0x00, sizeof(buffer));
			memset(sIp, 0x00, sizeof(sIp));

			size=read(sockfd1,buffer,len);

			if(memcmp(buffer, "CONNECT", 7) != 0  && memcmp(buffer, "GET", 3) != 0)
			{
				CommLog (gsLogFile, LOG_ERROR, __FILE__,__LINE__, "first req not CONNECT　or GET");
				close(sockfd1);
				exit(0);
			}
			CommLog (gsLogFile, LOG_ERROR, __FILE__,__LINE__, "read buffer = [%s]",buffer);
			sockfd2 = open_tcp_socket(host, port2);
			if(sockfd2 < 0)
			{
				sprintf(buffer,"[SERVER]connection to %s:%d error\r\n",host,port2);
				write(sockfd1,buffer,strlen(buffer));
				memset(buffer,0,1024);
				close(sockfd1);
				exit(0);
			}
			set_socket_timeout(sockfd2);
			make_nonblock(sockfd2);
			CommLog (gsLogFile, LOG_ERROR, __FILE__,__LINE__, "make a connection to %s:%d....success",host,port2);
			if (tls_set_socket(&conn, sockfd2) != 1 || tls_do_handshake(&conn) != 1) 
			{
				CommLog (gsLogFile, LOG_ERROR, __FILE__,__LINE__, "tls_set_socket error or tls_do_handshake error");
				exit(0);
			}

			if (tls13_send(&conn, (uint8_t *)buffer, size, &len) != 1) 
			{
				CommLog (gsLogFile, LOG_ERROR, __FILE__,__LINE__, "send error=[%d]",errno);
				exit(0);
			}
			memset(buffer,0x00, sizeof(buffer));
			if (tls13_recv(&conn, (uint8_t *)buffer, sizeof(buffer), &len) != 1)
			{
				CommLog (gsLogFile, LOG_ERROR, __FILE__,__LINE__, "recv error=[%d]",errno);
				exit(0);
			}
			size=write(sockfd1,buffer,len);
			transdatas(sockfd1,sockfd2);
		}
		else
		{
			close(sockfd1);
		}
    }

}
void transdatas(int fd1,  int fd2)
{
    struct timeval timeset;
    fd_set readfd,writefd;
    int result,i=0;
    char read_in1[MAXSIZE],send_out1[MAXSIZE];
    char read_in2[MAXSIZE],send_out2[MAXSIZE];
    size_t read1=0,totalread1=0,send1=0;
    size_t read2=0,totalread2=0,send2=0;
    size_t sendcount1,sendcount2;
    int maxfd;
    struct sockaddr_in client1,client2;
    int structsize1,structsize2;
    char host1[20],host2[20];
    int  port1=0,port2=0;
    char tmpbuf1[100],tmpbuf2[100];
    int err = 0,  err2=0;

    memset(host1,0,20);
    memset(host2,0,20);
    memset(tmpbuf1,0,100);
    memset(tmpbuf2,0,100);

    maxfd=max(fd1,fd2)+1;
    memset(read_in1,0,MAXSIZE);
    memset(read_in2,0,MAXSIZE);
    memset(send_out1,0,MAXSIZE);
    memset(send_out2,0,MAXSIZE);

    timeset.tv_sec=TIMEOUT;
    timeset.tv_usec=0;
    FD_ZERO(&readfd);
    FD_ZERO(&writefd);

    while(1)
    {
        FD_SET(fd1,&readfd);
        FD_SET(fd2,&readfd);
        result=select(maxfd,&readfd,&writefd,NULL,&timeset);
        if((result<0) && (errno!=EINTR))
        {
			CommLog (gsLogFile, LOG_ERROR, __FILE__,__LINE__, "select error=[%d]",errno);
            break;
        }
        else if(result==0)
        {
			CommLog (gsLogFile, LOG_ERROR, __FILE__,__LINE__, "select timeout");
            break;
        }

        if(FD_ISSET(fd1,&writefd))
        {
			for(;;)
			{
				err2=0;
				sendcount2=0;
				while(totalread2>0)
				{
					send2=write(fd1,send_out2+sendcount2,totalread2);
					if(send2==0)break;
					if((send2<0) && (errno!=EINTR))
					{
						perror("unknow error");
						err2=1;
						break;
					}
					if((send2<0) && (errno==ENOSPC)) break;
					sendcount2+=send2;
					totalread2-=send2;
				}
				//CommLog("gfw11_w_fd1.log", LOG_ERROR, __FILE__,__LINE__, "reply fd1 ");
				//HtDebugString ("gfw11_w_fd1.log", LOG_ERROR, __FILE__,__LINE__, send_out2, sendcount2);
				if(err2==1) break;
				if((totalread2>0) && (sendcount2 > 0))
				{
					memmove(send_out2,send_out2+sendcount2,totalread2);
					memset(send_out2+totalread2,0,MAXSIZE-totalread2);
				}
				else
				{
					memset(send_out2,0,MAXSIZE);
					FD_CLR(fd1,&writefd);
				} 
				if(conn.datalen > 0)
				{
					if (tls13_recv(&conn, (uint8_t *)read_in2, MAXSIZE-totalread2, &read2) != 1)
					{
						CommLog (gsLogFile, LOG_ERROR, __FILE__,__LINE__, "recv from fd1=[%d]", fd1);
						exit(-1);
					}
					if(read2>0) 
					{
						//CommLog("gfw11_sslr_fd2.log", LOG_ERROR, __FILE__,__LINE__, "read from JW_fd2");
						//HtDebugString ("gfw11_sslr_fd2.log", LOG_ERROR, __FILE__,__LINE__, read_in2, read2);
						memcpy(send_out2+totalread2,read_in2,read2);
						totalread2+=read2;
						memset(read_in2,0,MAXSIZE);
						FD_SET(fd1,&writefd);
					}
				}
				else
				{
					break;
				}
			}
        }
        if(FD_ISSET(fd2,&writefd))
        {
            int err=0;
            sendcount1=0;
            while(totalread1>0)
            {
				if (tls13_send(&conn, (uint8_t *)send_out1+sendcount1, totalread1, &send1) != 1) 
                {
					CommLog (gsLogFile, LOG_ERROR, __FILE__,__LINE__, "send error =[%d]", errno);
                    err=1;
                    break;
                }
                if((send1<0) && (errno==ENOSPC)) break;
                sendcount1+=send1;
                totalread1-=send1;
            }
            //CommLog("gfw11_sslw_fd2.log", LOG_ERROR, __FILE__,__LINE__, "req fd2 ");
            //HtDebugString ("gfw11_sslw_fd2.log", LOG_ERROR, __FILE__,__LINE__, send_out1, sendcount1);
            if(err==1) break;
            if((totalread1>0) && (sendcount1>0))
            {
                memmove(send_out1,send_out1+sendcount1,totalread1);
                memset(send_out1+totalread1,0,MAXSIZE-totalread1);
            }
            else
            {
                memset(send_out1,0,MAXSIZE);
                FD_CLR(fd2,&writefd);
            }
        }

        if(FD_ISSET(fd1,&readfd))
        {
            if(totalread1<MAXSIZE)
            {
                read1=read(fd1,read_in1,MAXSIZE-totalread1);
                if(read1==0) break;
                if((read1<0) && (errno!=EINTR))
                {
					CommLog (gsLogFile, LOG_ERROR, __FILE__,__LINE__, "read error =[%d]", errno);
                    break;
                }
                //CommLog("gfw11_r_fd1.log", LOG_ERROR, __FILE__,__LINE__, "read from fd1");
                //HtDebugString ("gfw11_r_fd1.log", LOG_ERROR, __FILE__,__LINE__, read_in1, read1);
                memcpy(send_out1+totalread1,read_in1,read1);
                totalread1+=read1;
                memset(read_in1,0,MAXSIZE);
            }
            FD_SET(fd2,&writefd);
        }
        if(FD_ISSET(fd2,&readfd))
        {
            if(totalread2<MAXSIZE)
            {
				if (tls13_recv(&conn, (uint8_t *)read_in2, MAXSIZE-totalread2, &read2) != 1)
                {
					CommLog (gsLogFile, LOG_ERROR, __FILE__,__LINE__, "recv from fd2=[%d] error", fd2);
					break;
                }
                if(read2>0) 
                {
                    //CommLog("gfw11_sslr_fd2.log", LOG_ERROR, __FILE__,__LINE__, "read from JW_fd2");
                    //HtDebugString ("gfw11_sslr_fd2.log", LOG_ERROR, __FILE__,__LINE__, read_in2, read2);
                    memcpy(send_out2+totalread2,read_in2,read2);
                    totalread2+=read2;
                    memset(read_in2,0,MAXSIZE);
                    FD_SET(fd1,&writefd);
                }
            }
        }
    }
    close(fd1);
	close(fd2);
	tls_ctx_cleanup(&ctx);
	tls_cleanup(&conn);
	CommLog (gsLogFile, LOG_ERROR, __FILE__,__LINE__, "ok,I closed the two fd");
    exit(0);
}
void ts2conn(int fd1,  int fd2)
{
	int pid= getpid();
    struct timeval timeset;
    fd_set readfd,writefd;
    int result,i=0, nRet;
    char read_in1[MAXSIZE],send_out1[MAXSIZE];
    char read_in2[MAXSIZE],send_out2[MAXSIZE];
    size_t read1=0,totalread1=0,send1=0;
    size_t read2=0,totalread2=0,send2=0;
    int sendcount1,sendcount2;
    int maxfd;
    struct sockaddr_in client1,client2;
    int structsize1,structsize2;
    char host1[20],host2[20];
    int port1=0,port2=0;
    char tmpbuf1[100],tmpbuf2[100];
	int err;
    int err2=0;

    memset(host1,0,20);
    memset(host2,0,20);
    memset(tmpbuf1,0,100);
    memset(tmpbuf2,0,100);

    maxfd=max(fd1,fd2)+1;
    memset(read_in1,0,MAXSIZE);
    memset(read_in2,0,MAXSIZE);
    memset(send_out1,0,MAXSIZE);
    memset(send_out2,0,MAXSIZE);

    timeset.tv_sec=TIMEOUT;
    timeset.tv_usec=0;
    FD_ZERO(&readfd);
    FD_ZERO(&writefd);

    while(1)
    {
        FD_SET(fd1,&readfd);
        FD_SET(fd2,&readfd);
        result=select(maxfd,&readfd,&writefd,NULL,&timeset);
        if((result<0) && (errno!=EINTR))
        {
			CommLog(gsLogFile, LOG_ERROR, __FILE__,__LINE__, "select errno=[%d]", errno);
            break;
        }
        else if(result==0)
        {
			CommLog(gsLogFile, LOG_ERROR, __FILE__,__LINE__, "select timeout");
            break;
        }
        if(FD_ISSET(fd1,&writefd))
        {
            err2=0;
            sendcount2=0;
            while(totalread2>0)
            {
				if (tls13_send(&conn, (uint8_t *)send_out2+sendcount2, totalread2, &send2) != 1) 
                if(send2==0)break;
                if((send2<0) && (errno!=EINTR))
                {
					CommLog(gsLogFile, LOG_ERROR, __FILE__,__LINE__, "send error=[%d]", errno);
                    err2=1;
                    break;
                }
                if((send2<0) && (errno==ENOSPC)) 
                {
					CommLog(gsLogFile, LOG_ERROR, __FILE__,__LINE__, "send error=[%d]", errno);
                    break;
                }
                sendcount2+=send2;
                totalread2-=send2;
            }
            //CommLog("gfw21_sslw_fd1.log", LOG_ERROR, __FILE__,__LINE__, "reply fd1 ");
            //HtDebugString ("gfw21_sslw_fd1.log", LOG_ERROR, __FILE__,__LINE__, send_out2, sendcount2);
            if(err2==1) break;
            if((totalread2>0) && (sendcount2 > 0))
            {
                memmove(send_out2,send_out2+sendcount2,totalread2);
                memset(send_out2+totalread2,0,MAXSIZE-totalread2);
            }
            else
            {
                memset(send_out2,0,MAXSIZE);
                FD_CLR(fd1,&writefd);
            } 
        }
        if(FD_ISSET(fd2,&writefd))
        {
			for(;;)
			{
				err=0;
				sendcount1=0;
				while(totalread1>0)
				{
					send1=write(fd2,send_out1+sendcount1,totalread1);
					if(send1==0)break;
					if((send1<0) && (errno!=EINTR ))
					{
						perror("unknow error");
						err=1;
						break;
					}
					if((send1<0) && (errno==ENOSPC)) break;
					sendcount1+=send1;
					totalread1-=send1;
				}
				//CommLog("gfw21_w_fd2.log", LOG_ERROR, __FILE__,__LINE__, "req fd2 ");
				//HtDebugString ("gfw21_w_fd2.log", LOG_ERROR, __FILE__,__LINE__, send_out1, sendcount1);
				if(err==1) exit(-1);
				if((totalread1>0) && (sendcount1>0))
				{
					memmove(send_out1,send_out1+sendcount1,totalread1);
					memset(send_out1+totalread1,0,MAXSIZE-totalread1);
				}
				else
				{
					memset(send_out1,0,MAXSIZE);
					FD_CLR(fd2,&writefd);
				}
				if (conn.datalen > 0) 
				{
					nRet = tls13_recv(&conn, (uint8_t *)read_in1, MAXSIZE-totalread1, &read1);
					if(nRet != 1)
					{
						CommLog(gsLogFile, LOG_ERROR, __FILE__,__LINE__, "recv fail nRet = [%d]", nRet);
						exit(-1);
					}
					//CommLog("gfw21_sslr_fd1.log", LOG_ERROR, __FILE__,__LINE__, "read from fd1");
					//HtDebugString ("gfw21_sslr_fd1.log", LOG_ERROR, __FILE__,__LINE__, read_in1, read1);
					memcpy(send_out1+totalread1,read_in1,read1);
					totalread1+=read1;
					memset(read_in1,0,MAXSIZE);
				}
				else
				{
					break;
				}
			}
        }
        if(FD_ISSET(fd1,&readfd))
        {
            if(totalread1<MAXSIZE)
            {
				nRet = tls13_recv(&conn, (uint8_t *)read_in1, MAXSIZE-totalread1, &read1);
				if (nRet != 1)
                {
					CommLog (gsLogFile, LOG_ERROR, __FILE__,__LINE__, "recv errno=[%d]",errno);
                    break;
                }
				else
				{
					//CommLog("gfw21_sslr_fd1.log", LOG_ERROR, __FILE__,__LINE__, "read from fd1");
					//HtDebugString ("gfw21_sslr_fd1.log", LOG_ERROR, __FILE__,__LINE__, read_in1, read1);
					memcpy(send_out1+totalread1,read_in1,read1);
					totalread1+=read1;
					memset(read_in1,0,MAXSIZE);
					FD_SET(fd2,&writefd);
				}
            }
        }

        if(FD_ISSET(fd2,&readfd))
        {
            //printf("read from  fd2=[%d]\n", fd2);
            if(totalread2<MAXSIZE)
            {
                read2=read(fd2,read_in2,MAXSIZE-totalread2);
                if(read2==0) break;
                if((read2<0) && (errno!=EINTR))
                {
                    perror("read data error");
                    break;
                }
				if(read2 > 0)
				{
					//CommLog("gfw21_r_fd2.log", LOG_ERROR, __FILE__,__LINE__, "read from JW_fd2");
					//HtDebugString ("gfw21_r_fd2.log", LOG_ERROR, __FILE__,__LINE__, read_in2, read2);
					memcpy(send_out2+totalread2,read_in2,read2);
					totalread2+=read2;
					memset(read_in2,0,MAXSIZE);
					FD_SET(fd1,&writefd);
				}
           }
        }
    }
	close(fd1);
	tls_ctx_cleanup(&ctx);
	tls_cleanup(&conn);
    close(fd2);
	CommLog (gsLogFile, LOG_ERROR, __FILE__,__LINE__, "ok,I closed the two fd ");
    exit(0);
}


int create_socket()
{
    int sockfd;

    sockfd=socket(AF_INET,SOCK_STREAM,0);
    if(sockfd<0)
    {
        perror("create socket error");
        return(0);
    }
    return(sockfd);
}

int create_serv(int sockfd,int port)
{
    struct sockaddr_in srvaddr;
    int on=1;

    bzero(&srvaddr,sizeof(struct sockaddr));
    srvaddr.sin_port=htons(port);
    srvaddr.sin_family=AF_INET;
    srvaddr.sin_addr.s_addr=htonl(INADDR_ANY);

    setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on)); //so I can rebind the port
    if(bind(sockfd,(struct sockaddr *)&srvaddr,sizeof(struct sockaddr))<0)
	{
		perror("error");
		return(0);
	}
    if(listen(sockfd,CONNECT_NUMBER)<0)
	{
		perror("listen error\n");
		return(0);
	}
    return(1);
}
int dnsResolve(const char *hostname, char *ip)
{    
    struct in_addr  ip_addr;    
    struct hostent  *host;
    char           **pptr;    
    host = gethostbyname(hostname);
    if(!host)
       return -1;
    pptr = host->h_addr_list;
    if(!inet_ntop(host->h_addrtype, *pptr, ip, 15))    
    {   return -2;
    }
    return 0;
}
void make_nonblock(int fd)
{
    int flags;
    if((flags = fcntl(fd, F_GETFL, 0)) < 0)
    {
            return ;
    }
    flags |= O_NONBLOCK;
    fcntl(fd,F_SETFL, flags);
}

void make_block(int fd) {
    int flags;
    if((flags = fcntl(fd, F_GETFL, 0)) < 0) {
        return ;
    }
    flags &= ~O_NONBLOCK;
    fcntl(fd,F_SETFL, flags);
}

int head2tlv(char *InBuf, char *sIp, int *port)
{
    char sTmp[512+1],sTag[128+1],sTlv[512+1];
    char *p = NULL;
    char *pp = NULL;
    char *ptr =NULL;
    char *ptr1 =NULL;
    char *h = NULL;

    pp = InBuf;
    while(pp != NULL)
    {
        p = pp;
        ptr1 = strstr(p, "\r\n");
        if(ptr1 == NULL)
        {
            printf("解析结束退出程序!!!\n");
            return -1;
        }
        pp = ptr1+2;
        memset(sTmp, 0x00, sizeof(sTmp));
        memcpy(sTmp, p, ptr1 - p);
        printf("sTmp[%s]\n",sTmp);
        ptr = sTmp;
        ptr1 = strstr(sTmp, ":");
        memset(sTag, 0x00, sizeof(sTag));
        memcpy(sTag, sTmp, ptr1 - ptr);
        printf("sTag[%s]=",sTag);
        memset(sTlv, 0x00, sizeof(sTlv));
        strcpy(sTlv, sTmp + (ptr1 - ptr)+1);
        printf("sTlv[%s]", sTlv);
        if(strncmp(sTag, "Host", 4) == 0)
        {
            h = strstr(sTlv, ":"); 
            if(h == NULL)
            {
                strcpy(sIp, sTlv);
                //*port = 0;
            }
            else
            {
                memcpy(sIp, sTlv, h-sTlv);
                *port = atoi(h+1);
            }
            printf("sIp=[%s]\n", sIp);
            printf("port=[%d]\n", *port);
        
            break;
        }
    }
    return 0;
}

int RTrim(char *caDest)
{
    int i;
    for( i=strlen(caDest)-1 ; i>=0 ; i-- )
    {
        if( caDest[i] !=' ')
        {
            break;
        }
    }
    caDest[i+1] = 0;
    return 0;
}

int LTrim( char *caDest )
{
    int i,j;
    char lsTmp[4096];                                                                                  
    memset(lsTmp, 0, sizeof(lsTmp));                                                                   

    for( i = 0, j=0; i< strlen(caDest) ; i++)                                                              
    {                                                                                                  
        if( caDest[i] ==' ')                                                                           
        {                                                                                              
            continue;                                                                                  
        }                                                                                              
        lsTmp[j] = caDest[i];                                                                          
        j++;
    }                                                                                                  
    lsTmp[j] = 0x00;
    strcpy(caDest, lsTmp);                                                                             
    return 0;                                                                                          
}              
void set_socket_timeout(int fd)
{
    struct timeval tv;
    tv.tv_usec = 0;
    tv.tv_sec = 2;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (void*) &tv, sizeof(tv));
    tv.tv_usec = 0;
    tv.tv_sec = 2;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (void*) &tv, sizeof(tv));
}

int open_tcp_socket(char *hostname, int portnumber)
{
    int err, fd;
    struct hostent *p;
    uint8_t *ip;
    struct sockaddr_in sock;

    printf("hostname %s\n", hostname);

    p = gethostbyname(hostname);

    if (p == NULL) {
        herror("gethostbyname");
        return -1;
    }
    ip = (uint8_t *) p->h_addr;
    printf("host ip %d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    sock.sin_family = AF_INET;
    sock.sin_port = htons(portnumber);
    memcpy(&sock.sin_addr.s_addr, ip, 4);

    err = connect(fd, (struct sockaddr *) &sock, sizeof sock);

    if (err) {
        close(fd);
        perror("connect");
        return -1;
    }
    // set nonblocking
    err = fcntl(fd, F_SETFL, O_NONBLOCK);
    if (err == -1) {
        close(fd);
        perror("fcntl");
        return -1;
    }
    return fd;
}

void SIGALRM_FUN()
{
	int pid = getpid();
	CommLog (gsLogFile, LOG_ERROR, __FILE__,__LINE__, "SIGALRM_FUN　pid=[%d]",pid);
	exit(0);
}

int bind_socket (int sockfd, const char *addr, int family)
{
        struct addrinfo hints, *res, *ressave;
        int n;

        //assert (sockfd >= 0);
        //assert (addr != NULL && strlen (addr) != 0);

        memset (&hints, 0, sizeof (struct addrinfo));
        hints.ai_family = family;
        hints.ai_socktype = SOCK_STREAM;

        /* The local port is not important */
        n = getaddrinfo (addr, NULL, &hints, &res);
        if (n != 0) {
                printf("bind_socket: getaddrinfo failed for %s: %s (af: %s)", addr, get_gai_error (n), family_string(family));
                return -1;
        }

        ressave = res;

        /* Loop through the addresses and try to bind to each */
        do {
                if (bind (sockfd, res->ai_addr, res->ai_addrlen) == 0)
                        break;  /*success */
        } while ((res = res->ai_next) != NULL);

        freeaddrinfo (ressave);
        if (res == NULL)        /* was not able to bind to any address */
                return -1;

        return sockfd;
}

static const char * get_gai_error (int n)
{
        if (n == EAI_SYSTEM)
                return strerror (errno);
        else
                return gai_strerror (n);
}

static const char * family_string (int af)
{
        switch(af) {
        case AF_UNSPEC: return "AF_UNSPEC";
        case AF_INET:   return "AF_INET";
        case AF_INET6:  return "AF_INET6";
        }
        return "unknown";
}
