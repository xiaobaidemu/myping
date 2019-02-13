//
// Created by 贺小白 on 2019/1/20.
//
#include<stdio.h>
#include<stdlib.h>
#include<sys/time.h>
#include<unistd.h>
#include<string.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<netdb.h>
#include<errno.h>
#include<arpa/inet.h>
#include<signal.h>
#include<netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/in_systm.h>
#define BUFSIZE 150     //发送缓存最大值
#define SLEEP_TIME 1000000

//数据类型别名
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

char hello[]="HELLO WORLD,xiaobai.";

char sendbuf[BUFSIZE];
char recvbuf[BUFSIZE];
int nsent = 0;//发送的ICMP消息序号
int nrecv = 0;
pid_t pid;//ping程序的进程pid
struct timeval sendtime; //发送ICMP的时间戳
struct timeval recvtime; //收到ICMP应答的时间戳
int sockfd; //发送和接收原始套接字
struct sockaddr_in dest;//被ping主机的ip
struct sockaddr_in from;//发送ping应答消息的主机ip
volatile int loop = 1;

//函数原型
void int_handler(int);//SIGINT处理程序
void send_ping();//发送ping消息
void recv_reply();//接收ping应答
u16 checksum(u8 *buf,int len);//计算校验和
void get_statistics(int ,int, struct timeval);//统计ping命令的检测结果
void bail(const char *);//错误报告
int main(int argc,char **argv)
{
    struct hostent *host;

    if(argc<2){
        printf("Usage: %s hostname\n",argv[0]);
        exit(1);
    }

    if((host=gethostbyname(argv[1]))==NULL)
    {
        perror("can not understand the host name");   //理解不了输入的地址
        exit(1);
    }

    memset(&dest,0,sizeof dest);
    dest.sin_family=host->h_addrtype;
    dest.sin_port=ntohs(0);
    dest.sin_addr=*(struct in_addr *)host->h_addr;// #define h_addr h_addr_list[0]

    // SOCK_RAW 用于直接访问网络层，应用程序负责构造自己的协议首部, IPPROTO_ICMP为指定使用icmp协议进行通信
    if((sockfd = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP))<0)
    {
        perror("SOCK_RAW type socket creates fail");
        exit(1);
    }

    pid=getpid();
    signal(SIGINT, int_handler);
    printf("PING %s(%s) %d(%d) bytes of data.\n",argv[1],inet_ntoa(dest.sin_addr),56, 56+sizeof(struct icmp));
    struct timeval total_start;
    gettimeofday(&total_start, NULL);
    // 改为定时器触发

    while(loop){
        gettimeofday(&sendtime, NULL);
        send_ping();
        recv_reply();//接收ping应答
        usleep(SLEEP_TIME);
    }
    get_statistics(nsent,nrecv, total_start);     //统计ping命令的检测结果
    close(sockfd);  //关闭网络套接字
    return 0;
}
//发送ping消息
void send_ping()
{
    struct icmp *icmp;
    //struct icmp 位于<netinet/icmp.h>, 也可以换为struct icmphdr，位于<linux/ip.h>。struct icmp为28字节(前8字节和icmphdr相同，都定义了icmp报头，
    // 后20字节暂时不明白什么意思，对于icmp报文来说都是用户定义数据部分，我们只需要icmp->icmp_data部分,
    // 从侧面可以说明icmp报文的数据部分有一个最小值，数据部分至少需要20字节)， struct icmphdr为8字节
    icmp=(struct icmp *)(sendbuf);
    icmp->icmp_type=ICMP_ECHO;//初始化ICMP消息类型type
    icmp->icmp_code=0;    //初始化消息代码code
    icmp->icmp_id=(unsigned short)pid;   //把进程标识码初始给icmp_id
    icmp->icmp_seq=(unsigned short)nsent++;  //发送的ICMP消息序号赋值给icmp序号
    gettimeofday((struct timeval *)icmp->icmp_data,NULL); // 获取当前时间
    memcpy(icmp->icmp_data+sizeof(struct timeval), hello, strlen(hello));
    size_t len=8+sizeof(struct timeval)+strlen(hello);
    icmp->icmp_cksum=0;    //初始化
    icmp->icmp_cksum=checksum((u8 *)icmp,len);  //计算校验和
    sendto(sockfd,sendbuf,len ,0, (struct sockaddr *)&dest,sizeof (dest)); //经socket传送数据
}
//接收程序发出的ping命令的应答

int receive_icmp_package()
{
    socklen_t len = sizeof(from); //一定要对len进行初始化
    int errno;
    int recvlen;
    while((recvlen = recvfrom(sockfd,recvbuf,sizeof recvbuf,0,(struct sockaddr *)&from,&len))<0){
        if(errno==EINTR)  //EINTR 慢系统调用被中断，对于read来说重试即可
            continue;
        else{
            bail("recvfrom error");
            break;
        }
    }
    return recvlen;
}
void recv_reply()
{
    int recvlen = receive_icmp_package();
    gettimeofday(&recvtime,NULL);
    int ret_code;
    if(ret_code = handle_pkt(recvlen))
        if(ret_code == -2)
        {
            recvlen = receive_icmp_package();
            if (handle_pkt(recvlen)){
                bail("error in handle_pkt second time");
            }
        }
        else
            bail("error in handle_pkt");
    nrecv++;

}
//计算校验和
u16 checksum(u8 *buf,int len)
{
    u32 sum=0; u16 *cbuf;
    cbuf=(u16 *)buf;
    while(len>1) {
        sum+=*cbuf++;
        len-=2;
    }
    if(len)
        sum+=*(u8 *)cbuf;
    sum=(sum>>16)+(sum & 0xffff);
    sum+=(sum>>16);
    return ~sum;
}
//ICMP应答消息处理
int handle_pkt(int len) {
    struct ip *ip;
    struct icmp *icmp;

    int ip_hlen, icmplen;
    double rtt; // 往返时间

    ip = (struct ip *) recvbuf;

    ip_hlen = ip->ip_hl << 2; //相当于ip首部长度位*4 ，4表示4字节为单位
    icmp = (struct icmp *) (recvbuf + ip_hlen);
    icmplen = len - ip_hlen;
    u16 sum = (u16) checksum((u8 *) icmp, icmplen);
    //计算校验和
    if (sum) {
        printf("checksum error");
        return -1;
    }
    if (icmp->icmp_id != pid) {
        printf("icmp_id is not same with sender");
        return -1;
    }
    if (icmp->icmp_type != ICMP_ECHOREPLY){
        //重新等待接受
        return -2;

    }
    struct timeval sendtime=*(struct timeval *)(icmp->icmp_data); //发送时间
    rtt=(recvtime.tv_sec-sendtime.tv_sec)*1000+(recvtime.tv_usec-sendtime.tv_usec)/1000.0;
    //打印结果
    printf("%d bytes from %s(%s): icmp_seq=%u ttl=%d time=%.1f ms (%s)\n",
           icmplen, //icmp数据长度
           inet_ntoa(from.sin_addr),    //icmp reply来自于 ip地址
           inet_ntoa(from.sin_addr),
           icmp->icmp_seq, //icmp报文序列号
           ip->ip_ttl,  //生存时间
           rtt,//往返时间
           (char*)(icmp->icmp_data+sizeof(struct timeval)));
    return 0;
}

//统计ping命令的检测结果
void get_statistics(int nsent,int nrecv, struct timeval total_start)
{
    struct timeval total_end;
    gettimeofday(&total_end, NULL);
    double delta_time = (total_end.tv_sec-total_start.tv_sec)*1000 + (total_end.tv_usec+total_start.tv_usec)/1000.0;
    printf("--- %s ping statistics ---\n",inet_ntoa(dest.sin_addr)); //将网络地址转换成“.”点隔的字符串格式。
    printf("%d packets transmitted, %d received, %0.0f%% ""packet loss, time %.1fms\n",
           nsent,nrecv,1.0*(nsent-nrecv)/nsent*100, delta_time);
}
//错误报告
void bail(const char * on_what)
{
    fputs(strerror(errno),stderr);  //:向指定的文件写入一个字符串（不写入字符串结束标记符‘\0’）。成功写入一个字符串后，文件的位置指针会自动后移，函数返回值为0；否则返回EOR(符号常量，其值为-1)。
    fputs(":",stderr);
    fputs(on_what,stderr);
    fputc('\n',stderr); //送一个字符到一个流中
    exit(1);
}

//SIGINT（中断信号）处理程序
void int_handler(int dummy)
{
    loop = 0;
}



