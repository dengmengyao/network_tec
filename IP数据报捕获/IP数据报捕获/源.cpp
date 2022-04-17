#include <Winsock2.h>
#include<iostream>
#include "pcap.h"
#include "stdio.h"
#include<time.h>
#include <fstream>
#include <stdint.h>
#include <cstring>
#include <windows.h>
#include <stdio.h>
#include <process.h>
using namespace std;
#define MY_MSG WM_USER+101
#pragma pack(1)		//进入字节对齐方式
typedef struct FrameHeader_t {	//帧首部
    BYTE	DesMAC[6];	// 目的地址
    BYTE 	SrcMAC[6];	// 源地址
    WORD	FrameType;	// 帧类型
} FrameHeader_t;
typedef struct IPHeader_t {		//IP首部
    WORD	Ver_HLen_TOS;
    WORD	TotalLen;
    WORD	ID;
    WORD	Flag_Segment;
    WORD	TTL_Protocol;
    WORD	Checksum;
    ULONG	SrcIP;
    ULONG	DstIP;
} IPHeader_t;
typedef struct Data_t {	//包含帧首部和IP首部的数据包
    FrameHeader_t	FrameHeader;
    IPHeader_t		IPHeader;
} Data_t;
#pragma pack()	//恢复缺省对齐方式

void ip_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr*
    packet_header, const u_char* packet_content);//获取网络接口设备列表

string char2mac(BYTE* MAC)//目的地址与源地址
{
    string ans;
    char temp[100];
    sprintf_s(temp, "%02X-%02X-%02X-%02X-%02X-%02X", int(MAC[0]), int(MAC[1]), int(MAC[2]), int(MAC[3]), int(MAC[4]), int(MAC[5]));
    ans = temp;
    return ans;
}



/* 将数字类型的IP地址转换成字符串类型的 */
string long2ip(DWORD in)//对应的IP地址
{
    string ans;
    DWORD mask[] = { 0xFF000000,0x00FF0000,0x0000FF00,0x000000FF };
    DWORD num[4];

    num[0] = in & mask[0];
    num[0] = num[0] >> 24;
    num[1] = in & mask[1];
    num[1] = num[1] >> 16;
    num[2] = in & mask[2];
    num[2] = num[2] >> 8;
    num[3] = in & mask[3];

    char temp[100];
    sprintf_s(temp, "%d.%d.%d.%d", num[0], num[1], num[2], num[3]);
    ans = temp;
    return ans;
}

USHORT checksum(USHORT* buffer, int size)//校验和计算
{
    unsigned long cksum = 0;
    int i = 0;
    WORD w;
    while (size > 1)
    {
        if (i != 5)
        {
            w = (WORD)(*buffer);
            w = ntohs(w);
            cksum += w;
        }
        buffer++;

        ++i;
        size -= sizeof(USHORT);
    }
    if (size)
    {
        cksum += *(UCHAR*)buffer;
    }
    cksum = (cksum >> 16) + (cksum & 0xFFFF);
    cksum += (cksum >> 16);
    return (USHORT)(~cksum);
}

void ip_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr*
    packet_header, const u_char* packet_content)//输出对应的参数
{
    Data_t* IPPacket;
    ULONG		SourceIP, DestinationIP;
    IPPacket = (Data_t*)packet_content;
    WORD Kind = ntohs(IPPacket->FrameHeader.FrameType);
    SourceIP = ntohl(IPPacket->IPHeader.SrcIP);
    DestinationIP = ntohl(IPPacket->IPHeader.DstIP);
    USHORT* buffer = (USHORT*)(packet_content + 14);
    WORD v = ntohs(IPPacket->IPHeader.Ver_HLen_TOS);
    WORD t = 0x0F00;
    t = t & v;
    t = t >> 8;
    int len_head = int(t) * 4;
    cout << "******************************************" << endl;
    cout << "计算所得校验和\t\t:" << checksum(buffer, len_head) << endl;
    cout << "目的MAC地址\t\t:" << char2mac(IPPacket->FrameHeader.DesMAC) << endl;
    cout << "源MAC地址\t\t:" << char2mac(IPPacket->FrameHeader.SrcMAC) << endl;
    cout << "源IP地址:\t\t:" << long2ip(SourceIP) << endl;
    cout << "目的IP地址\t\t:" << long2ip(DestinationIP) << endl;
    cout << "******************************************" << endl;
}

int main()
{
    cout << "==========    解析IP数据包    ==========\n";
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int netcard_id = 0;//需要打开的网卡号
    int i = 0;
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)//获得网卡列表
    {
        printf("获得网卡列表错误\n");
        exit(1);
    }
    for (d = alldevs; d; d = d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }
    if (i == 0)
    {
        printf("没有发现网卡\n");
        exit(1);
    }
    printf("\n**输入要选择打开的网卡号 (1-%d)**:\t", i);
    scanf_s("%d", &netcard_id);               //输入要选择打开的网卡号
    //此时要选择正在联网的网卡,如果你不知道就一个个试
    if (netcard_id < 1 || netcard_id > i) //判断网卡号的合法性
    {
        printf("\n网卡号超出范围\n");
        pcap_freealldevs(alldevs);
        exit(1);
    }
    // 找到要选择的网卡结构
    for (d = alldevs, i = 0; i < netcard_id - 1; d = d->next, i++);

    if ((adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL)
    {

        pcap_freealldevs(alldevs);
        exit(1);
    }

    printf("\n监听 %s...\n", d->description);

    pcap_freealldevs(alldevs);

    int number = -1;
    cout << "请输入要解析的IP数据包数量：";
    cin >> number;
    cout << endl;

    pcap_loop(adhandle, number, ip_protocol_packet_callback, NULL);
    int ret;

    cout << "\n\t解析IP数据包结束\n";
    return 0;
}