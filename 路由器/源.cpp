#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "Head.h"
#pragma comment(lib,"ws2_32.lib")//链接ws2_32.lib库文件到此项目中
#include <stdio.h>
//宏定义
#define PACAP_ERRBUF_SIZE 10
#define MAX_IP_NUM 10

log ltable;
//多线程
HANDLE hThread;
DWORD dwThreadId;

int index;
int main()
{
	scanf("%d", &index);
	//const char* 到char*的转换
	pcap_src_if_string = new char[strlen(PCAP_SRC_IF_STRING)];
	strcpy(pcap_src_if_string, PCAP_SRC_IF_STRING);

	find_alldevs();//获取本机ip

	for (int i = 0; i < 2; i++)//输出此时存储的IP地址与MAC地址
	{
		printf("%s\t", ip[i]);
		printf("%s\n", mask[i]);
	}
	getselfmac(inet_addr(ip[0]));
	getmac(selfmac);
	BYTE mac[6];
	int op;
	routetable rtable;
	hThread = CreateThread(NULL, NULL, handlerRequest, LPVOID(&rtable), 0, &dwThreadId);
	routeitem a;
	while (1)
	{
		printf("1添加路由表项，2删除路由表项，3打印路由表: ");
		scanf("%d", &op);
		if (op == 1)
		{
			routeitem a;
			char t[30];
			printf("请输入掩码：");
			scanf("%s", &t);
			a.mask = inet_addr(t);
			printf("请输入目的网络：");
			scanf("%s", &t);
			a.net = inet_addr(t);
			printf("请输入下一跳地址：");
			scanf("%s", &t);
			a.nextip = inet_addr(t);
			a.type = 1;
			rtable.add(&a);
		}
		else if (op == 2)
		{
			printf("请输入删除表项编号：");
			int index;
			scanf("%d", &index);
			rtable.remove(index);
		}
		else if (op == 3)
		{
			rtable.print();
		}
		else {
			printf("无效操作，请重新选择\n");
		}
	}
	routetable table;
	table.print();
	return 0;
}
//函数定义


//获取对应网卡网卡号与IP地址
void find_alldevs()	//获取网卡上的IP
{
	if (pcap_findalldevs_ex(pcap_src_if_string, NULL, &alldevs, errbuf) == -1)
	{
		printf("%s", "error");
	}
	else
	{
		int i = 0;
		d = alldevs;
		for (; d != NULL; d = d->next)//获取该网络接口设备的ip地址信息
		{
			if (i == index)
			{
				net[i] = d;
				int t = 0;
				for (a = d->addresses; a != nullptr; a = a->next)
				{
					if (((struct sockaddr_in*)a->addr)->sin_family == AF_INET && a->addr)
					{
						printf("%d ", i);
						printf("%s\t", d->name, d->description);
						printf("%s\t%s\n", "IP地址:", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
						//存储对应IP地址与MAC地址
						strcpy(ip[t], inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
						strcpy(mask[t++], inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));
					}
				}
				ahandle = open(d->name);//打开该网卡
			}
			i++;
		}
	}
	pcap_freealldevs(alldevs);
}

pcap_t* open(char* name)//打开网络接口
{
	pcap_t* temp = pcap_open(name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 100, NULL, errbuf);
	if (temp == NULL)
		printf("error");
	return temp;
}

int compare(BYTE a[6], BYTE b[6])//识别比较IP地址与MAC地址，过滤报文
{
	int index = 1;
	for (int i = 0; i < 6; i++)
	{
		if (a[i] != b[i])
			index = 0;
	}
	return index;
}

void getselfmac(DWORD ip)//获得本地IP地址以及对应的MAC地址
{
	memset(selfmac, 0, sizeof(selfmac));
	ARPFrame_t ARPFrame;
	//将APRFrame.FrameHeader.DesMAC设置为广播地址
	for (int i = 0; i < 6; i++)
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;
	//将APRFrame.FrameHeader.SrcMAC设置为本机网卡的MAC地址

	ARPFrame.FrameHeader.SrcMAC[0] = 0x0f;
	ARPFrame.FrameHeader.SrcMAC[1] = 0x0f;
	ARPFrame.FrameHeader.SrcMAC[2] = 0x0f;
	ARPFrame.FrameHeader.SrcMAC[3] = 0x0f;
	ARPFrame.FrameHeader.SrcMAC[4] = 0x0f;
	ARPFrame.FrameHeader.SrcMAC[5] = 0x0f;

	ARPFrame.FrameHeader.FrameType = htons(0x806);//帧类型为ARP
	ARPFrame.HardwareType = htons(0x0001);//硬件类型为以太网
	ARPFrame.ProtocolType = htons(0x0800);//协议类型为IP
	ARPFrame.HLen = 6;//硬件地址长度为6
	ARPFrame.PLen = 4;//协议地址长为4
	ARPFrame.Operation = htons(0x0001);//操作为ARP请求

	//将ARPFrame.SendHa设置为本机网卡的MAC地址
	ARPFrame.SendHa[0] = 0x0f;
	ARPFrame.SendHa[1] = 0x0f;
	ARPFrame.SendHa[2] = 0x0f;
	ARPFrame.SendHa[3] = 0x0f;
	ARPFrame.SendHa[4] = 0x0f;
	ARPFrame.SendHa[5] = 0x0f;
	//将ARPFrame.SendIP设置为本机网卡上绑定的IP地址
	ARPFrame.SendIP = inet_addr("122.122.122.122");
	//将ARPFrame.RecvHa设置为0
	for (int i = 0; i < 6; i++)
		ARPFrame.RecvHa[i] = 0;

	ARPFrame.RecvIP = ip;

	u_char* h = (u_char*)&ARPFrame;
	int len = sizeof(ARPFrame_t);


	if (ahandle == nullptr) printf("网卡接口打开错误\n");
	else
	{
		if (pcap_sendpacket(ahandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
		{
			//发送错误处理
			printf("senderror\n");
		}
		else
		{
			//发送成功
			while (1)
			{
				//printf("send\n");
				pcap_pkthdr* pkt_header;
				const u_char* pkt_data;
				int rtn = pcap_next_ex(ahandle, &pkt_header, &pkt_data);
				if (rtn == 1)
				{
					ARPFrame_t* IPPacket = (ARPFrame_t*)pkt_data;
					if (ntohs(IPPacket->FrameHeader.FrameType) == 0x806)
					{//输出目的MAC地址
						if (!compare(IPPacket->FrameHeader.SrcMAC, ARPFrame.FrameHeader.SrcMAC) && compare(IPPacket->FrameHeader.DesMAC, ARPFrame.FrameHeader.SrcMAC))
						{
							ltable.write2log_arp(IPPacket);
							//输出源MAC地址，源MAC地址即为所需MAC地址
							for (int i = 0; i < 6; i++)
								selfmac[i] = IPPacket->FrameHeader.SrcMAC[i];
							break;//已经捕获到了MAC地址，因此退出
						}
					}
				}
			}
		}
	}
}

void getothermac(DWORD ip_, BYTE mac[])//获取目的ip对应的mac
{
	memset(mac, 0, sizeof(mac));
	ARPFrame_t ARPFrame;
	//将APRFrame.FrameHeader.DesMAC设置为广播地址
	for (int i = 0; i < 6; i++)
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;
	//将APRFrame.FrameHeader.SrcMAC设置为本机网卡的MAC地址
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.SrcMAC[i] = selfmac[i];
		ARPFrame.SendHa[i] = selfmac[i];

	}

	ARPFrame.FrameHeader.FrameType = htons(0x806);//帧类型为ARP
	ARPFrame.HardwareType = htons(0x0001);//硬件类型为以太网
	ARPFrame.ProtocolType = htons(0x0800);//协议类型为IP
	ARPFrame.HLen = 6;//硬件地址长度为6
	ARPFrame.PLen = 4;//协议地址长为4
	ARPFrame.Operation = htons(0x0001);//操作为ARP请求

	//将ARPFrame.SendIP设置为本机网卡上绑定的IP地址
	ARPFrame.SendIP = inet_addr(ip[0]);
	//ipprint(ARPFrame.SendIP);
	//将ARPFrame.RecvHa设置为0
	for (int i = 0; i < 6; i++)
		ARPFrame.RecvHa[i] = 0;
	//将ARPFrame.RecvIP设置为请求的IP地址

	ARPFrame.RecvIP = ip_;

	u_char* h = (u_char*)&ARPFrame;
	int len = sizeof(ARPFrame_t);

	if (ahandle == nullptr) printf("网卡接口打开错误\n");
	else
	{
		if (pcap_sendpacket(ahandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
		{
			//发送错误处理
			printf("senderror\n");
		}
		else
		{
			//发送成功
			while (1)
			{
				//printf("send\n");
				pcap_pkthdr* pkt_header;
				const u_char* pkt_data;
				int rtn = pcap_next_ex(ahandle, &pkt_header, &pkt_data);
				//pcap_sendpacket(ahandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t));
				if (rtn == 1)
				{
					ARPFrame_t* IPPacket = (ARPFrame_t*)pkt_data;
					if (ntohs(IPPacket->FrameHeader.FrameType) == 0x806)
					{//输出目的MAC地址
						if (!compare(IPPacket->FrameHeader.SrcMAC, ARPFrame.FrameHeader.SrcMAC) && compare(IPPacket->FrameHeader.DesMAC, ARPFrame.FrameHeader.SrcMAC) && IPPacket->SendIP == ip_)//&&ip==IPPacket->SendIP
						{

							ltable.write2log_arp(IPPacket);
							//输出源MAC地址
							for (int i = 0; i < 6; i++)
								mac[i] = IPPacket->FrameHeader.SrcMAC[i];
							break;
						}
					}
				}
			}
		}
	}
}

void getmac(BYTE MAC[])//打印mac
{
	printf("MAC地址为： ");
	for (int i = 0; i < 5; i++)
		printf("%02X-", MAC[i]);
	printf("%02X\n", MAC[5]);
}

void routetable::add(routeitem* a)
{
	routeitem* pointer;
	//找到合适的地方
	//默认路由,一定是最开始的时候添加
	if (!a->type)//直接投递
	{
		a->nextitem = head->nextitem;
		head->nextitem = a;
		a->type = 0;
	}
	//其它，按照掩码由长至短找到合适的位置
	else
	{
		for (pointer = head->nextitem; pointer != tail && pointer->nextitem != tail; pointer = pointer->nextitem)//head有内容，tail没有
		{
			if (a->mask < pointer->mask && a->mask >= pointer->nextitem->mask || pointer->nextitem == tail)
				break;
		}
		a->nextitem = pointer->nextitem;
		pointer->nextitem = a;//插入到合适位置
		//a->type = 1;
	}
	routeitem* p = head->nextitem;
	for (int i = 0; p != tail; p = p->nextitem, i++)
	{
		p->index = i;
	}
	num++;
}

void routeitem::printitem()//打印路由表
{

	//index mask net nextip
	in_addr addr;
	printf("%d   ", index);
	addr.s_addr = mask;
	char* pchar = inet_ntoa(addr);
	printf("%s\t", pchar);

	addr.s_addr = net;
	pchar = inet_ntoa(addr);
	printf("%s\t", pchar);

	addr.s_addr = nextip;
	pchar = inet_ntoa(addr);
	printf("%s\t\t", pchar);

	printf("%d\n", type);
}

void routetable::print()//打印路由表
{
	routeitem* p = head->nextitem;
	for (; p != tail; p = p->nextitem)
	{
		p->printitem();
	}
}

routetable::routetable()//初始化，添加直接连接的网络
{
	head = new routeitem;
	tail = new routeitem;
	head->nextitem = tail;
	num = 0;
	for (int i = 0; i < 2; i++)
	{
		routeitem* temp = new routeitem;
		//本机网卡的ip 和掩码进行按位与即为所在网络
		temp->net = (inet_addr(ip[i])) & (inet_addr(mask[i]));
		temp->mask = inet_addr(mask[i]);
		temp->type = 0;//0表示直接投递的网络，不可删除
		this->add(temp);//添加表项
	}
}

void routetable::remove(int index)//删除路由表项
{

	for (routeitem* t = head; t->nextitem != tail; t = t->nextitem)
	{
		if (t->nextitem->index == index)
		{
			if (t->nextitem->type == 0)//直接投递的路由表项不可删除
			{
				printf("该项不可删除\n");
				return;
			}
			else
			{
				t->nextitem = t->nextitem->nextitem;
				return;
			}
		}
	}
	printf("无该表项\n");
}


//接收数据报
int iprecv(pcap_pkthdr* pkt_header, const u_char* pkt_data)
{
	int rtn = pcap_next_ex(ahandle, &pkt_header, &pkt_data);
	return rtn;
}


//数据报转发,修改源mac和目的mac
void resend(ICMP_t data, BYTE dmac[])
{
	Data_t* temp = (Data_t*)&data;
	memcpy(temp->FrameHeader.SrcMAC, temp->FrameHeader.DesMAC, 6);//源MAC为 本机MAC
	memcpy(temp->FrameHeader.DesMAC, dmac, 6);//目的MAC为下一跳MAC
	temp->IPHeader.TTL -= 1;//TTL-1
	if (temp->IPHeader.TTL < 0)
		return;//丢弃
	setchecksum(temp);//重新设置校验和
	int rtn = pcap_sendpacket(ahandle, (const u_char*)temp, 74);//发送数据报
	if (rtn == 0)
		ltable.write2log_ip("转发", temp);//写入日志
}


//查找路由表对应表项,并给出下一跳的ip地址
DWORD routetable::lookup(DWORD ip)
{
	routeitem* t = head->nextitem;
	for (; t != tail; t = t->nextitem)
	{
		if ((t->mask & ip) == t->net)
			return t->nextip;
	}
	//printf("未找到对应跳转地址");
	return -1;
}






int log::num = 0;
log log::diary[50] = {};
FILE* log::fp = nullptr;
log::log()
{
	fp = fopen("log.txt", "a+"); //第一个逗号前是文件位置。逗号之后是打开文件方式
//fprintf(fp, "This is testing for fprintf...\n");
}

log::~log()
{
	fclose(fp);
}


void log::print()//打印日志
{
	int i;
	if (num > 50)
		i = (num + 1) % 50;
	else i = 0;
	for (; i < num % 50; i++)
	{
		printf("%d ", diary[i].index);
		printf("%s\t ", diary[i].type);
		//printf("%s\n",diary[i].detail);
		if (!strcmp(diary[i].type, "ARP"))
		{
			in_addr addr;
			addr.s_addr = diary[i].arp.ip;
			char* pchar = inet_ntoa(addr);
			printf("%s\t", pchar);
			for (int i = 0; i < 5; i++)
			{
				printf("%02X.", diary[i].arp.mac[i]);
			}
			printf("%02X\n", diary[i].arp.mac[5]);
		}
		else if (!strcmp(diary[i].type, "IP"))
		{
			in_addr addr;
			addr.s_addr = diary[i].ip.sip;
			char* pchar = inet_ntoa(addr);
			printf("源IP：%s\t", pchar);
			addr.s_addr = diary[i].ip.dip;
			pchar = inet_ntoa(addr);
			printf("目的IP：%s\t", pchar);
			printf("源MAC: ");
			for (int i = 0; i < 5; i++)
			{
				printf("%02X.", diary[i].ip.smac[i]);
			}
			printf("%02X\t", diary[i].ip.smac[5]);
			printf("目的MAC: ");
			for (int i = 0; i < 5; i++)
			{
				printf("%02X.", diary[i].ip.dmac[i]);
			}
			printf("%02X\n", diary[i].ip.dmac[5]);
		}
	}
}

void log::write2log_ip(Data_t* pkt)//ip类型
{
	diary[num % 100].index = num++;
	strcpy(diary[num % 100].type, "IP");
	diary[num % 100].ip.sip = pkt->IPHeader.SrcIP;
	diary[num % 100].ip.dip = pkt->IPHeader.DstIP;

	//memcpy(copy,arr,len*sizeof(int)); 
	memcpy(diary[num % 100].ip.smac, pkt->FrameHeader.SrcMAC, 6);
	memcpy(diary[num % 100].ip.dmac, pkt->FrameHeader.DesMAC, 6);
}

void log::write2log_ip(const char* a, Data_t* pkt)//ip类型
{
	fprintf(fp, "IP  ");
	fprintf(fp, a);
	fprintf(fp, "  ");


	in_addr addr;
	addr.s_addr = pkt->IPHeader.SrcIP;
	char* pchar = inet_ntoa(addr);

	fprintf(fp, "源IP： ");
	fprintf(fp, "%s  ", pchar);
	fprintf(fp, "目的IP： ");
	addr.s_addr = pkt->IPHeader.DstIP;
	fprintf(fp, "%s  ", pchar);
	fprintf(fp, "源MAC： ");
	for (int i = 0; i < 5; i++)
		fprintf(fp, "%02X-", pkt->FrameHeader.SrcMAC[i]);
	fprintf(fp, "%02X  ", pkt->FrameHeader.SrcMAC[5]);
	fprintf(fp, "目的MAC： ");
	for (int i = 0; i < 5; i++)
		fprintf(fp, "%02X-", pkt->FrameHeader.DesMAC[i]);
	fprintf(fp, "%02X\n", pkt->FrameHeader.DesMAC[5]);

}


void log::write2log_arp(ARPFrame_t* pkt)//arp类型
{
	fprintf(fp, "ARP  ");

	in_addr addr;
	addr.s_addr = pkt->SendIP;
	char* pchar = inet_ntoa(addr);
	fprintf(fp, "IP： ");
	fprintf(fp, "%s  ", pchar);

	fprintf(fp, "MAC： ");
	for (int i = 0; i < 5; i++)
		fprintf(fp, "%02X-", pkt->SendHa[i]);
	fprintf(fp, "%02X\n", pkt->SendHa[5]);

}

DWORD WINAPI handlerRequest(LPVOID lparam)//接收和处理线程函数
{
	routetable rtable = *(routetable*)(LPVOID)lparam;
	while (1)
	{
		pcap_pkthdr* pkt_header; const u_char* pkt_data;
		while (1)
		{
			int rtn = pcap_next_ex(ahandle, &pkt_header, &pkt_data);
			if (rtn)//接收到消息
				break;
		}
		FrameHeader_t* header = (FrameHeader_t*)pkt_data;
		if (compare(header->DesMAC, selfmac))//目的mac是自己的mac
		{
			if (ntohs(header->FrameType) == 0x806)//收到arp内容
			{

			}
			else if (ntohs(header->FrameType) == 0x800)//IP格式数据报
			{
				Data_t* data = (Data_t*)pkt_data;
				ltable.write2log_ip("接收", data);//写入日志

				DWORD ip1_ = data->IPHeader.DstIP;
				DWORD ip_ = rtable.lookup(ip1_);//查找是否有对应表项
				if (ip_ == -1)//如果没有则直接丢弃或直接递交至上层
					continue;

				if (checkchecksum(data))//如果校验和不正确，则直接丢弃不进行处理
				{
					if (data->IPHeader.DstIP != inet_addr(ip[0]) && data->IPHeader.DstIP != inet_addr(ip[1]))
					{
						int t1 = compare(data->FrameHeader.DesMAC, broadcast);
						int t2 = compare(data->FrameHeader.SrcMAC, broadcast);
						if (!t1 && !t2)
						{
							//ICMP报文包含IP数据包报头和其它内容
							ICMP_t* temp_ = (ICMP_t*)pkt_data;
							ICMP_t temp = *temp_;
							//printf("%d",sizeof(temp));
							BYTE mac[6];

							if (ip_ == 0)
							{
								//如果ARP表中没有所需内容，则需要获取ARP
								if (!arptable::lookup(ip1_, mac))
									arptable::insert(ip1_, mac);
								//getmac(mac);
								resend(temp, mac);
							}

							else if (ip_ != -1)//非直接投递，查找下一条IP的MAC
							{
								if (!arptable::lookup(ip_, mac))
									arptable::insert(ip_, mac);
								//getmac(mac);
								resend(temp, mac);
							}
						}
					}
					else
					{
					}

				}
			}
		}
	}
}
void ipprint(DWORD ip)//打印IP
{
	in_addr addr;
	addr.s_addr = ip;
	char* pchar = inet_ntoa(addr);
	printf("%s\t", pchar);
	printf("\n");
}


void setchecksum(Data_t* temp)//设置校验和
{
	temp->IPHeader.Checksum = 0;
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
	{
		sum += t[i];
		while (sum >= 0x10000)
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	temp->IPHeader.Checksum = ~sum;//取反
}
bool checkchecksum(Data_t* temp)//校验
{
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
	{
		sum += t[i];
		while (sum >= 0x10000)//包含原有校验和相加
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	//printf("%d", (WORD)~temp->IPHeader.Checksum);
	if (sum == 65535)
		return 1;
	return 0;
}




int arptable::num = 0;
void arptable::insert(DWORD ip, BYTE mac[6])
{
	atable[num].ip = ip;
	getothermac(ip, atable[num].mac);
	memcpy(mac, atable[num].mac, 6);
	num++;
}
int arptable::lookup(DWORD ip, BYTE mac[6])
{
	memset(mac, 0, 6);
	for (int i = 0; i < num; i++)
	{
		if (ip == atable[i].ip)
		{
			memcpy(mac, atable[i].mac, 6);
			return 1;
		}
	}
	//未知返回00
	return 0;
}