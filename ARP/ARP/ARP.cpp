#include <pcap.h>
#include "misc.h" /* LoadNpcapDlls */
#include <stdio.h>
#include <time.h>
#include <iostream>
#include <iphlpapi.h>
#include <ws2tcpip.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Packet.lib")

/* ugly shortcut -- Ethernet packet headers are 14 bytes */
#define ETH_HEADER_SIZE 14
#define ETHERTYPE_ARP 0x0806

typedef struct ether_header {
	u_char  ether_dhost[6];
	u_char  ether_shost[6];
	u_short ether_type;
} ETHERHDR;

typedef struct arphdr {
	uint16_t ar_hrd;
	uint16_t ar_pro;
	uint8_t  ar_hln;
	uint8_t  ar_pln;
	uint16_t ar_op;
} ARPHDR;

typedef struct ether_arp {
	ARPHDR   ea_hdr;
	uint8_t  arp_sha[6];
	uint8_t  arp_spa[4];
	uint8_t  arp_tha[6];
	uint8_t  arp_tpa[4];
} ETHERARP;

double PCFreq = 0.0;
__int64 CounterStart = 0;

/* prototype of the packet handler */
void packet_handler(
	u_char* param,
	const struct pcap_pkthdr* header,
	const u_char* pkt_data);

void StartCounter()
{
	LARGE_INTEGER li;
	if (!QueryPerformanceFrequency(&li))
		std::cout << "QueryPerformanceFrequency failed!\n";

	PCFreq = double(li.QuadPart) / 1000000.0;

	QueryPerformanceCounter(&li);
	CounterStart = li.QuadPart;
}

double GetCounter()
{
	LARGE_INTEGER li;
	QueryPerformanceCounter(&li);
	return double(li.QuadPart - CounterStart) / PCFreq;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char* user,
	const struct pcap_pkthdr* header,
	const u_char* packet)
{

	struct ether_header* eth_header = (struct ether_header*)packet;
	struct ether_arp* arp_packet = (struct ether_arp*)(packet + ETH_HEADER_SIZE);

	struct tm ltime;
	char timestr[16];
	time_t local_tv_sec;

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

	printf("IP: Source: %d.%d.%d.%-13d Destination: %d.%d.%d.%d\nMAC: Source: %x.%x.%x.%x.%x.%-7x Destination: %x.%x.%x.%x.%x.%x\n",
		arp_packet->arp_spa[0],
		arp_packet->arp_spa[1],
		arp_packet->arp_spa[2],
		arp_packet->arp_spa[3],
		arp_packet->arp_tpa[0],
		arp_packet->arp_tpa[1],
		arp_packet->arp_tpa[2],
		arp_packet->arp_tpa[3],
		arp_packet->arp_sha[0],
		arp_packet->arp_sha[1],
		arp_packet->arp_sha[2],
		arp_packet->arp_sha[3],
		arp_packet->arp_sha[4],
		arp_packet->arp_sha[5],
		arp_packet->arp_tha[0],
		arp_packet->arp_tha[1],
		arp_packet->arp_tha[2],
		arp_packet->arp_tha[3],
		arp_packet->arp_tha[4],
		arp_packet->arp_tha[5]
	);
}

void SendRequest(char* argv[]) {
	StartCounter();
	ULONG arpRes[2];
	ULONG macAddrLen = 6;
	unsigned int buf[4] = { 0,0,0,0 };
	char* token = NULL;
	char* nextToken = NULL;
	IPAddr destIP = 0;
	int i = 0;

	memset(&arpRes, 0xff, sizeof(arpRes));

	token = strtok_s(argv[2], ".", &nextToken);
	while (token != NULL)
	{
		buf[i] = atoi(token);
		token = strtok_s(NULL, ".", &nextToken);
		i++;
	}
	destIP = buf[0] * pow(2, 24) + buf[1] * pow(2, 16) + buf[2] * pow(2, 8) + buf[3];

	if (SendARP(ntohl(destIP), 0, &arpRes, &macAddrLen) == 0)
		std::cout << GetCounter() << "\n";
	else
		std::cout << "Couldn't find IP address";
}

void CapturePacket() {
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "arp";
	struct bpf_program fcode;

	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}

	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING,
		NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
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
		printf("\nNo interfaces found! Make sure Npcap is installed.\n");
		exit(-1);
	}

	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		exit(-1);
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* Open the device */
	if ((adhandle = pcap_open(d->name, // name of the device
		65536, // portion of the packet to capture
			   // 65536 guarantees that the whole packet will
			   // be captured on all the link layers
		PCAP_OPENFLAG_PROMISCUOUS, // promiscuous mode
		1000, // read timeout
		NULL, // authentication on the remote machine
		errbuf // error buffer
	)) == NULL)
	{
		fprintf(stderr,
			"\nUnable to open the adapter. %s is not supported by Npcap\n",
			d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		exit(-1);
	}

	printf("\nlistening on %s...\n", d->description);


	if (d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses
		 * we suppose to be in a C class network */
		netmask = 0xffffff;


	//compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		exit(-1);
	}

	//set the filter
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		exit(-1);
	}

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);


	std::cout << GetCounter() << "\n";

	return;
}


int main(int argc, char* argv[])
{
	if (strcmp(argv[1], "req") == 0)
	{
		std::cout << "req\n";
		if (argc < 2)
		{
			std::cout << "req IP-Address - for request\n res - for response\n";
			exit(1);
		}
		SendRequest(argv);
	}
	else if (strcmp(argv[1], "res") == 0)
	{
		std::cout << "res";
		CapturePacket();
	}
	else
	{
		std::cout << "req IP-Address - for request\n res - for response\n";
		exit(1);
	}
	return 0;
}