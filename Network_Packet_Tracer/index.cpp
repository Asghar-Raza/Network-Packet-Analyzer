#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <iomanip>

using namespace std;

void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct ip* ipHeader = (struct ip*)(packet + 14);
    if (ipHeader->ip_v == 4) {
        cout << "Source IP: " << inet_ntoa(ipHeader->ip_src) << endl;
        cout << "Dest IP: " << inet_ntoa(ipHeader->ip_dst) << endl;
        if (ipHeader->ip_p == IPPROTO_TCP) {
            struct tcphdr* tcpHeader = (struct tcphdr*)((u_char*)ipHeader + ipHeader->ip_hl * 4);
            cout << "TCP Source Port: " << ntohs(tcpHeader->source) << endl;
            cout << "TCP Dest Port: " << ntohs(tcpHeader->dest) << endl;
        } else if (ipHeader->ip_p == IPPROTO_UDP) {
            struct udphdr* udpHeader = (struct udphdr*)((u_char*)ipHeader + ipHeader->ip_hl * 4);
            cout << "UDP Source Port: " << ntohs(udpHeader->source) << endl;
            cout << "UDP Dest Port: " << ntohs(udpHeader->dest) << endl;
        }
    }
    cout << "------------------------------------" << endl;
}

int main() {
    char errorBuffer[PCAP_ERRBUF_SIZE];
    pcap_if_t* devices;
    pcap_if_t* device;

    if (pcap_findalldevs(&devices, errorBuffer) == -1) {
        cerr << "Error finding devices: " << errorBuffer << endl;
        return 1;
    }

    device = devices; // Use the first available device

    if (device == nullptr) {
        cerr << "No devices found." << endl;
        pcap_freealldevs(devices);
        return 1;
    }

    cout << "Device: " << device->name << endl;

    pcap_t* handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errorBuffer);
    if (handle == nullptr) {
        cerr << "Error opening device: " << errorBuffer << endl;
        pcap_freealldevs(devices);
        return 1;
    }

    if (pcap_loop(handle, 0, packetHandler, nullptr) < 0) {
        cerr << "Error capturing packets: " << pcap_geterr(handle) << endl;
        pcap_close(handle);
        pcap_freealldevs(devices);
        return 1;
    }

    pcap_close(handle);
    pcap_freealldevs(devices); // Free the device list
    return 0;
}