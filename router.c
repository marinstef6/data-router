#include "include/queue.h"
#include "include/lib.h"
#include "include/protocols.h"
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "include/list.h"
#include "include/trie.h"

#define ARP_TYPE htons(0x0806)
#define IP_TYPE htons(0x0800)
#define DESTINATION_UNREACHABLE 0
#define TIME_EXCEEDED 1
#define ARP_REPLY 2
// Lungimea adresei MAC în octeți
#define ETHER_ADDR_LEN 6 
// Tipul de protocol pentru ARP în Ethernet frame
#define ETHERTYPE_ARP 0x0806 
// Tipul de protocol pentru IP în Ethernet frame
#define ETHERTYPE_IP 0x0800 
#define ARP_REQUEST 1
#define BROADCAST_MAC "FF:FF:FF:FF:FF:FF"

// Route table
struct route_table_entry *rtable;
int rtable_len;

// MAC table
struct arp_table_entry *mac_table;
int mac_table_len;

// Queue structure
struct que_elem {
	int cur_len;
	char packk[MAX_PACKET_LEN];
};

queue Q;
int q_len = 0;

struct trie_node *root;

// functia de longest prefix match care intoarce o intrare din tabela de rutare
struct route_table_entry *LPM(uint32_t ip_address) {
    struct route_table_entry *longest_match = NULL;
    struct trie_node *current_node;
    for (current_node = root; current_node != NULL; ip_address >>= 1) { 
       
        if (current_node->is_leaf) {
			
            longest_match = current_node->route_entry;
        }

	if (ip_address & 1) {
		current_node = current_node->right;
	} else 
		current_node = current_node->left;  
    }
    return longest_match;   
}

// functia de calculare a lungimii mascei
int get_mask_length(uint32_t mask) {
    int length = 0;
// car timp mask si 1 este diferit de 0, incrementam lungimea si shiftam mask-ul la dreapta
    while (mask & 1) {
        length++;
        mask = mask >> 1;
    }

    return length;
}
// functia de citire a tabelei de rutare
struct arp_table_entry *entry_mac (uint32_t ip_dest)
{
	int i = 0; 
	// cautam in tabela de mac adresa corespunzatoare ip-ului destinatie
	while (i < mac_table_len) { 
		if (mac_table[i].ip == ip_dest) {
			return &(mac_table[i]); 
		}
		i++;
	}
	return NULL;
}
// functia care construieste si trimite un pachet
void build_send(struct ether_header *eth_hdr, struct iphdr *ip_hdr, char *buf, int len, int interface)
{
	char packet[MAX_PACKET_LEN];
	memcpy(packet, eth_hdr, sizeof(struct ether_header));
	memcpy(packet + sizeof(struct ether_header), ip_hdr, sizeof(struct iphdr));
	int len_ip_hdr = len - (sizeof(struct ether_header) + sizeof(struct iphdr));
	memcpy(packet + sizeof(struct ether_header) + sizeof(struct iphdr), buf + sizeof(struct ether_header) + sizeof(struct iphdr),
			len_ip_hdr);
	send_to_link(interface, packet, len);
}
// functia care construieste un pachet ip
void build_ip(struct iphdr *ip_hdr)
{
	uint32_t save_addr = ip_hdr->daddr;
	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = save_addr;
	ip_hdr->ttl = 100;
	ip_hdr->protocol = 1;
	ip_hdr->tot_len = htons(sizeof(struct icmphdr) + 2 * sizeof(struct iphdr) + 8);
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
}
// functia care construieste un pachet icmp
void build_icmp_packet(struct route_table_entry *rt, struct icmphdr *icm, int interface, size_t len, struct ether_header *eth_hdr, struct iphdr *ip_hdr, char *buf)
{
	char packet[MAX_PACKET_LEN];
	char icmp[MAX_PACKET_LEN];
	memcpy(icmp, icm, sizeof(struct icmphdr));
	memcpy(icmp + sizeof(struct icmphdr), buf + sizeof(struct ether_header), sizeof(struct iphdr) + 8);
	icm->checksum = 0;
	icm->checksum = htons(checksum((uint16_t *) icmp, sizeof(struct icmphdr) + sizeof(struct iphdr) + 8));

	memcpy(packet, eth_hdr, sizeof(struct ether_header));
	memcpy(packet + sizeof(struct ether_header), ip_hdr, sizeof(struct iphdr));
	memcpy(packet + sizeof(struct ether_header) + sizeof(struct iphdr), icm, sizeof(struct icmphdr));
	int len_icmp_struct =  sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
	memcpy(packet + len_icmp_struct, icmp + sizeof(struct icmphdr), sizeof(struct iphdr) + 8);

	send_to_link(rt->interface, packet, sizeof(struct ether_header) + 2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 8);

}
// functia care trimite un pachet icmp
void send_icmp(int interface, size_t len, struct ether_header *eth_hdr, struct iphdr *ip_hdr, char *buf, short err) {

// apelam functia penru a construi un pachet ip
	build_ip(ip_hdr);
	struct route_table_entry *rt = LPM(ip_hdr->daddr);
	
	struct icmphdr *icm = malloc(sizeof(struct icmphdr));
	icm->code = 0;
// in functie de tipul de eroare setam tipul pachetului icmp
	if (err == TIME_EXCEEDED) {
		icm->type = 11;
	} else if (err == DESTINATION_UNREACHABLE) {
		icm->type = 3;
	} else {
		icm->type = 0;
	}
// construim pachetul icmp
	build_icmp_packet(rt, icm, rt->interface, len, eth_hdr, ip_hdr, buf);
}
// functia care trimite un pachet icmp de tip reply
void icmp_reply(int interface, size_t len, char *buf) {
 
 	struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
    struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
	
    struct route_table_entry *route_entry = LPM(ip_hdr->daddr); 
    uint8_t local_mac[6];
	struct arp_table_entry *arp_entry = entry_mac (route_entry->next_hop);
    get_interface_mac(route_entry->interface, local_mac);

	struct ether_header *eth_hdr = (struct ether_header *)buf;
    memcpy(eth_hdr->ether_dhost, arp_entry->mac, 6 * sizeof(uint8_t));

	icmp_hdr->type = 0;
    icmp_hdr->code = 0; 
     
    send_to_link(route_entry->interface, buf, len);
}

// functia care genereaza un pachet arp reply
void generate_arp_reply(struct arp_header *arp_received, struct sockaddr_in sa, struct ether_header *eth_hdr) {
    
	struct route_table_entry *rt = LPM(arp_received->spa);
	char arp_reply_packet[MAX_PACKET_LEN];

	struct ether_header *eth_reply = (struct ether_header *) arp_reply_packet;
    struct arp_header *arp_reply = (struct arp_header *) (arp_reply_packet + sizeof(struct ether_header));

    get_interface_mac(rt->interface, eth_reply->ether_shost);
    memcpy(eth_reply->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
    eth_reply->ether_type = htons(ETHERTYPE_ARP);
// construim pachetul arp reply
    arp_reply->htype = htons(1);
    arp_reply->ptype = htons(ETHERTYPE_IP);
    arp_reply->hlen = ETHER_ADDR_LEN;
    arp_reply->plen = 4;
    arp_reply->op = htons(2); 
    memcpy(arp_reply->sha, eth_reply->ether_shost, ETHER_ADDR_LEN);
    arp_reply->spa = sa.sin_addr.s_addr; 
    memcpy(arp_reply->tha, eth_hdr->ether_shost, ETHER_ADDR_LEN);
    arp_reply->tpa = arp_received->spa;

    size_t packet_length = sizeof(struct ether_header) + sizeof(struct arp_header);
    send_to_link(rt->interface, arp_reply_packet, packet_length);
}
// functia care trimite un pachet pe interfata
void resend_packet(struct que_elem* element, struct ether_header *eth_hdr, struct iphdr *ip_hdr, struct route_table_entry *rt) {
    uint8_t *mac_src = calloc(6, sizeof(uint8_t));
    get_interface_mac(rt->interface, mac_src);
    memcpy(eth_hdr->ether_shost, mac_src, 6 * sizeof(uint8_t));
    free(mac_src);
    struct arp_table_entry *arp_entry = entry_mac (rt->next_hop);
    if (arp_entry != NULL) {
        memcpy(eth_hdr->ether_dhost, arp_entry->mac, 6 * sizeof(uint8_t));
    }

    send_to_link(rt->interface, element->packk, element->cur_len);
}
// functia care itereaza prin coada
void iterate_through_queue() {
    int unsent_packets_count = 0;
    int i = 0;
// cat timp coada nu este goala extragem un element din coada si trimitem pachetul
	while (i < q_len) {
		struct que_elem* queue = queue_deq(Q);
		struct iphdr *ip_hdr = (struct iphdr *)(queue->packk + sizeof(struct ether_header));
		
		struct route_table_entry *rt = LPM(ip_hdr->daddr);
		struct ether_header *eth_hdr = (struct ether_header *)queue->packk;
		
		struct arp_table_entry *arp_entry = entry_mac (rt->next_hop);
// daca nu gasim adresa mac in tabela de mac, adaugam pachetul in coada
		if (arp_entry == NULL) {
			queue_enq(Q, queue);
			unsent_packets_count++;
		} else 
			resend_packet(queue, eth_hdr, ip_hdr, rt);
		i++;
	}
// actualizam lungimea cozii
    q_len = unsent_packets_count;
}
// functia care genereaza un pachet arp request
void generate_arp_request(struct route_table_entry *rt) {
    if (rt == NULL) {
        return;
	}
// construim pachetul arp request
    struct ether_header eth_hdr;
    memset(&eth_hdr, 0, sizeof(struct ether_header));
// setam adresele mac
    hwaddr_aton(BROADCAST_MAC, eth_hdr.ether_dhost);
    get_interface_mac(rt->interface, eth_hdr.ether_shost); 
    eth_hdr.ether_type = htons(ETHERTYPE_ARP);

    struct arp_header arp_hdr;
    memset(&arp_hdr, 0, sizeof(struct arp_header));
// setam campurile pachetului arp
    arp_hdr.htype = htons(1);
    arp_hdr.ptype = htons(ETHERTYPE_IP);
    arp_hdr.hlen = 6;
    arp_hdr.plen = 4; 
    arp_hdr.op = htons(ARP_REQUEST); 
    memcpy(arp_hdr.sha, eth_hdr.ether_shost, sizeof(arp_hdr.sha)); 

    struct in_addr ip_addr;
// setam adresa ip a interfetei
    inet_aton(get_interface_ip(rt->interface), &ip_addr);
    arp_hdr.spa = ip_addr.s_addr;

    memset(arp_hdr.tha, 0, sizeof(arp_hdr.tha)); 
    arp_hdr.tpa = rt->next_hop; 

    uint8_t arp_req_packet[MAX_PACKET_LEN];
    memcpy(arp_req_packet, &eth_hdr, sizeof(struct ether_header));
    memcpy(arp_req_packet + sizeof(struct ether_header), &arp_hdr, sizeof(struct arp_header));

    send_to_link(rt->interface, (char *)arp_req_packet, sizeof(struct ether_header) + sizeof(struct arp_header));
}
// functia care adauga un pachet in coada
void queue_func(char* buf, int len) 
{
    struct que_elem* el = (struct que_elem*) malloc(sizeof(struct que_elem));
   	el->cur_len =  len; 
    if (el == NULL) {
        free(el);
        return;
    }
    memcpy(el->packk, buf, len); 
    queue_enq(Q, el); 
	q_len++;
}

int main(int argc, char *argv[])
{
	
	// Do not modify this line
	init(argc - 2, argv + 2);
	
	Q = queue_create();
// aloca memorie pentru tabela de rutare si tabela de mac
	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	rtable_len = read_rtable(argv[1], rtable);
	root = create(NULL);
	
	int i = 0;
	
	mac_table = malloc(sizeof(struct arp_table_entry) * 100);
	mac_table_len = 0;
	if (mac_table == NULL) {
		free(mac_table);
		return -1;
	}
// cat timp exista intrari in tabela de rutare, le adaugam in trie
	while(i < rtable_len)
	{
		root = insert_node_trie(&(rtable[i]), root, get_mask_length(rtable[i].mask), rtable[i].prefix);
		i++;
	}
	char buf[MAX_PACKET_LEN];
	
	while (1) {
		struct sockaddr_in sa;
		struct ether_header *eth_hdr = (struct ether_header *) buf;
		int interface;
		size_t len;
		
// primim un pachet de pe orice interfata
		interface = recv_from_any_link(buf, &len);		
		inet_pton(AF_INET, get_interface_ip(interface), &(sa.sin_addr));
// verificam daca pachetul este de tip arp
		if (eth_hdr->ether_type == ARP_TYPE) {
			struct arp_header *arp_received = (struct arp_header *) (buf + sizeof(struct ether_header));
// verificam daca pachetul este destinat interfetei noastre
			if(arp_received->tpa == sa.sin_addr.s_addr){
// daca pachetul este de tip reply, adaugam adresa mac in tabela de mac
				if (ntohs(arp_received->op) == ARP_REPLY) {
					memcpy(mac_table[mac_table_len].mac, arp_received->sha, 6 * sizeof(uint8_t));
					mac_table[mac_table_len].ip = arp_received->spa;
					mac_table_len++;
					iterate_through_queue();
					continue;
// daca pachetul este de tip request, trimitem un pachet de tip reply
				} else if (ntohs(arp_received->op) == ARP_REQUEST) {
					memcpy(mac_table[mac_table_len].mac, arp_received->sha, 6 * sizeof(uint8_t));
					mac_table[mac_table_len].ip = arp_received->spa;
					mac_table_len++;
					generate_arp_reply(arp_received, sa, eth_hdr);
					continue;
				}
			}
		}
		
		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
// verificam checksum-ul pachetului ip
		uint16_t save_check = ip_hdr->check;
		ip_hdr->check = 0;
// daca checksum-ul nu este corect, continuam
		if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr))!= ntohs(save_check)) {
			continue;
		}
// daca ttl-ul este mai mic sau egal cu 1, trimitem un pachet de tip time exceeded
		if (ip_hdr->ttl <= 1) {
			ip_hdr->check = save_check;
			send_icmp(interface, len, eth_hdr, ip_hdr, buf, TIME_EXCEEDED);
			continue;
		}
// decrementam ttl-ul si recalculam checksum-ul
		ip_hdr->ttl--;
		ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
// daca pachetul este destinat interfetei noastre, trimitem un pachet icmp de tip reply	
		if (sa.sin_addr.s_addr == ip_hdr->daddr) {
			icmp_reply(interface, len, buf);
			continue;
		}

		struct route_table_entry *rt = LPM(ip_hdr->daddr);
// daca nu gasim o intrare in tabela de rutare, trimitem un pachet de tip destination unreachable
		if (!rt) {
			send_icmp(interface, len, eth_hdr, ip_hdr, buf, DESTINATION_UNREACHABLE);
			continue;
		}

		struct arp_table_entry *m;
		m = entry_mac (rt->next_hop);
// daca nu gasim adresa mac in tabela de mac, adaugam pachetul in coada
		if (!m) {
			queue_func(buf, len);
			generate_arp_request(rt);
			continue;
		} else {
// daca gasim adresa mac in tabela de mac, trimitem pachetul
			uint8_t *macc = calloc(6, sizeof(uint8_t));
			get_interface_mac(rt->interface, macc);
			memcpy((char *)eth_hdr->ether_dhost, (char *) (m->mac), 6 * sizeof(uint8_t));
			build_send(eth_hdr, ip_hdr, buf, len, rt->interface);
		}
	}
}