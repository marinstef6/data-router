#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "lib.h"

/* trie node structure, containing a pointer to the entry, 2 children (0 - left, 1 - right), and a boolean value is_leaf
 * is_leaf is 0 by default and 1 when it reached the end of the mask length (the afferent level)
 * Basically we put the route_table_entry when the sub-net prefix ended
 */
struct trie_node {
    struct route_table_entry *route_entry;
    struct trie_node *left;
    struct trie_node *right;
    int is_leaf;
};

struct trie_node *create(struct route_table_entry *entry);
struct trie_node *insert_node_trie(struct route_table_entry *entry, struct trie_node *root,  int mask_length, uint32_t ip_address);
