#include "trie.h"
// creez un nod nou
struct trie_node *create(struct route_table_entry *entry) {
    struct trie_node *node = malloc(sizeof(struct trie_node));
    if (node == NULL) 
        return NULL;
// initializez nodul
    node->left = NULL;
    node->right = NULL;
    node->route_entry = entry; 
    node->is_leaf = 0; 
    return node;
}
// inserez un nod in trie
struct trie_node *insert_node_trie(struct route_table_entry *entry, struct trie_node *root,  int mask_length, uint32_t ip_address) {
    int i = 0;
// daca arborele este gol, creez un nod nou
    struct trie_node *save_node = root;
// parcurg arborele pana la penultimul nod
    while (i < mask_length - 1) {
    struct trie_node **nextNode;
// daca bitul curent este 1, merg la dreapta, altfel la stanga
    if (ip_address & 1) {
        nextNode = &save_node->right;
    } else {
        nextNode = &save_node->left;
    }
    if (*nextNode == NULL) {
        *nextNode = create(NULL);
    }
// trec la urmatorul nod
    save_node = *nextNode;
    ip_address >>= 1;
    i++;
}

    struct trie_node **nextNode;

    if (ip_address & 1) 
        nextNode = &save_node->right;
    else 
        nextNode = &save_node->left;
// daca nodul este gol, creez un nod nou
    if (*nextNode == NULL) 
        *nextNode = create(entry);
    else 
        (*nextNode)->route_entry = entry;
// marchez nodul ca fiind frunza
    (*nextNode)->is_leaf = 1;
// returnez radacina arborelui
    return root;
}
