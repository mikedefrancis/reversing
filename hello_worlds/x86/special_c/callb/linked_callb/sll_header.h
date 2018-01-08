/* sll_header.h -- here's contained all header declarations for a 
 * singly linked list
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
 
typedef struct NODE     {
                struct NODE *link;      /* ptr-to-self_ref_struct */
                int data;
        } Node;
Node **create_sll(const int);           /* fun. returns ptr-to-root */
void insert_data(Node **);
void show_list(Node **);        /* fun. shows up data in the list */
void sort_list(Node **);        /* sorting list using selection sort */
 
#include "sll_operations.c"
