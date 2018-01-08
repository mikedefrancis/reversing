/* callback.c -- program implements callback technique to search a linked
 * list for a given value
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sll_header.h"
 
int compare_ints(void const *, void const *);   /* function prototype */
Node *search_list(Node *, void const *, int (void const *, void const *));
      /* prototype */
 
int main(void)
{
    int (*compare)(void const *, void const *) = compare_ints;
 
    int value, val2find;
    int nodes;      /* nodes count*/
    Node **rootp;   /* pointer-to-root */
    Node *desired_node;
 
    puts("\n**Program creates Singly Linked List**");
    puts("**And allows users to perform various operations on the"
           " list**\n");
    puts("User, specify number of nodes in the list, in range 1"
         " through some positive no.");
    scanf("%d", &nodes);
 
    /* let's create list with specified nodes */
    rootp = create_sll(nodes);
 
    printf("Let's insert %d integers in the list...\n", nodes);
    insert_data(rootp);
 
    puts("**Let's show up the list**");
    show_list(rootp);
 
    puts("Let's sort the list, in ascending order...");
    sort_list(rootp);
    puts("**Let's show up the list**");
    show_list(rootp);
 
    puts("**Let's use Callback() function**");
    printf("User, enter an integer you want to see into the "
            "Singly Linked List...\n");
    scanf("%d", &val2find);
 
    /* call to callback function */
    desired_node = search_list(*rootp, &val2find, compare);
 
    /* Let's confirm whether desired value is found or not */
    if (desired_node != NULL)
            puts("Desired value is found.");
    else
            puts("Desired value NOT found.");
 
    return 0;
}
 
/* search_list() is a typeless callback function */
/*
 * 3rd argument to search_list() is pointer-to-function, search_list()
 * calls back this function to compare values
 */
 
Node *search_list(Node *node, void const *value, int compare(void const *,
        void const *))
{
    while (node != NULL) {
            if (compare(&node->data, value) == 0)
                    break;
            node = node->link;
    }
 
    return node;
}
 
/* compare_ints() compares the integers */
int compare_ints(void const *p2nv, void const *p2v)
{
    if (*(int *)p2nv == *(int *)p2v)
            return 0;
    else
            return 1;
}
