/*
 * sll_operations.c -- here's contained all the definitions of
 * different operations performed on a singly linked list
 */
 
Node **create_sll(const int nodes)
{
    int i;
    Node *current;
    static Node *root;
    Node **rootp = &root;   /* ptr-to-root */
 
    /* Let's allocate memory dynamically */
    root = (Node *)malloc(nodes * sizeof(Node));
 
    /* verify if dynamic allocation successful */
    if (root == NULL) {
            puts("Error: Not Enough Memory!");
            exit(1);
 }
    else {
            /* Create the list */
            current = root; 
            /* current set to the start of dynamic allocation */
 
            for (i = 1; i <= nodes; i++) {
                   if (i == nodes) {
                           current->link = NULL;
                    }
                    else {
                            current->link = current + 1;
                            current++;
                    }
            }
            printf("List with %d nodes created successfully!\n", nodes);
            puts("");
    }
 
    return rootp;
}
 
/* insert_data() inserts data into successive nodes in the list */
void insert_data(Node **linkp)
{
    Node *next = *linkp;
    Node *current;
 
    /* Write integers into the list */
    do {
            current = next;
            scanf("%d", &(current->data));
            next = current->link;
    } while (current->link != NULL);
    puts("");
}
 
/* show up data in the list */
void show_list(Node **linkp)
{
    Node *next = *linkp;
    Node *current;
 
    /* Let's read data from the list */
    do {
            current = next;
            printf("%d ", current->data);
            next = current->link;
    } while (current->link != NULL);
    puts("\n");
}
 
/* sorting list using Selection Sort */
void sort_list(Node **linkp)
{
    int temp;
    Node *current = *linkp;
    Node *next = current->link;
 
    /* Let's sort the list by sorting values  */
    while (current->link != NULL) { /* Outer while loop terminates when */
            /* there's no next node to current node in the list */
            while (next != NULL) {  /* Inner while loop */
                    /* sorts the current value */
                    if (current->data > next->data) {
                            /* swap the values */
                            temp = next->data;
                            next->data = current->data;
                            current->data = temp;
                    }
                    /* update the next value */
                    next = next->link;
            }
            /* current value is sorted */
            /* update the current and next values */
            current = current->link;
            next = current->link;
    }
}
