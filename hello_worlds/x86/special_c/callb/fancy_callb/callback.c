#include<stdio.h>
#include"reg_callback.h"
 
/* callback function definition goes here */
void my_callback(void)
{
    printf("inside my_callback\n");
}
 
int main(void)
{
    /* initialize function pointer to
    my_callback */
    callback ptr_my_callback=my_callback;                           
    printf("This is a program demonstrating function callback\n");
    /* register our callback function */
    register_callback(ptr_my_callback);                             
    printf("back inside main program\n");
    return 0;
}
