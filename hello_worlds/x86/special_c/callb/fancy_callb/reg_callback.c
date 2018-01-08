#include<stdio.h>
#include"reg_callback.h"
 
/* registration goes here */
void register_callback(callback ptr_reg_callback)
{
    printf("inside register_callback\n");
    /* calling our callback function my_callback */
    (*ptr_reg_callback)();                                  
}
