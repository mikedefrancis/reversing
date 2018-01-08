
#include <stdio.h>

void cbfunc()
{
    printf("Hello World (from callback function) MPD @ IAI\n");
}
 
int main ()
{
     /* function pointer */
    void (*callback)(void);
 
    /* point to your callback function */
    callback=(void *)cbfunc;
     
   /* perform callback */
   callback();
 
   return 0;
}
