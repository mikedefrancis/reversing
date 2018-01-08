
#include <stdio.h>

typedef struct _myst
{
    int a;
    char b[10];
}myst;
 
void cbfunc(myst *mt)
{
    printf("@MPD calling function pointer with args %d %s \n", mt->a, mt->b);
    fprintf(stdout,"called %d %s.\n",mt->a,mt->b);
}
 
int main()
{
 
    /* func pointer */
    void (*callback)(void *);
 
    //param
    myst m;
    m.a=10;
    strcpy(m.b,"123");
     
    /* point to callback function */
    callback = (void*)cbfunc;
     
    /* perform callback and pass in the param */
    callback(&m);
 
    return 0;
 
}
