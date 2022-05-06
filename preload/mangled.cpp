#include <stdio.h>
#define mangled(x) (#x)
void foo(void)
{
    printf("Value of foo is %d\n", foo);
    printf("String of foo is : %s\n", mangled(foo));
}
