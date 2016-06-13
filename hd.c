#include "hexdump.h"
#include <string.h>

int main()
{
  char *b = "This is my mother fucking buffer yo";
  
  hexdump(b,5,2);
}
