#ifndef _H_UTILS
#define _H_UTILS

#include <ctype.h>
#include <stdio.h>

char *upper_case(char *string)
{
  char *c, n;
  int index = 0;
  char *new_string;
  size_t len = strlen(string);
  new_string = (char *)malloc(len);
  c = string;
  while (*c != '\0')
    {
      n = (char ) toupper((int)*c);
      new_string[index] = n;
      c++;
      index++;
    }
  new_string[len] = '\0';
  
  return new_string;
  
}
#endif
