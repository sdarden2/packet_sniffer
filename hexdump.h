#ifndef _H_HEXDUMP
#define _H_HEXDUMP

#define DEFAULT_WIDTH 16

#include <stdio.h>
#include <string.h>

void hex_dump(unsigned char *buffer, int size, int width)
{
  unsigned char *c;
  int line_start = 0;
  int i,k,spacer, index = 0;
  int needed_spaces;
  
  if (width <= 0)
    width = DEFAULT_WIDTH;
  if (size < width)
    needed_spaces = width - size;
  else
    needed_spaces = width - size%width;
  
  while (index < size)
  {
    for (i = line_start; i < line_start+width; i++)
      {
	if (index == size)
	  break;
	c = buffer[i];
	printf("%02x ",c);

	index++;
      }
    if (line_start + width > size)
      {
	for (spacer = 0; spacer < needed_spaces; spacer++)
	  printf("   ");
      }
    printf("\t |");
    for (k = line_start; k < line_start + width; k++)
      {
	if (k == size)
	  break;
	c = buffer[k];
	if (c >= 33 && c <= 126)
	  printf("%c",c);
	else
	  printf(".");
      }
    line_start = i;
    
    
    printf("\n");
  }
  
  

  
}


#endif
