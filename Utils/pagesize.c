/*
  This code checks the size of a memory page

  Author: Guillem Alminyana
*/

#include <stdio.h>
#include <unistd.h>

int main()
{
	int size = getpagesize();
	printf("\nPage size on this system is %i bytes\n", size);
	return 0;
}
