#include <Windows.h>
#include <stdio.h>

#define HASH_KEY						13
#pragma intrinsic( _rotr )
__forceinline DWORD ror(DWORD d) { return _rotr(d, HASH_KEY); }
__forceinline DWORD hash(char * c)
{
	register DWORD h = 0;
	do {
		h = ror(h);
		h += *c;
	} while (*++c);
	return h;
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		printf("Usage: %s <function name>\n", argv[0]);
		return 1;
	}
	printf("0x%x\n", hash(argv[1]));
	return 0;
}

