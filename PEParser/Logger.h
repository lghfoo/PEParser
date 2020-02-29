#pragma once
#include<cstdio>
#include<cstdarg>
class Logger
{
public:
	static void Printlnf(const char* Format, ...) {
		va_list args;
		va_start(args, Format);
		vprintf(Format, args);
		va_end(args);
		printf("\n");
	}
};

