#include <string.h>
#include <iostream>
#include <cstdio>
#include <string>

using namespace std;

int main()
{
	const char* const_message = "		This message from printf const char* \n";
	const char* const_cout_message = "		This message from cout const char* \n";
	char s[100];
	printf("\nEnter Mike's favourite color:");
	cin >> s;
	printf("You have entered ");
	printf(s);
	printf("\n");
	if (strcmp(s, "red")==0) {
		printf("You have chosen wisely! Here are some hello worlds... \n");
		printf("	Flavours of Hello World from MPDS visual studio APPSEC: \n");
		printf("		This message from printf.\n");
		printf(const_message);
		cout << "		This message from cout \n";
		cout << const_cout_message;
	}
	else {
		printf("That is not Mike's favourite color!\n");
	}
	printf("...end of program. \n");
	return 0;

}


