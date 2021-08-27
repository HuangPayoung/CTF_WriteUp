#include <iostream>
#include <cstdio>

using namespace std;
 
int main()
{
	long long a = 28537194573619560;
	char *p = (char*)&a;
	char b[] = ":\"AL_RT^L*.?+6/46";
	for(int i = 0; b[i] != 0; i++){
		b[i] = b[i] ^ p[i % 7];
	}
	cout << b << endl;
}