#include <iostream>
#include <fstream>
#include <vector>
#include <string>

using namespace std;

int h2d(char hex)
{
	if (hex<='9')
		return hex-'0';
	else
		return 10+hex-'a';
}

int hex2dec(string hex)
{
	int p = 1;
	int s = 0;
	for (int i = hex.size()-1; i >= 0; --i)
	{
		s+=p*h2d(hex[i]);
		p*=16;
	}
	return s;
}

int main()
{
	vector<pair<int, int> > data;
	string fname = "data2.txt";
	key

}