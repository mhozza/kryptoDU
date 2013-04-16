#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>

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

int s[] = {46, 47, 49, 54, 55, 57, 17, 37, 35, 62, 22, 58, 4, 28, 51, 24, 32, 16, 29, 1, 53, 7, 12, 52, 0, 63, 42, 45, 34, 5, 26, 33, 14, 8, 59, 3, 43, 20, 41, 31, 6, 40, 61, 2, 21, 56, 30, 39, 10, 25, 23, 38, 19, 36, 15, 60, 18, 44, 9, 11, 13, 27, 48, 50};
int p[] = {10, 5, 9, 4, 18, 19, 21, 23, 16, 22, 2, 12, 13, 1, 17, 8, 15, 20, 3, 14, 7, 11, 0, 6};

int sbox(int val, int num)
{	
	return s[(((2<<6)-1)&(val>>(num*6)))]<<(num*6);
}

int perm(int val)
{
	int r = 0;
	for (int i = 23; i >= 0; --i)
	{
		r <<= 1;
		r |= ((val >> (24-p[24-i]-1)) & 1);
	}	
	return r >> 1;
}

int main()
{
	vector<pair<int, int> > data;
	string fname = "data2.txt";
	string line;
	ifstream f(fname.c_str());

	while(getline(f, line))
	{
		istringstream ss(line);
		string a, b;		
		ss >> a >> b;
		data.push_back(make_pair(hex2dec(a),hex2dec(b)));
	}

	cerr << "decrypting..." << endl;

	for(int key3 = 0; key3<(2<<24); key3++)
	{
		if (!(key3 & (2<<12)-1))
			cerr << (float)key3/(2<<24) << endl;
		for(int key2 = 0; key2<(2<<6); key2++)
		{
			for(int key1 = 0; key1<(2<<6); key1++)
			{				
				int index = 0;
				bool found = true;
				while(true)
				{
					//ct
					int ct = data[index].first ^ key3;
					//subs 24bit
					int val = 0;
					for (int i = 0; i < 4; ++i)
					{
						val+=sbox(ct,i);
					}
					//perm 24bit - staci mi poslednych 6 bitov, tak je aj noakdena fcia
					val = perm(val); //& ((2<<6)-1); // nechame si len poslednych 6 bitov // toto treba spravit velmi efektivne
					//xor 6bit
					val ^= key2;
					//subs 6bit
					val+= sbox(val,0);
					//xor 6bit
					val^=key1;
					//test
					if(val==(data[index].second & ((2<<6)-1)))
					{
						index++;						
					}
					else
					{
						found = false;
						break;
					}
				}
				if(found)
				{
					cout << "key3:" << key3 << endl;
					cout << "key2:" << key2 << endl;
					cout << "key1:" << key1 << endl;
					return 0;				
				}
			}			
		}
	}
}

