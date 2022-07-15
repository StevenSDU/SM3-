#include <iostream>
#include "SM3.h"
using namespace std;

//十进制转16进制
void hex(int a, char ch[10]) 
{
	char mid_char;
	int temp = 0, i = 0;
	while (a / 16 > 0)
	{
		temp = a % 16;
		if (temp > 9)
			ch[i] = temp + 97;
		else
			ch[i] = temp + 48;
		i++;
		a = a / 16;

		if (a < 16)
		{
			ch[i] = a + 48;
			ch[i + 1] = 0;
			break;
		}
	}
	temp = strlen(ch);
	for (i = 0; i < strlen(ch) / 2; i++)
	{
		mid_char = ch[i];
		ch[i] = ch[temp - i - 1];
		ch[temp - i - 1] = mid_char;
	}
}

int main(void)
{
	unsigned char MsgHash2[64];
	unsigned char MsgHash1[64];
	unsigned int i;
	unsigned int MsgLen = 64;
	char Hash1[] = { 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
					   0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
					   0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
					   0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
					   0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
					   0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
					   0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
					   0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, };
	unsigned int HashLen1 = sizeof(Hash1);
	SM3_256(Hash1, HashLen1, MsgHash1);
	cout<<"哈希后数据:"<<"\n";
	for (i = 0; i < MsgLen; i++)
	{
		cout<<MsgHash1[i]<<'\n';
	}
	char attack[10];
	int p = rand() * rand();
	//穷搜
	for (int i = p; i < p + 0xfffff; i++) 
	{
		hex(i, attack);
		unsigned int attack_len = strlen((char*)attack);
		SM3_256(attack, attack_len, MsgHash2);
		if (MsgHash2[0] == MsgHash1[0] && MsgHash2[1] == MsgHash1[1])
		{
			cout << "找到碰撞"<<"\n";
			break;
		}
	}
	return 0;
}
