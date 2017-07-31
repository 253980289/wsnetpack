#ifndef _INT_LIB_H_  
#define _INT_LIB_H_  
int tolower(int c)
{
	if (c >= 'A' && c <= 'Z')
	{
		return c + 'a' - 'A';
	}
	else
	{
		return c;
	}
}

int htoi(const char s[], int start, int len)
{
	int i, j;
	int n = 0;
	if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) //�ж��Ƿ���ǰ��0x����0X  
	{
		i = 2;
	}
	else
	{
		i = 0;
	}
	i += start;
	j = 0;
	for (; (s[i] >= '0' && s[i] <= '9')
		|| (s[i] >= 'a' && s[i] <= 'f') || (s[i] >= 'A' && s[i] <= 'F'); ++i)
	{
		if (j >= len)
		{
			break;
		}
		if (tolower(s[i]) > '9')
		{
			n = 16 * n + (10 + tolower(s[i]) - 'a');
		}
		else
		{
			n = 16 * n + (tolower(s[i]) - '0');
		}
		j++;
	}
	return n;
}


#endif  