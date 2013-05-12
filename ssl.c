#include <openssl/rc4.h> //���������� ���������� � ����� ���������� 
#include <openssl/md5.h>
#include <stdio.h> 
#include <unistd.h> 

void main (int argc, char* argv[]) 
{ 
char buff[1024]; 
RC4_KEY key; //��������� ��������� ���� ���� 
RC4_set_key(&key,sizeof(argv[2]),argv[2]); //����������� � ����� ����������� �������� 
FILE *fi = NULL, *fo = NULL; 
//��������� ����� �� ������ � ������ 
fi = fopen(argv[1],"rb"); 
fo = fopen(argv[3],"wb"); 
while (!feof(fi)) 
{ 
char msg[1024]; 
int size = fread(msg,1,1024,fi); //�������� ������� 1024 ����� ����������, 
msg[size] = 0; 
RC4(&key,size,msg,buff); //�������� �������� ������ � �������� � ����� 
fwrite(buff,1,size,fo); //���������� ����� � ���� 
} 
fclose(fi); 
fclose(fo); 
}

int get_MD5()
{
int i;
unsigned char hash[16];

MD5((unsigned char *) "qwe", 3, hash);
for (i = 0; i < 16; i++)
{
printf("%02x", hash[i]);
}
putchar('\n');

return 0;
}
