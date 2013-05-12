#include <openssl/rc4.h> //Подключаем библиотеку с нашим алгоритмом 
#include <openssl/md5.h>
#include <stdio.h> 
#include <unistd.h> 

void main (int argc, char* argv[]) 
{ 
char buff[1024]; 
RC4_KEY key; //Описываем структуру типа ключ 
RC4_set_key(&key,sizeof(argv[2]),argv[2]); //Привязываем к ключу необходимый аргумент 
FILE *fi = NULL, *fo = NULL; 
//Открываем файлы на чтение и запись 
fi = fopen(argv[1],"rb"); 
fo = fopen(argv[3],"wb"); 
while (!feof(fi)) 
{ 
char msg[1024]; 
int size = fread(msg,1,1024,fi); //Пытаемся считать 1024 байта информации, 
msg[size] = 0; 
RC4(&key,size,msg,buff); //Кодируем считаные данные и передаём в буфер 
fwrite(buff,1,size,fo); //Записываем буфер в файл 
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
