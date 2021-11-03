#include <stdio.h>
#include <string.h>

int main(){
	char *ch = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%%&\\'()*+,-./:;<=>?@[]^_`{|}~";
	char input[34]= {0};
	char command1[0x100];
	char command2[0x100];
	FILE *fd = fopen("save.txt", "a+");
	if (fd)
		fscanf(fd, "%s", input);
	for(int i = 0; i < strlen(ch); i++){
		if (ch[i] == '\"' ||  ch[i] == '\\' || ch[i] == '`' ){
			sprintf(command1, "echo \"%s\\%c\" > save.txt", input, ch[i]);
			sprintf(command2, "./exploit2 %s\\%c", input, ch[i]);
		}
		else{
			sprintf(command1, "echo \"%s%c\" > save.txt", input, ch[i]);
			sprintf(command2, "./exploit2 %s%c", input, ch[i]);
		}
		printf("%s\n", command2);
		system(command1);
		system(command2);
	}
	return 0;
}
