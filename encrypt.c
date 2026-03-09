#include <stdio.h>
#include <string.h>
#define KEY "TRiPO_lab1"

int main()
{
    char string[100] = "Superpassword_1234!";
    char decrypted[100] = {'\0'};
    char encypted[100] = {'\0'};


    for (int i = 0; i < strlen(string); i++) {
        if (32 <= string[i] && string[i] <= 126) {
            char text_sym = string[i] - 32;
            char key_sym = KEY[i % strlen(KEY)] - 32;
            encypted[i] = (text_sym + key_sym) % 95 + 32;
        }
    }
    printf("encypted: %s\n", encypted);

    for (int i = 0; i < strlen(encypted); i++) {
        if (32 <= encypted[i] && encypted[i] <= 126) {
            char encypted_sym = encypted[i] - 32;
            char key_sym = KEY[i % strlen(KEY)] - 32;
            decrypted[i] = (encypted_sym - key_sym + 95) % 95 + 32;
        }
    }
    printf("decrypted: %s\n", decrypted);
    memset(string, '\0', sizeof(string));
    memset(encypted, '\0', sizeof(encypted));
    memset(decrypted, '\0', sizeof(decrypted));

    return 0;
}