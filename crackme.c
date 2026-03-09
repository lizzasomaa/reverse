#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <stdbool.h>
#include <windows.h>
#include <intrin.h>
#include <winternl.h>
#include <math.h>


#define KEY "TRiPO_lab1"
#define EXPECTED_CRC 0xb078c22e
#define PASSWORD "(HZ6BPNUV)DEN0`q uc"

#pragma comment(lib, "advapi32.lib")

void create_key(char *string);
void merge_strings(char *string);
bool check_password(char *string);
void check_password_end();

uint32_t crc32(const unsigned char *data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xEDB88320;
            else
                crc >>= 1;
        }
    }
    return crc ^ 0xFFFFFFFF;
}

void decrypt(char *s, int len)
{
    for (int i = 0; i < len; i++) {
        if (32 <= s[i] && s[i] <= 126) {
            char encypted_sym = s[i] - 32;
            char key_sym = KEY[i % strlen(KEY)] - 32;
            s[i] = (encypted_sym - key_sym + 95) % 95 + 32;
        }
    }
}

void create_key(char *string)
{
    //дополнительная проверка пароля
    if (check_password(string) == false) return;

    char filename[] = "H8\\:1LzV[&";
    decrypt(filename, strlen(filename));
    FILE *fs = fopen(filename, "w");
    char key[] = "~vCSHXeZ[*MKbIR";  

    srand(time(NULL));
    decrypt(key, strlen(key));
    for (int i = 4; i < 14; i++) {
        key[i] = 33 + rand() % (126 - 33);
    }

    fprintf(fs, "%s\n", key);
    fclose(fs);
}

void merge_strings(char *string) 
{
    //дополнительная проверка пароля
    if (check_password(string) == false) return;

    char s1[33], s2[33], s[65];
    char* str1 = s1;
    char* str2 = s2;
    int N, k, j;
    char filename[] = "B8\\85?`VUzC:]^DXa";
    decrypt(filename, strlen(filename));
    FILE *fs = fopen(filename, "r");
    fscanf(fs, "%d", &N);


    int state = 0;  
    int i = 0;
    while (i < N) {
        switch (state) {
            case 0:  //чтение строк
                s[0] = '\0';
                fscanf(fs, "%s %s", s1, s2);
                int len1 = strlen(s1);
                state = 1;
                break;
            case 1:  //поиск пересечения
                int l = -1;
                for (k = 0; k < len1; k++) {
                    if (strncmp(str1 + k, str2, len1 - k) == 0) {
                        l = k;
                        break;
                    }
                }
                state = (l == -1) ? 2 : 3;
                break;
            case 2:  //нет пересечения
                strcpy(s, s1);
                strcat(s, s2);
                state = 4;
                break;
            case 3:  //есть пересечение
                s1[l] = '\0';
                strcpy(s, s1);
                strcat(s, s2);
                state = 4;
                break;
            case 4:  //вывод
                printf("%s\n", s);
                i++;
                state = 0;
                break;
        }
    }
    fclose(fs);
}

//проверка на отладчик
bool check_debugger()
{
    //1. isDebuggerPresent
    if (IsDebuggerPresent()) {
        //printf("1\n");
        return true;
    }

    //2. CheckRemoteDebuggerPresent
    BOOL isDebuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent);
    if (isDebuggerPresent) {
        //printf("2\n");
        return true;
    }

    //3. Trap Flag
    BOOL isDebugged = TRUE;
    __try {
        __asm {
            pushfd
            or dword ptr[esp], 0x100 
            popfd                    
            nop                      
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        isDebugged = FALSE;
    }
    if (isDebugged)
    {
        //printf("3\n");
        return true;
    }

    //4. ProcessDebugObjectHandle
    HANDLE debugObject = NULL;
    NTSTATUS status = NtQueryInformationProcess(
        GetCurrentProcess(),
        0x1E,
        &debugObject,
        sizeof(HANDLE),
        NULL);
    if (0x00000000 == status && NULL != debugObject) {
        //printf("4\n");
        return true;
    }

    return false;
}

//проверка на виртуальную машину
bool check_vm()
{
    //1. CPUID
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 1);
    bool isHypervisor = (cpuInfo[2] & (1 << 31));
    if (isHypervisor) return true;

    //2. 
    HKEY hKey = NULL;
    LONG ret;
    char value[1024];
    DWORD size = sizeof(value);
    ret = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "System\\CurrentControlSet\\Control\\SystemInformation",
        0,
        KEY_READ,
        &hKey);
    if (ret == ERROR_SUCCESS) {
        ret = RegQueryValueExA(hKey, "SystemProductName", NULL, NULL, (LPBYTE)value, &size);
        if (ret == ERROR_SUCCESS) { 
            if (strstr(value, "VirtualBox") || strstr(value, "VMware") || strstr(value, "KVM") || strstr(value, "Bochs") || strstr(value, "Xen")) {
                return true;
            }
        }
    }
    return false;
}

void evil_code() {
    __asm {
        __emit 0xEB    
        __emit 0xFF    
        __emit 0xC0    
        __emit 0x48  
    }
    char msg[] = ":IS=OC\\FH2US"; //evil code!!!
    decrypt(msg, strlen(msg));
    printf("%s\n", msg);
}

void antidisassembly1() {
    __asm {
        call $ + 5
        add [esp], 5
        ret
    }
    char msg[] = "9<]D1SROE}NRM@ELQPi&TFO6OIabc2"; //antidissasembly couldn't see it!!!
    decrypt(msg, strlen(msg));
    printf("%s\n", msg);
}

void antidisassembly2() {
    __asm {
        xor eax, eax
        jz label
        __emit 0xe9
    label:
        call evil_code
    }
}

void doThis() 
{
    int a,b,c,d;
    srand(time(0));
    a=rand()+1;b=rand()+1;
    c=rand()+1;d=rand()+1;
    if (a+b+c*d > 0)
    {
        printf("yes\n");
        return;
    }
    printf("no\n");
}

int mypow(int base, int exp) {
    int result = 1;
    for (int i = 0; i < exp; i++) {
        result *= base;
    }
    return result;
}

int compute(int input) {
     if (input % 2 == 0) {
        int temp = (input >> 1) << 1; 
        return temp | 0x1;
    } else {
        double temp = sqrt(mypow(input, 2));
        return (int)temp + (2 - 1);
    }
}

#pragma auto_inline(off)

bool check_password(char *string)
{
    char password[100] = PASSWORD;
    decrypt(password, strlen(password));

    if (strcmp(string, password) == 0) return true;
    else return false;
}

void check_password_end()
{
 //примерный адрес окончания check_password
}

#pragma auto_inline(on)

int main()
{
    //проверка на отладчик
    if (check_debugger()) {
        char message[] = "98LF7GRTbu:GO4DEQ";
        decrypt(message, strlen(message));
        printf("%s\n", message);

        //при обнаружении отладчика изменяем код функции check_password
        unsigned char* code = (unsigned char*)check_password;
        DWORD oldProtect;

        VirtualProtect(code, 16, PAGE_EXECUTE_READWRITE, &oldProtect); //отключаем защиту от записи

        __asm {
            mov edi, offset check_password  
            mov byte ptr [edi], 0x31        
            mov byte ptr [edi + 1], 0xC0    
            mov byte ptr [edi + 2], 0xC3    
        }

        VirtualProtect(code, 16, oldProtect, &oldProtect);
        return 1;
    }

    //проверка на виртуальную машину
    if (check_vm()) {
        char message[] = "K<\\EEAYaPr8;S?5_QGWv8GO5";
        decrypt(message, strlen(message));
        printf("%s\n", message);
        return 1;
    }

    //вычисляем crc32 функции check_password
    unsigned char *func_start = (unsigned char *)check_password;
    unsigned char *func_end = (unsigned char *)check_password_end;
    size_t func_size = (size_t)(func_end - func_start);
    uint32_t crc = crc32((const unsigned char *)func_start, func_size);
    //printf("%x\n", crc);

    //проверяем crc32
    if (crc != EXPECTED_CRC) {
        char message[] = "8;O4;?]CV%LB\\5OHNUbs:8XP=OQKIz:7";
        decrypt(message, strlen(message));
        printf("%s\n", message);
        return 1;
    }

    char welcome_msg[] = ":A^6B_]CV%LB\\5i_";
    decrypt(welcome_msg, strlen(welcome_msg));
    printf("%s", welcome_msg);

    char string[100];
    scanf("%s", string);

    //ложная проверка пароля
    if (strcmp(string, "ed|d1BPF")==0) {
        char message[] = "8B\\C5CaaSrHFa@BD";
        decrypt(message, strlen(message));
        //printf("%s\n", message);
        create_key(string);
        merge_strings(string);
    }
    else {
        char message[] = "LEY?7_]CV%LB\\5OBbVbzIY]P6AXGbt=8M<";
        decrypt(message, strlen(message));
        //printf("%s\n", message);
    }

    //основная проверка пароля
    if (check_password(string)) {
        char message[] = "8B\\C5CaaSrHFa@BD";
        decrypt(message, strlen(message));
        printf("%s\n", message);
        create_key(string);
        merge_strings(string);
    }
    else {
        char message[] = "LEY?7_]CV%LB\\5";
        decrypt(message, strlen(message));
        printf("%s\n", message);
    }

    if (compute(3) == 4) {
        antidisassembly1();
        antidisassembly2();
    }
    else {
        doThis();
    }

    return 0;
}
