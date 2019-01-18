#include <stdio.h>
#include <stdlib.h>
#define SHA256_ROTL(a,b) (((a>>(32-b))&(0x7fffffff>>(31-b)))|(a<<b))//��aѭ������bλ 
#define SHA256_SR(a,b) ((a>>b)&(0x7fffffff>>(b-1)))//��a����bλ����˲�0 
#define SHA256_Ch(x,y,z) ((x&y)^((~x)&z))//���x,��y,����z������T1ʱʹ�� 
#define SHA256_Maj(x,y,z) ((x&y)^(x&z)^(y&z))//����ÿ��bit��Ϊ�浱�ҽ���x,y,z�ж��Ϊ�棨2��3����������T2ʹ�� 
#define SHA256_E1(x) (SHA256_ROTL(x,26)^SHA256_ROTL(x,21)^SHA256_ROTL(x,7))//����T1ʱʹ��
#define SHA256_E0(x) (SHA256_ROTL(x,30)^SHA256_ROTL(x,19)^SHA256_ROTL(x,10))//����T2ʱʹ�� 
#define SHA256_O0(x) (SHA256_ROTL(x,25)^SHA256_ROTL(x,14)^SHA256_SR(x,3))//����W16-63ʱʹ��
#define SHA256_O1(x) (SHA256_ROTL(x,15)^SHA256_ROTL(x,13)^SHA256_SR(x,10))//����W16-63ʱʹ��
extern char* StrSHA256(const char* str, long long length, char* sha256){
    /*
    �����ַ���SHA-256
    ����˵����
    str         �ַ���ָ��
    length      �ַ�������
    sha256         ���ڱ���SHA-256���ַ���ָ��
    ����ֵΪ����sha256
    */
    char *pp, *ppend;
    int l, i, W[64], T1, T2, A, B, C, D, E, F, G, H, H0, H1, H2, H3, H4, H5, H6, H7;
	//A-H,H0-H7��Ӧ32bit�Ĵ���������int��������iҲ����32bit��ʹ�� 
    H0 = 0x6a09e667, H1 = 0xbb67ae85, H2 = 0x3c6ef372, H3 = 0xa54ff53a;
    H4 = 0x510e527f, H5 = 0x9b05688c, H6 = 0x1f83d9ab, H7 = 0x5be0cd19;//sha256�̶���ʼֵ 
    int K[64] = {//sha256�̶��ֳ��� 
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    };
    l = length + ((length % 64 >= 56) ? (128 - length % 64) : (64 - length % 64));//���󳤶ȣ���λ���ֽڣ� 
    if (!(pp = (char*)malloc((unsigned int)l))) return 0;//�����Ӧ���ȵĿռ�洢���� 
    for (i = 0; i < length; pp[i + 3 - 2 * (i % 4)] = str[i], i++);
    for (pp[i + 3 - 2 * (i % 4)] = 128, i++; i < l; pp[i + 3 - 2 * (i % 4)] = 0, i++);//���1��0 
    *((int*)(pp + l - 4)) = length << 3;//����3bit�൱�ڳ�8���õ���bitΪ��λ�ĳ�����Ϣ�ĵ�32λ 
    *((int*)(pp + l - 8)) = length >> 29;//��䳤����Ϣ�ĸ�32λ 
    //printf("%x\n",'abc');
    //printf("%02X\n",pp[0]);
	//for(int j=0;j<l;j++)printf("%02X",pp[j]);
    //printf("\n");
    for (ppend = pp + l; pp < ppend; pp += 64){//��512bitΪһ���飬ʵ��merkle�Ĺ�ϣ�㷨�ṹ 
        for (i = 0; i < 16; W[i] = ((int*)pp)[i], i++);//�õ�ǰ16��W[i]����Ϊ32bit 
        for (i = 16; i < 64; W[i] = (SHA256_O1(W[i - 2]) + W[i - 7] + SHA256_O0(W[i - 15]) + W[i - 16]), i++);
        //�õ���ǰ���ķ����Ӧ������64��W[i]  
        A = H0, B = H1, C = H2, D = H3, E = H4, F = H5, G = H6, H = H7;
        for (i = 0; i < 64; i++){//64���ֺ��� 
            T1 = H + SHA256_E1(E) + SHA256_Ch(E, F, G) + K[i] + W[i];
            T2 = SHA256_E0(A) + SHA256_Maj(A, B, C);
            H = G, G = F, F = E, E = D + T1, D = C, C = B, B = A, A = T1 + T2;
        }
        H0 += A, H1 += B, H2 += C, H3 += D, H4 += E, H5 += F, H6 += G, H7 += H;
    }
    free(pp - l);
    sprintf(sha256, "%08X%08X%08X%08X%08X%08X%08X%08X", H0, H1, H2, H3, H4, H5, H6, H7);
    return sha256;
}
 

/*�÷�ʾ��*/
#include <stdio.h>
#include <stdlib.h>

extern char* StrSHA256(const char* str, long long length, char* sha256);

int main(void){
    char text[] = "503";//ֱ����˫�����������������ַ��� 
    char sha256[65];
    double Length = sizeof(text)-1;
	if(Length >= 2305843009213694000)return 0;//sha256�����벻�ܳ���2^64bits 
    StrSHA256(text,Length,sha256);  // sizeof()����Ľ��������ĩβ��'\0'Ӧ��1
    puts(sha256);
    //puts(StrSHA256(text,sizeof(text)-1,sha256));    // ��������ֵ��sha256��ֱ�����Ҳ����
    return 0;
}
