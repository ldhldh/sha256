#include <stdio.h>
#include <stdlib.h>
#define SHA256_ROTL(a,b) (((a>>(32-b))&(0x7fffffff>>(31-b)))|(a<<b))//把a循环左移b位 
#define SHA256_SR(a,b) ((a>>b)&(0x7fffffff>>(b-1)))//把a右移b位，左端补0 
#define SHA256_Ch(x,y,z) ((x&y)^((~x)&z))//如果x,则y,否则z，计算T1时使用 
#define SHA256_Maj(x,y,z) ((x&y)^(x&z)^(y&z))//对于每个bit，为真当且仅当x,y,z有多个为真（2或3个），计算T2使用 
#define SHA256_E1(x) (SHA256_ROTL(x,26)^SHA256_ROTL(x,21)^SHA256_ROTL(x,7))//计算T1时使用
#define SHA256_E0(x) (SHA256_ROTL(x,30)^SHA256_ROTL(x,19)^SHA256_ROTL(x,10))//计算T2时使用 
#define SHA256_O0(x) (SHA256_ROTL(x,25)^SHA256_ROTL(x,14)^SHA256_SR(x,3))//计算W16-63时使用
#define SHA256_O1(x) (SHA256_ROTL(x,15)^SHA256_ROTL(x,13)^SHA256_SR(x,10))//计算W16-63时使用
extern char* StrSHA256(const char* str, long long length, char* sha256){
    /*
    计算字符串SHA-256
    参数说明：
    str         字符串指针
    length      字符串长度
    sha256         用于保存SHA-256的字符串指针
    返回值为参数sha256
    */
    char *pp, *ppend;
    int l, i, W[64], T1, T2, A, B, C, D, E, F, G, H, H0, H1, H2, H3, H4, H5, H6, H7;
	//A-H,H0-H7对应32bit寄存器，其它int常量除了i也均作32bit串使用 
    H0 = 0x6a09e667, H1 = 0xbb67ae85, H2 = 0x3c6ef372, H3 = 0xa54ff53a;
    H4 = 0x510e527f, H5 = 0x9b05688c, H6 = 0x1f83d9ab, H7 = 0x5be0cd19;//sha256固定初始值 
    int K[64] = {//sha256固定轮常数 
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    };
    l = length + ((length % 64 >= 56) ? (128 - length % 64) : (64 - length % 64));//填充后长度（单位是字节） 
    if (!(pp = (char*)malloc((unsigned int)l))) return 0;//分配对应长度的空间存储明文 
    for (i = 0; i < length; pp[i + 3 - 2 * (i % 4)] = str[i], i++);
    for (pp[i + 3 - 2 * (i % 4)] = 128, i++; i < l; pp[i + 3 - 2 * (i % 4)] = 0, i++);//填充1和0 
    *((int*)(pp + l - 4)) = length << 3;//左移3bit相当于乘8，得到以bit为单位的长度信息的低32位 
    *((int*)(pp + l - 8)) = length >> 29;//填充长度信息的高32位 
    //printf("%x\n",'abc');
    //printf("%02X\n",pp[0]);
	//for(int j=0;j<l;j++)printf("%02X",pp[j]);
    //printf("\n");
    for (ppend = pp + l; pp < ppend; pp += 64){//以512bit为一分组，实现merkle的哈希算法结构 
        for (i = 0; i < 16; W[i] = ((int*)pp)[i], i++);//得到前16个W[i]，均为32bit 
        for (i = 16; i < 64; W[i] = (SHA256_O1(W[i - 2]) + W[i - 7] + SHA256_O0(W[i - 15]) + W[i - 16]), i++);
        //得到当前明文分组对应的所有64个W[i]  
        A = H0, B = H1, C = H2, D = H3, E = H4, F = H5, G = H6, H = H7;
        for (i = 0; i < 64; i++){//64轮轮函数 
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
 

/*用法示例*/
#include <stdio.h>
#include <stdlib.h>

extern char* StrSHA256(const char* str, long long length, char* sha256);

int main(void){
    char text[] = "503";//直接在双引号中输入待处理的字符串 
    char sha256[65];
    double Length = sizeof(text)-1;
	if(Length >= 2305843009213694000)return 0;//sha256的输入不能超出2^64bits 
    StrSHA256(text,Length,sha256);  // sizeof()计算的结果包含了末尾的'\0'应减1
    puts(sha256);
    //puts(StrSHA256(text,sizeof(text)-1,sha256));    // 函数返回值即sha256，直接输出也可以
    return 0;
}
