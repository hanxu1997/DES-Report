#include"baseData.h" 

/*---------初始置换IP---------*/
// IP置换
// 对输入char数组进行IP置换 
char* Init_Permutation(char* M);

/*---------迭代T---------*/
/* -----------------------------------------1. Feistel轮函数 */ 
// E-扩展规则（比特-选择表）
// 将32位的串R(i-1)作E扩展，变成48位的串E(R(i-1))
char* E_explaned(char* R);
// 将48位的串E(R(i-1))和Ki二进制串按位异或运算
// ki由密钥K生成
char* XOR(char* ER, char* ki);
 
// 二进制6-4 转换机制：S-盒
// S1...S8,每个盒有4行16列
// 最后合并得到长32的串(48->32) 
char* S_BoxTrans(char* data);


// P置换得到轮函数最终结果
char* P_Transform(char* data);

 /* ---------------------------------2. 轮函数中子密钥Ki生成 */
// PC-1置换表
// 置换选择表1，去除校验位，得56位密钥
char* get_56bit_Realkey(char* key)；
// PC-2压缩置换表
// 置换选择表2，去除8位校验位，得48位ki
char* get_48bit_subkey(char* newrealkey);

// 48位分左右分别左移
void Move_Left(char* data, int times)；

// 从64位密钥得到16个48位子密钥
void getSubkeys(char* Key, char subkeys[16][48])；

/*---------逆置换IP^-1---------*/ 
// IP逆置换
// 对输入char数组进行IP置换 
char* Final_Permutation(char* code) 

// 8位char数组转64bit
char* charTobit(char* text);
// 64bit转8位char数组
char* bitTochar(char* bits);
/* ---------16次迭代T ------------*/
//加密
// 8个字节(64位)明文利用子密钥转为密文
void Encipher(char* plaintext, char subKeys[16][48], char* ciphertext);

//解密
// 8个字节(64位)密文利用子密钥转为明文
void Decrypt(char* ciphertext, char subKeys[16][48], char* plaintext);