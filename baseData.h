/* 置换表基本数据结构 */ 

/*---------初始置换IP---------*/
// IP置换表 
int IP_table[64];


/*---------迭代T---------*/
/* -----------------------------------------1. Feistel轮函数 */ 
// E-扩展规则（比特-选择表）
// 将32位的串R(i-1)作E扩展，变成48位的串E(R(i-1))
int E_Table[48];
 
// 二进制6-4 转换机制：S-盒
// S1...S8,每个盒有4行16列 
int S_box[8][4][16];

// P置换得到轮函数最终结果
int P_table[32];

 /* ---------------------------------2. 轮函数中子密钥Ki生成 */
// PC-1置换表
int PC1_table[56];

// PC-2压缩置换表
int PC2_table[56]; 

/*---------逆置换IP^-1---------*/ 
// 逆置换表IP^-1
int FP_table[64];
 

