/*---------初始置换IP---------*/
// IP置换
// 对输入char数组进行IP置换 
char* Init_Permutation(char* M) {
	char* IP_result = new char[64];
	for (int i = 0; i < 64; i++) {
		IP_result[i] = M[IP_table[i]];
	}
	return IP_result;
}


/*---------迭代T---------*/
/* -----------------------------------------1. Feistel轮函数 */ 
// E-扩展规则（比特-选择表）
// 将32位的串R(i-1)作E扩展，变成48位的串E(R(i-1))
char* E_explaned(char* R) {
	char* E_result = new char[48];
	for (int i = 0; i < 48;i++) {
		E_result[i] = R[E_table[i]];
	}
	return E_result;
}
// 将48位的串E(R(i-1))和Ki二进制串按位异或运算
// ki由密钥K生成
char* XOR(char* ER, char* ki) {
	char* XOR_result = new char[48];
	for (int i = 0; i < 48; i++) {
		XOR_result[i] = ER[i]^ki[i]; 
	}
	return XOR_result;
}


// 二进制6-4 转换机制：S-盒
// S1...S8,每个盒有4行16列 
// 最后合并得到长32的串(48->32)
char* S_BoxTrans(char* data) {
	char* result = new char[32];
	for (int i = 0; i < 8; i++) {
		int nindex = i * 6;
		int mindex = i << 2;
		// n行m列
		// n=(b1b6)10
		// m=(b2b3b4b5)10
		int n = (data[nindex] << 1) + data[nindex+5];
		int m = (data[nindex+1] << 3) + (data[nindex+2] << 2) + (data[nindex+3] << 1) + data[nindex+4]；
		// 从sbox中选取对应值
		int num = S_box[i][n][m];

		// 转成4位二进制
		result[mindex] = (num&0x08) >> 3;
		result[mindex+1] = (num&0x04) >> 2;
		result[mindex+2] = (num&0x02) >> 1;
		result[mindex+3] = num&0x01;
	}
	return result;
}

// P置换得到轮函数最终结果
char* P_Transform(char* data) {
	char* result = new char[32];
	for (int i = 0; i < 32; i++) {
		result[i] = data[P_table[i]];
	}
	return result;
}





// 置换选择表1，去除8位校验位，得56位密钥
char* get_56bit_Realkey(char* key) {
	char* realkey = new char[56];
	for (int i = 0; i < 64; i++) {
		 // 逢8去1
		if ((i+1)%8 != 0) {
			realkey = key[PC1_table[i]];
		}
	}
	return realkey;
}

// 置换选择表2，去除8位校验位，得48位ki
char* get_48bit_subkey(char* newrealkey) {
	char* subkey = new char[48];
	for (int i = 0; i < 56; i++) {
		// 去除9，18，22，25，35，38，43，54位
		if (i != 9 && i != 18 && i != 22 && i != 25
		 && i != 35 && i != 38 && i != 43 && i != 54) {
			subkey = newrealkey[PC2_table[i]];
		}
	}
	return subkey;
}


// i=1,2,9,16时，循环左移一个位置，否则循环左移两个位置
int movetoleft[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
// 48位分左右分别左移
void Move_Left(char* data, int times) {
	char* savedata = new char[56];
	// 保存移位数据
	memcpy(savedata, data, times);
	memcpy(savedata+times, data+28, times);

	// 前28位
	memcpy(data, data+times, 28-times);
	memcpy(data+28-times, savedata, times);
	// 后28位
	memcpy(data+28, data+28+times, 28-times);
	memcpy(data+56-times, savedata+times, times);


}


// 从64位密钥得到16个子密钥
void getSubkeys(char* Key, char subkeys[16][48]) {
	char* realkey = new char[56];
	// PC-1置换
	realkey = get_56bit_Realkey(key);
	// 16次循环迭代
	for (int i = 0; i < 16; i++) {
		// 左移movetoleft[i]位
		Move_Left(realkey, movetoleft[i]);
		// // PC-2置换，得到子密钥
		subkeys[i] = get_48bit_subkey(realkey);
	}
}


// IP逆置换
// 对输入char数组进行IP置换 
char* Final_Permutation(char* code) {
	char* FP_result = new char[64];
	for (int i = 0; i < 64; i++) {
		FP_result[i] = code[FP_table[i]];
	}
	return FP_result;
}


char* charTobit(char* text);
char* bitTochar(char* bits);
//加密
// 8个字节(64位)明文利用子密钥转为密文
void Encipher(char* plaintext, char subKeys[16][48], char* ciphertext) {   
    char* plain = new char[64];
	char* afterIP = new char[64];
	char* Left = new char[48];   
    char* Right = new char[48];
	char* eRight = new char[48];
	char* xor_result = new char[48];
	char* s_result = new char[32];
	char* f_result = new char[32];
	char* Ri = new char[32];
	char* afterFP = new char[64];
	
	plain = charTobit(plaintext);     
    //初始IP  
	afterIP = Init_Permutation(plain);
     
    //16轮迭代   
    for(int i = 0; i < 16; i++){   
		// 左半部分
		memcpy(Left, afterIP, 32); 
		// 右半部分       
        memcpy(Right,afterIP+32,32);   
        //右半部分E扩展置换，32位->48位   
		eRight = E_explaned(Right);
        //将右半部分与子密钥进行异或操作   
		xor_result = XOR(eRight, subkeys[i]);   
        //异或结果进入Sbox，输出32位结果   
        s_result = S_BoxTrans(xor_result);   
        //P置换得到轮函数最终结果
		f_result = P_Transform()
        //明文左半部分与轮函数结果进行异或  
        Ri = XOR(Left,f_result);
		// Li和Ri交换
        if(i < 15){  
            Swap(Right,Ri);   
        }   
		memcpy(afterIP, Right, 32);
		memcpy(afterIP+32, Ri, 32);
    }   
    //逆初始置换（IP^-1置换）   
    afterFP = Final_Permutation(afterIP);
    ciphertext = bitTochar(afterFP);
}   

//解密
// 8个字节(64位)密文利用子密钥转为明文
void Decrypt(char* ciphertext, char subKeys[16][48], char* plaintext) {   
    char* cipher = new char[64];
	char* afterIP = new char[64];
	char* Left = new char[48];   
    char* Right = new char[48];
	char* eRight = new char[48];
	char* xor_result = new char[48];
	char* s_result = new char[32];
	char* f_result = new char[32];
	char* Ri = new char[32];
	char* afterFP = new char[64];
	
	cipher = charTobit(ciphertext);     
    //初始IP  
	afterIP = Init_Permutation(cipher);
     
    //16轮迭代   
    for(int i = 15; i >= 0; i--){   
		// 左半部分
		memcpy(Left, afterIP, 32); 
		// 右半部分       
        memcpy(Right,afterIP+32,32);   
        //右半部分E扩展置换，32位->48位   
		eRight = E_explaned(Right);
        //将右半部分与子密钥进行异或操作   
		xor_result = XOR(eRight, subkeys[i]);   
        //异或结果进入Sbox，输出32位结果   
        s_result = S_BoxTrans(xor_result);   
        //P置换得到轮函数最终结果
		f_result = P_Transform()
        //明文左半部分与轮函数结果进行异或  
        Ri = XOR(Left,f_result);
		// Li和Ri交换
        if(i < 15){  
            Swap(Right,Ri);   
        }   
		memcpy(afterIP, Right, 32);
		memcpy(afterIP+32, Ri, 32);
    }   
    //逆初始置换（IP^-1置换）   
    afterFP = Final_Permutation(afterIP);
    plaintext = bitTochar(afterFP);
}   