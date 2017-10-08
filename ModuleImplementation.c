/*---------��ʼ�û�IP---------*/
// IP�û�
// ������char�������IP�û� 
char* Init_Permutation(char* M) {
	char* IP_result = new char[64];
	for (int i = 0; i < 64; i++) {
		IP_result[i] = M[IP_table[i]];
	}
	return IP_result;
}


/*---------����T---------*/
/* -----------------------------------------1. Feistel�ֺ��� */ 
// E-��չ���򣨱���-ѡ���
// ��32λ�Ĵ�R(i-1)��E��չ�����48λ�Ĵ�E(R(i-1))
char* E_explaned(char* R) {
	char* E_result = new char[48];
	for (int i = 0; i < 48;i++) {
		E_result[i] = R[E_table[i]];
	}
	return E_result;
}
// ��48λ�Ĵ�E(R(i-1))��Ki�����ƴ���λ�������
// ki����ԿK����
char* XOR(char* ER, char* ki) {
	char* XOR_result = new char[48];
	for (int i = 0; i < 48; i++) {
		XOR_result[i] = ER[i]^ki[i]; 
	}
	return XOR_result;
}


// ������6-4 ת�����ƣ�S-��
// S1...S8,ÿ������4��16�� 
// ���ϲ��õ���32�Ĵ�(48->32)
char* S_BoxTrans(char* data) {
	char* result = new char[32];
	for (int i = 0; i < 8; i++) {
		int nindex = i * 6;
		int mindex = i << 2;
		// n��m��
		// n=(b1b6)10
		// m=(b2b3b4b5)10
		int n = (data[nindex] << 1) + data[nindex+5];
		int m = (data[nindex+1] << 3) + (data[nindex+2] << 2) + (data[nindex+3] << 1) + data[nindex+4]��
		// ��sbox��ѡȡ��Ӧֵ
		int num = S_box[i][n][m];

		// ת��4λ������
		result[mindex] = (num&0x08) >> 3;
		result[mindex+1] = (num&0x04) >> 2;
		result[mindex+2] = (num&0x02) >> 1;
		result[mindex+3] = num&0x01;
	}
	return result;
}

// P�û��õ��ֺ������ս��
char* P_Transform(char* data) {
	char* result = new char[32];
	for (int i = 0; i < 32; i++) {
		result[i] = data[P_table[i]];
	}
	return result;
}





// �û�ѡ���1��ȥ��8λУ��λ����56λ��Կ
char* get_56bit_Realkey(char* key) {
	char* realkey = new char[56];
	for (int i = 0; i < 64; i++) {
		 // ��8ȥ1
		if ((i+1)%8 != 0) {
			realkey = key[PC1_table[i]];
		}
	}
	return realkey;
}

// �û�ѡ���2��ȥ��8λУ��λ����48λki
char* get_48bit_subkey(char* newrealkey) {
	char* subkey = new char[48];
	for (int i = 0; i < 56; i++) {
		// ȥ��9��18��22��25��35��38��43��54λ
		if (i != 9 && i != 18 && i != 22 && i != 25
		 && i != 35 && i != 38 && i != 43 && i != 54) {
			subkey = newrealkey[PC2_table[i]];
		}
	}
	return subkey;
}


// i=1,2,9,16ʱ��ѭ������һ��λ�ã�����ѭ����������λ��
int movetoleft[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
// 48λ�����ҷֱ�����
void Move_Left(char* data, int times) {
	char* savedata = new char[56];
	// ������λ����
	memcpy(savedata, data, times);
	memcpy(savedata+times, data+28, times);

	// ǰ28λ
	memcpy(data, data+times, 28-times);
	memcpy(data+28-times, savedata, times);
	// ��28λ
	memcpy(data+28, data+28+times, 28-times);
	memcpy(data+56-times, savedata+times, times);


}


// ��64λ��Կ�õ�16������Կ
void getSubkeys(char* Key, char subkeys[16][48]) {
	char* realkey = new char[56];
	// PC-1�û�
	realkey = get_56bit_Realkey(key);
	// 16��ѭ������
	for (int i = 0; i < 16; i++) {
		// ����movetoleft[i]λ
		Move_Left(realkey, movetoleft[i]);
		// // PC-2�û����õ�����Կ
		subkeys[i] = get_48bit_subkey(realkey);
	}
}


// IP���û�
// ������char�������IP�û� 
char* Final_Permutation(char* code) {
	char* FP_result = new char[64];
	for (int i = 0; i < 64; i++) {
		FP_result[i] = code[FP_table[i]];
	}
	return FP_result;
}


char* charTobit(char* text);
char* bitTochar(char* bits);
//����
// 8���ֽ�(64λ)������������ԿתΪ����
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
    //��ʼIP  
	afterIP = Init_Permutation(plain);
     
    //16�ֵ���   
    for(int i = 0; i < 16; i++){   
		// ��벿��
		memcpy(Left, afterIP, 32); 
		// �Ұ벿��       
        memcpy(Right,afterIP+32,32);   
        //�Ұ벿��E��չ�û���32λ->48λ   
		eRight = E_explaned(Right);
        //���Ұ벿��������Կ����������   
		xor_result = XOR(eRight, subkeys[i]);   
        //���������Sbox�����32λ���   
        s_result = S_BoxTrans(xor_result);   
        //P�û��õ��ֺ������ս��
		f_result = P_Transform()
        //������벿�����ֺ�������������  
        Ri = XOR(Left,f_result);
		// Li��Ri����
        if(i < 15){  
            Swap(Right,Ri);   
        }   
		memcpy(afterIP, Right, 32);
		memcpy(afterIP+32, Ri, 32);
    }   
    //���ʼ�û���IP^-1�û���   
    afterFP = Final_Permutation(afterIP);
    ciphertext = bitTochar(afterFP);
}   

//����
// 8���ֽ�(64λ)������������ԿתΪ����
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
    //��ʼIP  
	afterIP = Init_Permutation(cipher);
     
    //16�ֵ���   
    for(int i = 15; i >= 0; i--){   
		// ��벿��
		memcpy(Left, afterIP, 32); 
		// �Ұ벿��       
        memcpy(Right,afterIP+32,32);   
        //�Ұ벿��E��չ�û���32λ->48λ   
		eRight = E_explaned(Right);
        //���Ұ벿��������Կ����������   
		xor_result = XOR(eRight, subkeys[i]);   
        //���������Sbox�����32λ���   
        s_result = S_BoxTrans(xor_result);   
        //P�û��õ��ֺ������ս��
		f_result = P_Transform()
        //������벿�����ֺ�������������  
        Ri = XOR(Left,f_result);
		// Li��Ri����
        if(i < 15){  
            Swap(Right,Ri);   
        }   
		memcpy(afterIP, Right, 32);
		memcpy(afterIP+32, Ri, 32);
    }   
    //���ʼ�û���IP^-1�û���   
    afterFP = Final_Permutation(afterIP);
    plaintext = bitTochar(afterFP);
}   