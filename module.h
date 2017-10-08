#include"baseData.h" 

/*---------��ʼ�û�IP---------*/
// IP�û�
// ������char�������IP�û� 
char* Init_Permutation(char* M);

/*---------����T---------*/
/* -----------------------------------------1. Feistel�ֺ��� */ 
// E-��չ���򣨱���-ѡ���
// ��32λ�Ĵ�R(i-1)��E��չ�����48λ�Ĵ�E(R(i-1))
char* E_explaned(char* R);
// ��48λ�Ĵ�E(R(i-1))��Ki�����ƴ���λ�������
// ki����ԿK����
char* XOR(char* ER, char* ki);
 
// ������6-4 ת�����ƣ�S-��
// S1...S8,ÿ������4��16��
// ���ϲ��õ���32�Ĵ�(48->32) 
char* S_BoxTrans(char* data);


// P�û��õ��ֺ������ս��
char* P_Transform(char* data);

 /* ---------------------------------2. �ֺ���������ԿKi���� */
// PC-1�û���
// �û�ѡ���1��ȥ��У��λ����56λ��Կ
char* get_56bit_Realkey(char* key)��
// PC-2ѹ���û���
// �û�ѡ���2��ȥ��8λУ��λ����48λki
char* get_48bit_subkey(char* newrealkey);

// 48λ�����ҷֱ�����
void Move_Left(char* data, int times)��

// ��64λ��Կ�õ�16��48λ����Կ
void getSubkeys(char* Key, char subkeys[16][48])��

/*---------���û�IP^-1---------*/ 
// IP���û�
// ������char�������IP�û� 
char* Final_Permutation(char* code) 

// 8λchar����ת64bit
char* charTobit(char* text);
// 64bitת8λchar����
char* bitTochar(char* bits);
/* ---------16�ε���T ------------*/
//����
// 8���ֽ�(64λ)������������ԿתΪ����
void Encipher(char* plaintext, char subKeys[16][48], char* ciphertext);

//����
// 8���ֽ�(64λ)������������ԿתΪ����
void Decrypt(char* ciphertext, char subKeys[16][48], char* plaintext);