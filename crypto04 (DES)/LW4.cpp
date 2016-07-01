#include "des.h"
#include <iostream>
#include <string>
#include <random>
#include <bitset>
#include <cstdlib>
#include <ctime>

#define MAX_LENGTH 256

using namespace std;

// ��������� �����
ulong64 keygen_mt19937()
{
	ulong64 key;
	random_device rd;
	mt19937 gen(rd());
	key.l = gen();
	key.h = gen();
	return key;
}
ulong64 keygen_rand()
{
	ulong64 key;
	ulong64_single k = 0;
	
	for (int i = 0; i < 8; i++)
	{
		k <<= 8;
		k += rand() % 256;
	}
	key = convert_to_ulong64(k);
	return key;
}
ulong64 keygen()
{
	ulong64 key;
	int A = 9, C = 49, B = 4294967296;
	key.h = time(NULL);
	//key.h = 42949672;
	key.l = A * key.h + C;
	return key;
}

/*
// ���� ������ ��������� ���� ������������ ����, ��� ������� des_encrypt_block,
// des_decrypt_block � des_create_keys ��������. ��� �� ��������� ����������,
// ������ ����� �������, ��������� ����� ����������, ���� ��������� ������ �
// ����� ���� ���...
// ������� ������������ ������� GET_ULONG_BE � PUT_ULONG_BE ��� ������������ 
// 64-� ������ ������ �� ������������������ ���� ������ � ��������
*/
int main(int argc, char* argv[])
{
	// ������������� ���� DES ���������
	ulong64 des_key = {0x19456DA2, 0xAD12DA34};

	srand(time(NULL));
	/*des_key = keygen();
	des_key = keygen();
	des_key = keygen();
	des_key = keygen();
	des_key = keygen();*/

	//string ldfks = "";
	//getline(cin, ldfks);

	/*
	// ������� 16 ������ ������ ���������� DES
	ulong64 keys[16];
	des_create_keys(des_key, keys);

	// ���� ��������� �����
	ulong64 message = {0x12657841, 0xADBCCBDA};
	// �������������
	ulong64 cryptogram;
	// ��������� ������������
	ulong64 result;

	// ���������� ������ 64-������� �����
	cryptogram = des_encrypt_block(message, keys);
	//������������� ������ 64-������� �����
	result = des_decrypt_block(cryptogram, keys);

	// if t<32
	int t = 13;
	ulong64 b1 = { 0x6789ABCD, 0x00012345 };
	bitset<32> bitset_h_1{ b1.h };
	bitset<32> bitset_l_1{ b1.l };
	cout << bitset_h_1 << ' ' << bitset_l_1 << endl;

	ulong tmp_h = b1.h;
	ulong tmp_l = b1.l;
	b1.l <<= t;
	b1.h <<= t;
	tmp_l >>= 64 - t;
	b1.h ^= tmp_l;

	bitset<32> bitset_h_2{ b1.h };
	bitset<32> bitset_l_2{ b1.l };
	cout << bitset_h_2 << ' ' << bitset_l_2 << endl;*/


	string msg_in;
	ulong msglen;
	uchar *msg = new uchar[MAX_LENGTH];
	uchar *msg_enc = new uchar[MAX_LENGTH];
	uchar *msg_dec = new uchar[MAX_LENGTH];
	int i = 0;
	//int t = 64;	// ������ �����

	// ��� ������ ���� ��������� ���������� �����
	ulong64 blk = keygen(); // ��� cbc
	des_key = keygen();		// ����� ����

	int op;
	bool exit = false;
	while (!exit)
	{
		cout << "Welcome to DES cipher! Choose the mode you want to use:" << endl;
		cout << "1. ECB (electronic codebook)" << endl;
		cout << "2. CBC (cipher block chaining)" << endl;
		cout << "3. CFB (cipher feedback)" << endl;
		cout << "4. OFB (output feedback)" << endl;
		cout << "...: "; cin >> op;
		switch (op)
		{
		case 1:	// ECB
			msg_in = "00000000111111112222222233333333444444445555555566666666777777778888888899999999";
			cout << "type something: " << msg_in;
			//cin.ignore(256, '\n'); getline(cin, msg_in);
			cout << endl;

			msglen = (msg_in.length() / 8 + 1) * 8;		// ����� ���������
			msg = (uchar*)msg_in.c_str();				// ���������
			msg_enc = new uchar[msglen];				// ������������ ���������

			des_encrypt_ecb(msg, msglen, msg_enc, des_key);	// �����������
			cout << "    encrypting: " << msg_enc << endl;

			//msglen = strlen((char*)msg_enc);			// ����� ������������� ���������
			msg_dec = new uchar[msglen];				// �������������� ���������
			des_decrypt_ecb(msg_enc, msglen, msg_dec, des_key);	// �������������
			cout << "    decrypting: " << msg_dec << endl;

			system("pause");
			system("CLS");
			break;
		case 2:	// CBC
			msg_in = "00000000111111112222222233333333444444445555555566666666777777778888888899999999";
			cout << "type something: " << msg_in;
			//cin.ignore(256, '\n'); getline(cin, msg_in);
			cout << endl;

			msglen = (msg_in.length() / 8 + 1) * 8;		// ����� ���������
			msg = (uchar*)msg_in.c_str();				// ���������
			msg_enc = new uchar[msglen];				// ������������ ���������
			//blk = { 0x76543210, 0xFEDCBA98 };			// ��������������� ��������� ����

			des_encrypt_cbc(msg, msglen, msg_enc, des_key, blk);	// �����������
			cout << "    encrypting: " << msg_enc << endl;
			/*for (msg_enc[i] = 0x00; msg_enc[i] <= 0xff; i++) {
				printchar((unsigned char)msg_enc[i]);
			}*/
			//msglen = strlen((char*)msg_enc);			// ����� ������������� ���������
			msg_dec = new uchar[msglen];				// �������������� ���������
			des_decrypt_cbc(msg_enc, msglen, msg_dec, des_key, blk);	// �������������
			cout << "    decrypting: " << msg_dec << endl;
			i = 0;
			/*for (msg_dec[i] = 0x00; msg_dec[i] <= 0xff; i++) {
				printchar((unsigned char)msg_dec[i]);
			}*/
			system("pause");
			system("CLS");
			break;
		case 3:	// CFB
			msg_in = "00000000111111112222222233333333444444445555555566666666777777778888888899999999";
			cout << "type something: " << msg_in;
			//cin.ignore(256, '\n'); getline(cin, msg_in);
			cout << endl;

			/*msglen = (msg_in.length() / 8 + 1) * 8;		// ����� ���������
			msg = (uchar*)msg_in.c_str();				// ���������
			msg_enc = new uchar[msglen];				// ������������ ���������
			//blk = { 0x76543210, 0xFEDCBA98 };			// ��������������� ��������� ����*/
			
			msglen = msg_in.length() + 1;				// ����� ���������
			msg = (uchar*)msg_in.c_str();				// ���������
			msg_enc = new uchar[msglen];				// ������������ ���������

			des_encrypt_cfb(msg, msglen, msg_enc, des_key, blk);	// �����������

			cout << "    encrypting: " << msg_enc << endl;
			//msglen = strlen((char*)msg_enc) + 1;		// ����� ������������� ���������
			msg_dec = new uchar[msglen];				// �������������� ���������
			des_decrypt_cfb(msg_enc, msglen, msg_dec, des_key, blk);	// �������������
			cout << "    decrypting: " << msg_dec << endl;
			i = 0;
			system("pause");
			system("CLS");
			break;
		case 4:	// OFB
			msg_in = "00000000111111112222222233333333444444445555555566666666777777778888888899999999";
			cout << "type something: " << msg_in;
			//cin.ignore(256, '\n'); getline(cin, msg_in);
			cout << endl;

			/*msglen = (msg_in.length() / 8 + 1) * 8;		// ����� ���������
			msg = (uchar*)msg_in.c_str();				// ���������
			msg_enc = new uchar[msglen];				// ������������ ���������
			//blk = { 0x76543210, 0xFEDCBA98 };			// ��������������� ��������� ����*/

			msglen = msg_in.length() + 1;				// ����� ���������
			msg = (uchar*)msg_in.c_str();				// ���������
			msg_enc = new uchar[msglen];				// ������������ ���������

			des_encrypt_ofb(msg, msglen, msg_enc, des_key, blk);	// �����������

			cout << "    encrypting: " << msg_enc << endl;
			//msglen = strlen((char*)msg_enc) + 1;		// ����� ������������� ���������
			msg_dec = new uchar[msglen];				// �������������� ���������
			des_decrypt_ofb(msg_enc, msglen, msg_dec, des_key, blk);	// �������������
			cout << "    decrypting: " << msg_dec << endl;
			i = 0;
			system("pause");
			system("CLS");
			break;
		case 0:
			exit = true;
			break;
		default:
			break;
		}
	}
	
	delete []msg;
	delete []msg_enc;
	delete []msg_dec;
	
	/*
	// �������� ����������
	if ((result.h == message.h) && (result.l == message.l))
		cout << "Success" << endl;
	else
		cout << "Fault" << endl;*/

	cout << "Exiting..." << endl;
	system("pause");
	return 0;
}