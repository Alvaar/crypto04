#include <memory.h>

typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned long ulong;
typedef unsigned long long ulong64_single;

//==========================================================================
// �������� 64-� ������� �����
typedef struct _ulong64
{
	ulong l;
	ulong h;
} ulong64;



//==========================================================================
// ��������� 32-� ������� ����� �� ������ ���� �� ������� (������ BIG ENDIAN)
// BIG ENDIAN - ������ ���� ������ ����� ������� ������ � �����
// ���������:
//   ulong n  - 32-� ������ �����, � ������� ������������ ������
//   uchar* b - ������� ����� ����
//   ulong i  - �������, � ������� ���������� ������ ������ �� �������� ������
#ifndef GET_ULONG_BE
#define GET_ULONG_BE(n,b,i)                     \
{                                               \
    (n) = ( (ulong) (b)[(i)    ] << 24 )        \
        | ( (ulong) (b)[(i) + 1] << 16 )        \
        | ( (ulong) (b)[(i) + 2] <<  8 )        \
        | ( (ulong) (b)[(i) + 3]       );       \
}
#endif

//==========================================================================
// ������ 32-� ������� ����� � ����� ���� � ������ ������� (������ BIG ENDIAN)
// ���������:
//   ulong n  - 32-� ������ �����, �� ������� �������� ������
//   uchar* b - �������� ����� ����
//   ulong i  - �������, � ������� ���������� ������ ������ � �������� �����
#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n,b,i)                     \
{                                               \
    (b)[(i)    ] = (uchar) ( (n) >> 24 );       \
    (b)[(i) + 1] = (uchar) ( (n) >> 16 );       \
    (b)[(i) + 2] = (uchar) ( (n) >>  8 );       \
    (b)[(i) + 3] = (uchar) ( (n)       );       \
}
#endif

//==========================================================================
// ��������� ������
// bool n - ��������� ���
// uchar* b - ������� �����
// ulong i - �������, � ������� ���������� ������ ������ � �������� �����
// ulong o - �������� ���� (��� ����������������� ������)
#ifndef GET_BIT_BE
#define GET_BIT_BE(n,b,i,o)                     \
{                                               \
    (n) = ( (( 0x80 >> o ) & (b)[(i)]) != 0 );  \
}
#endif

//==========================================================================
// ��������� ������
// bool n - ��������� ���
// uchar* b - �������� �����
// ulong i - �������, � ������� ���������� ������ ������ � �������� �����
// ulong o - �������� ���� (��� ����������������� ������)
// ?: - ��������� �������� �������� (if (something) do_something; else do_something2
#ifndef PUT_BIT_BE
#define PUT_BIT_BE(n,b,i,o)                       \
{                                                 \
    (b)[(i)] = (n) ? (( 0x80 >> o ) | (b)[(i)]) : \
    (~( 0x80 >> o ) & (b)[(i)]);                  \
}
#endif


//==========================================================================
// ������� ������������ 16-�� ��������� ������ ���������� DES
// ���������:
//   - src - 64-� ������ ���� ��������� DES
//   - keys - �������������� 16 64-� ������ ������ ������ ����������
void des_create_keys(ulong64 src, ulong64 keys[16]);
// ������� ���������� DES ������ 64-� ������� �����
// ���������:
//   - src - 64-� ������ ������� ���� ��������� ����� 
//   - keys - 16 64-� ������ ������ ������ ����������
// ���������:
//   - 64-� ������ ������� ���� ������������
ulong64 des_encrypt_block(ulong64 src, ulong64 keys[16]);
// ������� ������������� DES ������ 64-� ������� �����
// ���������:
//   - src - 64-� ������ ������� ���� ������������
//   - keys - 16 64-� ������ ������ ������ ����������
// ���������:
//   - 64-� ������ ������� ���� ��������� ����� 
ulong64 des_decrypt_block(ulong64 src, ulong64 keys[16]);

//==========================================================================
// ��������!!!!
// ���������� ���������� ������ ECB, CBC, CFB � OFB. ��������� ������� 
// ������� ����. 
// ���������:
//   - SRC - ������� ��������� (������������)
//   - SRCLEN - ������ �������� ��������� (������������)
//   - DST - ������������ (���������)
//   - IV - ����������������� ������ ��� ������� (CBC, CFB, OFB)

// ECB
ulong des_encrypt_ecb(uchar *src, ulong srclen, uchar *dst, ulong64 key);
ulong des_decrypt_ecb(uchar *src, ulong srclen, uchar *dst, ulong64 key);

// CBC
ulong des_encrypt_cbc(uchar *src, ulong srclen, uchar *dst, ulong64 key, ulong64 iv);
ulong des_decrypt_cbc(uchar *src, ulong srclen, uchar *dst, ulong64 key, ulong64 iv);

// CFB
ulong des_encrypt_cfb(uchar *src, ulong srclen, uchar *dst, ulong64 key, ulong64 iv);
ulong des_decrypt_cfb(uchar *src, ulong srclen, uchar *dst, ulong64 key, ulong64 iv);

// OFB
ulong des_encrypt_ofb(uchar *src, ulong srclen, uchar *dst, ulong64 key, ulong64 iv);
ulong des_decrypt_ofb(uchar *src, ulong srclen, uchar *dst, ulong64 key, ulong64 iv);

// print (beta)
void printchar(uchar ch);

// 
ulong64 convert_to_ulong64(ulong64_single x);

#ifndef GET_ULONG_BE_CUSTOM
#define GET_ULONG_BE_CUSTOM(n,b,i)            \
{                                               \
    (n) = ( (ulong) (b)[(i)    ]  << 31 )        \
        | ( (ulong) (b)[(i) + 1]  << 30 )        \
        | ( (ulong) (b)[(i) + 2]  << 29 )        \
        | ( (ulong) (b)[(i) + 3]  << 28 )        \
        | ( (ulong) (b)[(i) + 4]  << 27 )        \
        | ( (ulong) (b)[(i) + 5]  << 26 )        \
        | ( (ulong) (b)[(i) + 6]  << 25 )        \
        | ( (ulong) (b)[(i) + 7]  << 24 )        \
        | ( (ulong) (b)[(i) + 8]  << 23 )        \
        | ( (ulong) (b)[(i) + 9]  << 22 )        \
        | ( (ulong) (b)[(i) + 10]  << 21 )        \
        | ( (ulong) (b)[(i) + 11]  << 20 )        \
        | ( (ulong) (b)[(i) + 12]  << 19 )        \
        | ( (ulong) (b)[(i) + 13]  << 18 )        \
        | ( (ulong) (b)[(i) + 14]  << 17 )        \
        | ( (ulong) (b)[(i) + 15]  << 16 )        \
        | ( (ulong) (b)[(i) + 16]  << 15 )        \
        | ( (ulong) (b)[(i) + 17]  << 14 )        \
        | ( (ulong) (b)[(i) + 18]  << 13 )        \
        | ( (ulong) (b)[(i) + 19]  << 12 )        \
        | ( (ulong) (b)[(i) + 20] << 11 )        \
        | ( (ulong) (b)[(i) + 21] << 10 )        \
        | ( (ulong) (b)[(i) + 22] <<  9 )        \
        | ( (ulong) (b)[(i) + 23] <<  8 )        \
        | ( (ulong) (b)[(i) + 24] <<  7 )        \
        | ( (ulong) (b)[(i) + 25] <<  6 )        \
        | ( (ulong) (b)[(i) + 26] <<  5 )        \
        | ( (ulong) (b)[(i) + 27] <<  4 )        \
        | ( (ulong) (b)[(i) + 28] <<  3 )        \
        | ( (ulong) (b)[(i) + 29] <<  2 )        \
        | ( (ulong) (b)[(i) + 30] <<  1 )        \
        | ( (ulong) (b)[(i) + 31]        );       \
}
#endif

#ifndef PUT_ULONG_BE_CUSTOM
#define PUT_ULONG_BE_CUSTOM(n,b,i,t)            \
{                                               \
    (b)[(i)    ]  = (uchar) ( (n) >> 31 );       \
    (b)[(i) + 1]  = (uchar) ( (n) >> 30 );       \
    (b)[(i) + 2]  = (uchar) ( (n) >> 29 );       \
    (b)[(i) + 3]  = (uchar) ( (n) >> 28 );       \
    (b)[(i) + 4]  = (uchar) ( (n) >> 27 );       \
    (b)[(i) + 5]  = (uchar) ( (n) >> 26 );       \
    (b)[(i) + 6]  = (uchar) ( (n) >> 25 );       \
    (b)[(i) + 7]  = (uchar) ( (n) >> 24 );       \
    (b)[(i) + 8]  = (uchar) ( (n) >> 23 );       \
    (b)[(i) + 9]  = (uchar) ( (n) >> 22 );       \
    (b)[(i) + 10] = (uchar) ( (n) >> 21 );       \
    (b)[(i) + 11] = (uchar) ( (n) >> 20 );       \
    (b)[(i) + 12] = (uchar) ( (n) >> 19 );       \
    (b)[(i) + 13] = (uchar) ( (n) >> 18 );       \
    (b)[(i) + 14] = (uchar) ( (n) >> 17 );       \
    (b)[(i) + 15] = (uchar) ( (n) >> 16 );       \
    (b)[(i) + 16] = (uchar) ( (n) >> 15 );       \
    (b)[(i) + 17] = (uchar) ( (n) >> 14 );       \
    (b)[(i) + 18] = (uchar) ( (n) >> 13 );       \
    (b)[(i) + 19] = (uchar) ( (n) >> 12 );       \
    (b)[(i) + 20] = (uchar) ( (n) >> 11 );       \
    (b)[(i) + 21] = (uchar) ( (n) >> 10 );       \
    (b)[(i) + 22] = (uchar) ( (n) >>  9 );       \
    (b)[(i) + 23] = (uchar) ( (n) >>  8 );       \
    (b)[(i) + 24] = (uchar) ( (n) >>  7 );       \
    (b)[(i) + 25] = (uchar) ( (n) >>  6 );       \
    (b)[(i) + 26] = (uchar) ( (n) >>  5 );       \
    (b)[(i) + 27] = (uchar) ( (n) >>  4 );       \
    (b)[(i) + 28] = (uchar) ( (n) >>  3 );       \
    (b)[(i) + 29] = (uchar) ( (n) >>  2 );       \
    (b)[(i) + 30] = (uchar) ( (n) >>  1 );       \
    (b)[(i) + 31] = (uchar) ( (n)       );       \
}
#endif