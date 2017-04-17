#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/aes.h>

void my_AES_cbc_encrypt(unsigned char *in, unsigned char *out, size_t len, const AES_KEY *key, unsigned char *ivec) {
  size_t n;
  const unsigned char *iv = ivec;

  if (len == 0)
    return;

  while (len) {
    for (n = 0; n < 16 && n < len; ++n) {
      out[n] = in[n] ^ iv[n];
    }
    for (; n < 16; ++n) {
      out[n] = iv[n];
    }
    AES_encrypt(out, out, key);
    iv = out;
    if (len <= 16) break;
    len -= 16;
    in += 16;
    out += 16;
  }
}

void my_AES_cbc_decrypt(unsigned char *in, unsigned char *out, size_t len, const AES_KEY *key, unsigned char *ivec) {
  size_t n;
  unsigned char iv[AES_BLOCK_SIZE+1];
  strcpy(iv,ivec);
  union {
    size_t t[16 / sizeof(size_t)];
    unsigned char c[16];
  } tmp;

  if (len == 0) return;

  while (len) {
    unsigned char c;
    AES_decrypt(in, tmp.c, key); 
    for (n = 0; n < 16 && n < len; ++n) {
      c = in[n];
      out[n] = tmp.c[n] ^ iv[n];
      iv[n] = c;
    }
    if (len <= 16) {
      for (; n < 16; ++n) {
        iv[n] = in[n];
        break;
      }
    }
    len -= 16;
    in += 16;
    out += 16;
  }
}

unsigned char* DET_ENC(unsigned char *data, unsigned char* rootkey) {
  int len = 0; //计数变量
  int length = ((strlen(data)+AES_BLOCK_SIZE-1)/AES_BLOCK_SIZE)*AES_BLOCK_SIZE; //对齐分组   
  unsigned char *encrypt_result = malloc(length+1); 
  AES_KEY key;
  memset((void*)encrypt_result, 0, length+1);
  AES_set_encrypt_key(rootkey, AES_BLOCK_SIZE*8, &key); //生成加密密钥

  while(len < length) { //分组加密
    AES_encrypt(data+len, encrypt_result+len, &key);    
    printf("%s\n",encrypt_result);
    len += AES_BLOCK_SIZE;
  }
  
  return encrypt_result;
}

unsigned char* DET_DEC(unsigned char *data, unsigned char* rootkey) {
  int len = 0; //计数变量
  int length = ((strlen(data)+AES_BLOCK_SIZE-1)/AES_BLOCK_SIZE)*AES_BLOCK_SIZE; //对齐分组
  unsigned char *decrypt_result = malloc(length); 
  AES_KEY key;

  memset((void*)decrypt_result, 0, length);
  AES_set_decrypt_key(rootkey, AES_BLOCK_SIZE*8, &key); //生成解密密钥

  while(len < length) { //分组解密
    AES_decrypt(data+len, decrypt_result+len, &key);    
    len += AES_BLOCK_SIZE;
  }

  return decrypt_result;
}

unsigned char* RND_ENC(unsigned char *data, unsigned char* rootkey, unsigned char* iv) {
  size_t len = strlen(data); //实际长度
  size_t length = ((strlen(data)+AES_BLOCK_SIZE-1)/AES_BLOCK_SIZE)*AES_BLOCK_SIZE; //对齐分组
  unsigned char *encrypt_result = malloc(length+1); 
  AES_KEY key;

  memset((void*)encrypt_result, 0, length+1);
  AES_set_encrypt_key(rootkey, AES_BLOCK_SIZE*8, &key); //生成加密密钥
  my_AES_cbc_encrypt(data, encrypt_result, len, &key, iv);  //分组加密

  return encrypt_result;
}

unsigned char* RND_DEC(unsigned char *data, unsigned char* rootkey, unsigned char* iv) {
  size_t len = strlen(data); //实际长度
  size_t length = ((strlen(data)+AES_BLOCK_SIZE-1)/AES_BLOCK_SIZE)*AES_BLOCK_SIZE; //对齐分组
  unsigned char *decrypt_result = malloc(length+1); 
  AES_KEY key;

  memset((void*)decrypt_result, 0, length+1);
  AES_set_decrypt_key(rootkey, AES_BLOCK_SIZE*8, &key); //生成解密密钥
  my_AES_cbc_decrypt(data, decrypt_result, len, &key, iv); //分组解密

  return decrypt_result;
}


