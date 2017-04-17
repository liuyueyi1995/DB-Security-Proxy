#include <iostream>
#include <string>
#include <string.h>
#include <fstream>
#include <vector>
#include <sstream>
#include <chrono>
#include "seal.h"
#include "uuid.h"

using namespace std;
using namespace seal;

/**
 * 同态加密的密钥生成环节
 * 输入加密参数
 * 生成的密钥结果写入文件中
 * 主模块调用./seal gen得到密钥文件
 * 该函数仅能调用一次，否则密钥会被覆盖！
 */
void HOM_GEN_KEY(EncryptionParameters parms) {
    KeyGenerator generator(parms);
    generator.generate();
    BigPolyArray public_key = generator.public_key();
    BigPoly secret_key = generator.secret_key();

    fstream pubk_save;
    fstream seck_save;
    pubk_save.open("pubk",ios::binary|ios::out);
    seck_save.open("seck",ios::binary|ios::out);
    public_key.save(pubk_save);
    secret_key.save(seck_save);
}

/**
 * 同态加密的加密环节
 * 输入整数明文和加密参数
 * 加密结果写入文件中
 * 打印结果的文件名作为返回
 * 主模块调用./seal enc value之后得到返回的文件名，将其打开读出内容即可
 */
void HOM_ENC_INT(int value, EncryptionParameters parms) {
    // 将数字编码成多项式
    IntegerEncoder encoder(parms.plain_modulus());
    BigPoly encoded = encoder.encode(value);

    // 读取公钥文件
    fstream pubk_load;
    pubk_load.open("pubk",ios::binary|ios::in);
    BigPolyArray public_key;
    public_key.load(pubk_load);

    // 完成加密
    Encryptor encryptor(parms, public_key);
    BigPolyArray encrypted = encryptor.encrypt(encoded);
   
    // 将加密结果序列化写进文件
    char filename[37];
    random_uuid(filename);
    fstream outfile;
    outfile.open(filename,ios::binary|ios::out);
    encrypted.save(outfile);
    cout << filename;
}

/**
 * 同态加密的运算环节
 * 输入要运算的密文和加密参数
 * 运算结果写入文件中
 * 打印结果的文件名作为返回
 * 主模块调用./seal add file1 file2之后得到返回的文件名，将其打开读出内容即可
 */
void HOM_ADD(vector<string> files, EncryptionParameters parms){  
    int i;    
    int size = files.size();
    vector<BigPolyArray> encrypteds;

    for(i=0;i<size;i++){
      BigPolyArray encrypted;
      fstream infile;
      infile.open(files[i],ios::binary|ios::in);
      encrypted.load(infile);
      encrypteds.push_back(encrypted);
    }
    Evaluator evaluator(parms);
    BigPolyArray encryptedsum = evaluator.add_many(encrypteds);

    // 将计算结果序列化写进文件
    char filename[37];
    random_uuid(filename);
    fstream outfile;
    outfile.open(filename,ios::binary|ios::out);
    encryptedsum.save(outfile);
    cout << filename;
}

/**
 * 同态加密的解密环节
 * 输入要解密的密文所在的文件名和加密参数
 * 打印解密结作为返回
 * 主模块调用./seal dec filename之后得到返回的结果
 */
void HOM_DEC_INT(char* filename, EncryptionParameters parms) {
    IntegerEncoder encoder(parms.plain_modulus());
    // 读取待解密的数
    fstream if1;
    if1.open(filename,ios::binary|ios::in);
    BigPolyArray encrypted;
    encrypted.load(if1);
    // 读取私钥
    fstream seck_load;
    seck_load.open("seck",ios::binary|ios::in);
    BigPoly secret_key;
    secret_key.load(seck_load);

    Decryptor decryptor(parms, secret_key);
    BigPoly decrypted = decryptor.decrypt(encrypted);
    int decoded = encoder.decode_int32(decrypted);
    cout <<decoded;
}

int main(int argc, char**argv)
{
    if (argc < 2) { //输入参数的判断及用法提示
      cout << "usage1: ./seal enc intValue" << endl;
      cout << "usage2: ./seal dec filename" << endl;
      cout << "usage3: ./seal add filename1 filename2 [filename3 ...]" << endl;
      exit(1);
    }
    char* type = argv[1];  
    // Create encryption parameters.
    EncryptionParameters parms;
    parms.poly_modulus() = "1x^2048 + 1";
    parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(2048);
    parms.plain_modulus() = 1 << 8;
  
    if(strcmp(type,"gen")==0) {
        HOM_GEN_KEY(parms);

    } else if(strcmp(type,"enc")==0) {
        int value = atoi(argv[2]);
        HOM_ENC_INT(value, parms);

    } else if(strcmp(type,"dec")==0) {
        char *filename = argv[2]; 
        HOM_DEC_INT(filename,parms);

    } else if(strcmp(type,"add")==0) {
        int file_account = argc - 2;
        int i;
        vector<string> files;
        for(i=2;i<argc;i++) {
          files.push_back(argv[i]);
        }
        HOM_ADD(files,parms);
    } else {
        cout<< "ERROR";
    }

    return 0;
}

