#include "cipher.h"
#include <QtDebug>
#include <iostream>

Cipher::Cipher(QObject *parent) : QObject(parent)
{
    initialize();
}


RSA * Cipher::getPublicKey(QByteArray data){


    int size =data.size();

    char key[size + 1];

    for(int i = 0; i< data.size(); i++){
        key[i] = data.at(i);
    }
    key[size] = '\0';

    std::cout << "public key from file: " << key << std::endl;
    BIO * bio = BIO_new_mem_buf( key, (int) sizeof(key) );
    if (!bio) {
        std::cout << "Could not load public key" << ERR_error_string(ERR_get_error(), NULL) << std::endl;
    }

    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);

    if (!pkey) {
        std::cout << "Could not load public key" << ERR_error_string(ERR_get_error(), NULL) << std::endl;
    }

    //    int type = EVP_PKEY_get_type

    RSA* rsaPubKey = EVP_PKEY_get1_RSA(pkey);
    if (!rsaPubKey) {
        std::cout << "Could not load public key" << ERR_error_string(ERR_get_error(), NULL) << std::endl;
    }

    //    const char * publicKeyStr = data.constData();
    //    BIO * bio = BIO_new_mem_buf((void*) publicKeyStr, (int)sizeof(publicKeyStr));

    ////    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    //    EVP_PKEY  *evpKey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    //    if(!evpKey){
    //        qCritical() << "Could not PEM_read_bio_PUBKEY" << ERR_error_string(ERR_get_error(), NULL);
    //    }

    //    RSA * rsaPubKey = EVP_PKEY_get1_RSA(evpKey);
    //    if(!rsaPubKey){
    //        qCritical() << "Could not load public key" << ERR_error_string(ERR_get_error(), NULL);
    //    }
    BIO_free(bio);
    return rsaPubKey;
}


RSA * Cipher::getPublicKey(QString fileName){
    QByteArray data = readFile(fileName);
    qDebug() << "get public key from file: " << data;
    return getPublicKey(data);
}

RSA * Cipher::getPrivateKey(QByteArray &data){

    const char * privateKeyStr = data.constData();
    BIO * bio = BIO_new_mem_buf((void*) privateKeyStr, -1);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    RSA * rsaPrivateKey = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    if(!rsaPrivateKey){
        qCritical() << "Could not load private key" << ERR_error_string(ERR_get_error(), NULL);
    }
    BIO_free(bio);
    return rsaPrivateKey;
}
RSA * Cipher::getPrivateKey(QString fileName){
    QByteArray data = readFile(fileName);
    qDebug() << "get private key from file: " << data;
    return getPrivateKey(data);
}

QByteArray Cipher::encryptRSA(RSA * key, QByteArray &data){
    QByteArray buffer;
    int dataSize = data.length();
    const unsigned char * str = (const unsigned char*)data.constData();

    int rsaLen = RSA_size(key);
    unsigned char* ed = (unsigned char *) malloc(rsaLen);

    int resultLen = RSA_public_encrypt(dataSize, (const unsigned char*)str, ed, key, RSA_X931_PADDING);

    if(resultLen == -1){
        qCritical() << "Could not encrypt: " << ERR_error_string(ERR_get_error(), NULL);

        return  buffer;
    }

    buffer = QByteArray(reinterpret_cast<char*>(ed), resultLen);
    return  buffer;

}
QByteArray Cipher::decryptRSA(RSA * key, QByteArray &data){

}

QByteArray Cipher::encryptAES(QByteArray passphrase, QByteArray &data){

}
QByteArray Cipher::decryptAES(QByteArray passphrase, QByteArray &data){

}

QByteArray Cipher::randomBytes(int size){

}

void Cipher::freeRSAKey(RSA *key){

}

void Cipher::initialize(){
    ERR_load_CRYPTO_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

}
void Cipher::finalize(){
    EVP_cleanup();
    ERR_free_strings();

}

QByteArray Cipher::readFile(QString filename){
    QByteArray data;
    QFile file(filename);
    if(!file.open(QFile::ReadOnly)){
        qCritical() << file.errorString();
        return  data;
    }
    data = file.readAll();
    file.close();
    return data;
}

void Cipher::writeFile(QString filename, QByteArray &data){

}

Cipher:: ~Cipher(){
    finalize();
}
