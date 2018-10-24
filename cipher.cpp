#include "cipher.h"
#include <QtDebug>

Cipher::Cipher(QObject *parent) : QObject(parent)
{
    initialize();
}


RSA * Cipher::getPublicKey(QByteArray &data){
    const char * publicKeyStr = data.constData();
    BIO * bio = BIO_new_mem_buf((void*) publicKeyStr, -1);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    RSA  *rsaPubKey = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
    if(!rsaPubKey){
        qCritical() << "Could not load public key" << ERR_error_string(ERR_get_error(), NULL);
    }
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

    int resultLen = RSA_public_encrypt(dataSize, (const unsigned char*)str, ed, key, PADDING);

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
