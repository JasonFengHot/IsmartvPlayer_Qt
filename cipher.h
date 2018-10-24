#ifndef CIPHER_H
#define CIPHER_H

#include <QObject>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <QByteArray>
#include <QFile>


#define PADDING RSA_PKCS1_PADDING

class Cipher : public QObject
{
    Q_OBJECT
public:
    explicit Cipher(QObject *parent = nullptr);
    ~Cipher();

public:
    RSA * getPublicKey(QByteArray &data);
    RSA * getPublicKey(QString fileName);

    RSA * getPrivateKey(QByteArray &data);
    RSA * getPrivateKey(QString fileName);

    QByteArray encryptRSA(RSA * key, QByteArray &data);
    QByteArray decryptRSA(RSA * key, QByteArray &data);

    QByteArray encryptAES(QByteArray passphrase, QByteArray &data);
    QByteArray decryptAES(QByteArray passphrase, QByteArray &data);

    QByteArray randomBytes(int size);

    void freeRSAKey(RSA *key);

    void initialize();
    void finalize();

    QByteArray readFile(QString filename);
    void writeFile(QString filename, QByteArray &data);

    signals:

        public slots:
};

#endif // CIPHER_H
