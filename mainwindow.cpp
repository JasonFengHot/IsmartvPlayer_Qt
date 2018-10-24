#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <iostream>
#include <QMessageBox>
#include <string>
#include <QCryptographicHash>
#include <QFile>
#include <QDir>
#include "qaesencryption.h"
#include <QtDebug>
#include <cipher.h>
#include <QByteArray>




QByteArray getPositionByte(QByteArray byteArray, int start, int end){
    QByteArray newByteArray(end -start,  Qt::Initialization::Uninitialized);
    int k = 0;
    for(int i  = start; i < end; i++){
        newByteArray[k] = byteArray.at(i);
        k++;
    }
    return  newByteArray;
}

void MainWindow::checkLicence(){
    QString currentDirPath = QDir::currentPath() + "/licence";
    QFile licenceFile(currentDirPath);
    if(licenceFile.exists()){
        securityActive();
    }else{
        getLicence();
    }
}

void MainWindow::saveLicenceFile(QByteArray byteArray){
    QString currentDirPath = QDir::currentPath() + "/licence";

    QFile licenceFile(currentDirPath);
    if(licenceFile.open(QIODevice::WriteOnly |QIODevice::Text)){
        QTextStream textStream(&licenceFile);
        textStream.setAutoDetectUnicode(true);
        textStream << byteArray;
        licenceFile.close();
    }else{
        QMessageBox::information(this, "错误", "保存licence文件错误");
    }
}

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    checkLicence();
}

void MainWindow::getLicence(){
    QUrl url("http://sky.tvxio.com/trust/get_licence/");
    QByteArray append;

    QString sn;
    QByteArray snByteArray;
    snByteArray = QCryptographicHash::hash ( mSn.toUtf8(), QCryptographicHash::Md5 );
    sn.append(snByteArray.toHex());

    QString fingerprint;
    QByteArray fingerprintByteArray =  QCryptographicHash::hash ( sn.toUtf8(), QCryptographicHash::Md5 );
    fingerprint.append(fingerprintByteArray);

    append.append("sn=").append(sn);
    append.append("&fingerprint=").append( fingerprint);
    append.append("&manufacture=" ).append( mManufacture);
    append.append("&code=").append( QString("1"));
    QNetworkRequest request= QNetworkRequest(url);

    // request
    request.setRawHeader("Content-Type", "application/x-www-form-urlencoded");
    reply = networkManager.post(request, append);
    connect(reply,SIGNAL(finished()), this, SLOT(onLicenceFinish()));
    connect(reply,SIGNAL(error(QNetworkReply::NetworkError)), this, SLOT(onLicenceError(QNetworkReply::NetworkError)));
}

void MainWindow::onLicenceFinish(){
    std::cout << "onLicenceFinish "<< std::endl;
    saveLicenceFile(reply->readAll());

}

void MainWindow:: onLicenceError(QNetworkReply::NetworkError error){
    std::cout << "onLicenceError: " << error << std::endl;
}

void MainWindow::securityActive(){
    //              @Field("sn") String sn,
    //              @Field("manufacture") String manufacture,
    //              @Field("kind") String kind,
    //              @Field("version") String version,
    //              @Field("sign") String sign,
    //              @Field("fingerprint") String fingerprint,
    //              @Field("api_version") String api_version,
    //              @Field("info") String deviceInfo);

    QUrl url("http://sky.tvxio.com/trust/security/active/");
    QString sn;
    QByteArray snByteArray;
    snByteArray = QCryptographicHash::hash ( mSn.toUtf8(), QCryptographicHash::Md5 );
    sn.append(snByteArray.toHex());

    QString fingerprint;
    QByteArray fingerprintByteArray =  QCryptographicHash::hash ( sn.toUtf8(), QCryptographicHash::Md5 );
    fingerprint.append(fingerprintByteArray);

    QString currentDirPath = QDir::currentPath() + "/licence";

    QFile licenceFile(currentDirPath);

    QString licence;
    if(licenceFile.open(QIODevice::ReadOnly |QIODevice::Text)){
        QTextStream textStream(&licenceFile);
        textStream.setAutoDetectUnicode(true);
        licence = textStream.readAll();
        licenceFile.close();
    }else{
        QMessageBox::information(this, "错误", "读取licence文件错误");
    }

    std::cout << "licence: " << licence.toStdString() << std::endl;
    std::cout << "sn: " << sn.toStdString() << std::endl;

    QByteArray licenceResult =   QByteArray::fromBase64(licence.toUtf8(), QByteArray::Base64UrlEncoding);

    QAESEncryption encryption(QAESEncryption::AES_128, QAESEncryption::CBC, QAESEncryption::ZERO);

    QByteArray reultByteArray = encryption.decode(getPositionByte(licenceResult, 16, licenceResult.size()), getPositionByte(sn.toUtf8(), 0, 16), getPositionByte(licenceResult,0, 16));

    // 去除填充字符
    QByteArray plainTemp = getPositionByte(reultByteArray, reultByteArray.size() - 1, reultByteArray.size());
    QByteArray plainTemp2 = getPositionByte(reultByteArray, 0, reultByteArray.size() - (int) plainTemp[0]);

    QString finalResult = QString (plainTemp2);

    std::cout <<"final result: " << finalResult.toStdString()<< std::endl;


    QByteArray append;

    append.append("sn=").append(sn);
    append.append("&fingerprint=").append( fingerprint);
    append.append("&manufacture=" ).append( mManufacture);
    append.append("&kind=").append("uf30");
    append.append("&version=").append("1");
    append.append("&api_version=").append("v3_0");


    QString sign;
    sign.append  ("ismartv=201415&kind=uf30&sn=").append(sn);



    char publicKey2[]="-----BEGIN RSA PUBLIC KEY-----\n"\
       "MIIBCAKCAQEAppxnlHiDYUtJxwXRiizoZH+xL8BNSsfQiE75qi+1I70LoZawPqCi\n"\
       "JdeejXdzGJrgM4c2lmxsp4xKMbDlXHtoXEe86E1h2R33R+xHxh5ZQaoM5Znj5PvW\n"\
       "jmHjdBdciBMlcTHvk+GKpzrpI18dHK9Clzpp6RQ0rHqpPG5Qvn6X4gpStglj6n2L\n"\
       "tc3lWjDRNTPuS70SRSoBrkMv9YPCMTzJAbXIa7yNS4u8W50Wqt9skCItu/XTKoTC\n"\
       "/PzceqfrjDJk5SWCDOIey8DAclI62DE3kSLg3+0dinDkm//zLt8Wz0ttythaTl6X\n"\
       "YapHPPGulUXukeMtWAQV3TfuJ+LxheYVSwIBOw==\n"\
       "-----END RSA PUBLIC KEY-----";

      QString publicKey(publicKey2);

    //    publicKey.append("-----BEGIN PUBLIC KEY-----");
    //    publicKey.append( finalResult.split("$$$").at(1));
    //    publicKey.append("-----END PUBLIC KEY-----");

    qDebug() << "public key: " << publicKey;

    Cipher cipher;

    QByteArray publicKeyByteArray = publicKey.toUtf8();

    RSA * rsaPublicKey = cipher.getPublicKey(publicKeyByteArray);
//    RSA * rsaPrivateKey = cipher.getPrivateKey("/Users/huibin/private.pem");

    QByteArray signByteArray = sign.toUtf8();

    QByteArray rsaEncryptResult = cipher.encryptRSA(rsaPublicKey, signByteArray);
//    qDebug() << "RSA ENCRYPT RESULT: " << rsaEncryptResult;


    QNetworkRequest request= QNetworkRequest(url);

    // request
    request.setRawHeader("Content-Type", "application/x-www-form-urlencoded");
    securityActiveReply = networkManager.post(request, append);
    connect(securityActiveReply,SIGNAL(finished()), this, SLOT(onsecurityActiveFinish()));
    connect(securityActiveReply,SIGNAL(error(QNetworkReply::NetworkError)), this, SLOT(onsecurityActiveError(QNetworkReply::NetworkError)));

}

void MainWindow::onsecurityActiveFinish(){
    std::cout << "onsecurityActiveFinish "<< std::endl;
    QByteArray securityActiveResponse = securityActiveReply->readAll();
    QString response (securityActiveResponse);
    qDebug() << response;

}


void MainWindow::onsecurityActiveError(QNetworkReply::NetworkError error){
    std::cout << "onsecurityActiveError: " << error << std::endl;
}



MainWindow::~MainWindow()
{
    delete ui;
}
