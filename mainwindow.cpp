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
    fingerprint.append(fingerprintByteArray.toHex());

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





    QString sign;
    sign.append  ("ismartv=201415&kind=uf30&sn=").append(sn);



//    static const char key[] = "-----BEGIN PUBLIC KEY-----\n"\
//                              "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDsvk1NWilZ11sJEx0M5dmh9VR0\n"\
//                              "7M0Zzrwqop17KqtRWOp4OXEyc/Hg6DkoPTD4TPyL2WFkArot9TWpqHINXQwmylRa\n"\
//                              "hNamwlSmnx9nxCYO6+arCnsWD6AVkeXgq+HFZjI+0nZwKjIy3Y21mFiyHKdo5Esa\n"\
//                              "O/Zq6o3yCF4G14VQiQIDAQAB\n"\
//                              "-----END PUBLIC KEY-----\n";

    QString publicKey;

            publicKey.append("-----BEGIN PUBLIC KEY-----");
            publicKey.append( finalResult.split("$$$").at(1));
            publicKey.append("-----END PUBLIC KEY-----");


    Cipher cipher;

    QByteArray publicKeyByteArray = publicKey.toUtf8();

    RSA * rsaPublicKey = cipher.getPublicKey(publicKeyByteArray);
    //    RSA * rsaPrivateKey = cipher.getPrivateKey("/Users/huibin/private.pem");

    QByteArray signByteArray = QCryptographicHash::hash ( sign.toUtf8(), QCryptographicHash::Md5 );

    QByteArray rsaEncryptResult = cipher.encryptRSA(rsaPublicKey, signByteArray);
    QString rsaEncryptResultString = rsaEncryptResult.toBase64();
    qDebug() << "RSA ENCRYPT RESULT: " << rsaEncryptResultString;


    QByteArray append;

    append.append("sn=").append(sn);
    append.append("&fingerprint=").append( fingerprint);
    append.append("&manufacture=" ).append( mManufacture);
    append.append("&kind=").append("uf30");
    append.append("&version=").append("1");
    append.append("&api_version=").append("v3_0");
    //    append.append("&sign=").append(rsaEncryptResultString);
    append.append("&sign=").append(rsaEncryptResultString);

    QString info  = "{\"fingerprintE\":\"ecacf77e6480b76e8e3c4f2869fe779a\",\"fingerprintD\":\"HUAWEIBKL-AL20\\/\\/TUKDU18108010250\",\"versionName\":\"1.0\",\"serial\":\"TUKDU18108010250\",\"deviceId\":\"868341030203250\"}///null";
    append.append("&info=").append(info);

    qDebug() << "request body: " << append;

    QNetworkRequest request= QNetworkRequest(url);

    // request
    request.setRawHeader("Content-Type", "application/x-www-form-urlencoded");
    securityActiveReply = networkManager.post(request, append);
    connect(securityActiveReply,SIGNAL(finished()), this, SLOT(onsecurityActiveFinish()));
    connect(securityActiveReply,SIGNAL(error(QNetworkReply::NetworkError)), this, SLOT(onsecurityActiveError(QNetworkReply::NetworkError)));

}

void MainWindow::onsecurityActiveFinish(){
    QByteArray securityActiveResponse = securityActiveReply->readAll();
    QString response (securityActiveResponse);
    qDebug() <<"onsecurityActiveFinish"<< response;
    qDebug() << securityActiveReply->rawHeaderPairs();


    QVariant statusCode = securityActiveReply->attribute(QNetworkRequest::HttpStatusCodeAttribute);
    int status = statusCode.toInt();
    qDebug() << "response code: " << status;

    //    if ( status != 200 )
    //    {
    //        QString reason = securityActiveReply->attribute( QNetworkRequest::HttpReasonPhraseAttribute ).toString();
    //        qDebug() << reason;
    //    }

}


void MainWindow::onsecurityActiveError(QNetworkReply::NetworkError error){
    std::cout << "onsecurityActiveError: " << error << std::endl;
}



MainWindow::~MainWindow()
{
    delete ui;
}
