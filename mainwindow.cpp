#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <iostream>
#include <QMessageBox>
#include <string>
#include <QCryptographicHash>
#include <QFile>
#include <QDir>
#include "qaesencryption.h"




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


    QAESEncryption encryption(QAESEncryption::AES_128, QAESEncryption::CBC);
    QByteArray reultByteArray = encryption.decode(licence.toUtf8(), getPositionByte(sn.toUtf8(), 0, 16), getPositionByte(licence.toUtf8(),0, 16));

    // 去除填充字符
    QByteArray plainTemp = getPositionByte(reultByteArray, reultByteArray.size() - 1, reultByteArray.size());
    QByteArray plainTemp2 = getPositionByte(reultByteArray, 0, reultByteArray.size() - (int)0xc3);

    QString finalResult (plainTemp2);

    std::cout <<"final result: " << finalResult.toStdString()<< std::endl;
    //        QCOMPARE(encryption.decode(outCBC128, key16, iv), inCBC128);

}

void MainWindow::onsecurityActiveFinish(){

}


void MainWindow::onsecurityActiveError(QNetworkReply::NetworkError error){

}



MainWindow::~MainWindow()
{
    delete ui;
}
