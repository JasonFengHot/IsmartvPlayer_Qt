#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QNetworkAccessManager>
#include <QNetworkReply>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

private:
    const QString mVersionCode = "1";
    const QString mApiVersion = "v3_0";

    QNetworkAccessManager networkManager;
    QNetworkReply* reply ;

    const QString mSn = "123456";
    const QString mManufacture = "sharp";
    const QString mKind = "uf30";

private:
    void getLicence();
    void securityActive();
    void saveLicenceFile(QByteArray byteArray);
    void checkLicence();

private slots:
    void onLicenceFinish();
    void onLicenceError(QNetworkReply::NetworkError error);

    void onsecurityActiveFinish();
    void onsecurityActiveError(QNetworkReply::NetworkError error);

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private:
    Ui::MainWindow *ui;
};

#endif // MAINWINDOW_H
