#ifndef MAINWINDOW_H
#define MAINWINDOW_H
#include <QPlainTextEdit>
#include <QMainWindow>
#include <QApplication>
#include <QTextEdit>
#include <QTimer>
#include <QDebug>
#include <Iphlpapi.h>
#include <WinSock2.h>
#include <pcap.h>

#include <QApplication>
#include <QWidget>
#include <QVBoxLayout>
#include <QTextEdit>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);

    ~MainWindow();

signals:
    void packetCaptured(QString);


private slots:
    void on_start_clicked();
    void upDate();
    void on_stop_clicked();


public slots:
    void init();
    void onPacketCaptured(const QString& packetDetails);
private:
    Ui::MainWindow *ui;

    pcap_if_t* allDevs;
    bool check=false;
    char errBuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcapHandle;
    pcap_if_t* device;
    unsigned char *userData1;
    struct pcap_pkthdr header;
    const u_char *packet;
    QTimer * timer;
    QList<QString> deviceList;


};
#endif // MAINWINDOW_H
