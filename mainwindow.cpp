#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QDebug>
#include <Iphlpapi.h>
#include <WinSock2.h>
#include <pcap.h>

#include <QApplication>
#include <QWidget>
#include <QVBoxLayout>
#include <QTextEdit>
#include<QTime>

#include<QFontComboBox>



#define MAX_PACKET_SIZE 1514


MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    timer=new QTimer(this);

    // 连接按钮的 clicked 信号与 on_start_clicked 槽函数
    connect(ui->start, SIGNAL(clicked()), this, SLOT(on_start_clicked()));

    connect(ui->stop, SIGNAL(clicked()), this, SLOT(on_stop_clicked()));

    connect(timer, SIGNAL(timeout()), this, SLOT(upDate()));



}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::onPacketCaptured(const QString& packetDetails)
{
    ui->packetDate->append(packetDetails);
     ui->packetDate->append("----------------------------------------");
     ui->packetDate->setAcceptRichText(true);
}


void MainWindow::on_start_clicked()
{
    check=true;
    qDebug()<<check;
    timer->start(1500);
    int index=ui->comboBox->currentIndex();
    for(int i=0;i<index;i++){
        device =device->next;
    }
    qDebug()<<index;




//    upDate();
}
void MainWindow::upDate(){

    packet = pcap_next(pcapHandle, &header); // Capture a packet




        if (packet) {
            qDebug()<<device->description;
            QString packetDetails = "A packet is captured with length of " + QString::number(header.len);

            const u_char *ih = packet + 14; // Skip ethernet header

            // Convert to IP addresses
            struct sockaddr_in source, dest;
            memcpy(&source.sin_addr, ih + 12, sizeof(struct in_addr));
            memcpy(&dest.sin_addr, ih + 16, sizeof(struct in_addr));

            // Print packet info
            packetDetails += "<br><font color='red'>From: " + QString(inet_ntoa(source.sin_addr))+ "</font>"
                                         + "<br><font color='green'>To: " + QString(inet_ntoa(dest.sin_addr)) + "</font><br>";


            // Extract packet data
              const u_char *pkt_data = ih + (ih[0]&0x0F)*4;  // Extract header length from ih[0]
            for (unsigned int i=0; i < header.len; ++i) {
                packetDetails += QString("%1").arg(static_cast<unsigned int>(pkt_data[i]), 2, 16, QChar('0')).toUpper()+" ";
                // New line every 8 bytes
                               if ((i+1) % 8 == 0) {
                                   packetDetails += "\n";
                               }
            }
//            emit packetCaptured(packetDetails); // Emit the signal with packet data
            qDebug()<<packetDetails;
             emit packetCaptured(packetDetails);
            onPacketCaptured(packetDetails);
        }

//          // Remember to close the pcap handle.
    }





void MainWindow::init(){
    if (pcap_findalldevs(&allDevs, errBuf) == -1) {
        qDebug() << "Failed to retrieve network device list:" << errBuf;
        return ;
    }
    pcap_if_t* it = allDevs;
    device=allDevs;
    while (it != nullptr) {

        QString deviceInfo =
                                        "Device name: " + QString(it->description)+"   Device id: " + QString(it->name)  ;
        qDebug()<<deviceInfo;

        deviceList.append(deviceInfo);

        it=it->next;
      }
    ui->comboBox->addItems(deviceList);
    pcapHandle = pcap_open_live(device->name, MAX_PACKET_SIZE, 1, 1000, errBuf);

}



int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow window;

    window.show();
    window.init();


    return a.exec();
}





void MainWindow::on_stop_clicked()
{
 pcap_close(pcapHandle);  // Remember to close the pcap handle.
 timer->stop();
}
