#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "supervisor.h"
#include "defines.h"
#include "functions.h"
#include <QAction>
#include <QMenuBar>
#include <QToolBar>
#include <QStatusBar>
#include <QRegExp>
#include <QRegExpValidator>
#include <QMessageBox>
#include <QLabel>
#include <QMovie>
#include <QSpacerItem>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),ui(new Ui::MainWindow),m_rowCount(0),m_supvisor(new Supervisor(this))
{
    ui->setupUi(this);
    m_menu = this->menuBar()->addMenu(tr("Settings")); // create the menu bar
    m_toolBar = this->addToolBar(tr("Shortcuts")); // create the tool bar
    this->statusBar();  // create status bar
    // set the actions
    // start action
    m_startAction = new QAction(QIcon(":/images/tool-start"),tr("St&art"),this);
    m_startAction->setStatusTip(tr("Start a new SCanning"));
    m_menu->addAction(m_startAction);
    m_toolBar->addAction(m_startAction);
    // stop action
    m_stopAction = new QAction(QIcon(":/images/tool-stop"),tr("St&op"),this);
    m_stopAction->setStatusTip(tr("Stop SCanning"));
    m_menu->addAction(m_stopAction);
    m_toolBar->addAction(m_stopAction);
    // the radar gif
    m_radar=new QLabel;
    QMovie *pm =new QMovie(":/movies/radar-green");
    pm->start();
    m_radar->setMovie(pm);
    m_radar->setScaledContents(true);   // set the label can resize the picture(or label size is fixed)
    this->ui->verticalLayout_right->addWidget(m_radar);
    m_radar->setVisible(false);
    // add a spacer
    m_spacer=new QSpacerItem(20,40,QSizePolicy::Expanding,QSizePolicy::Expanding);
    this->ui->verticalLayout_right->addItem(m_spacer);

    /* initial components */
    // set tableWidget
    ui->tableResult->setColumnCount(3);
    ui->tableResult->setRowCount(m_rowCount);
    QStringList headers;
    headers << "IP" << "PORT" << "PROTOCOL";
    ui->tableResult->setHorizontalHeaderLabels(headers);
    ui->tableResult->setEditTriggers(QAbstractItemView::NoEditTriggers); // not editable
    ui->tableResult->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);// only for qt5.0+

    // set ip line editor
    QRegExp regExpIP("((2[0-4]\\d|25[0-5]|[01]?\\d\\d?)\\.){3}(2[0-4]\\d|25[0-5]|[01]?\\d\\d?)");
    ui->lineEditIPStart->setValidator(new QRegExpValidator(regExpIP,this));
    ui->lineEditIPStart->setInputMask("000.000.000.000");
    ui->lineEditIPEnd->setValidator(new QRegExpValidator(regExpIP,this));
    ui->lineEditIPEnd->setInputMask("000.000.000.000");
    // set port line editor
    QRegExp regExpPort("[0-9]{0,5}");
    ui->lineEditPortStart->setValidator(new QRegExpValidator(regExpPort,this));
    ui->lineEditPortEnd->setValidator(new QRegExpValidator(regExpPort,this));

    /* connect signals and slots */
    //action to startScan and supervisor::stop
    connect(m_startAction, &QAction::triggered, this, &MainWindow::startScan);
    connect(m_stopAction, &QAction::triggered, m_supvisor, &Supervisor::signal_stop);
    //buttonStart to startScan
    connect(this->ui->buttonStart,&QPushButton::clicked,this,&MainWindow::startScan);
    //Found to addTableItem
    connect(this->m_supvisor,&Supervisor::Founded,this,&MainWindow::addTableItem);
    // signals between MainWindows and supvisor
    connect(this->ui->buttonStop,&QPushButton::clicked,this->m_supvisor,&Supervisor::signal_stop);// stop
    connect(this->m_supvisor,&Supervisor::signal_start,this,&MainWindow::lockInput);  // lock input
    connect(this->m_supvisor,&Supervisor::signal_done,this,&MainWindow::freeInput);   // free input
}

void MainWindow::startScan()
{
    // clear the  tablewidget
    m_rowCount = 0;
    this->ui->tableResult->setRowCount(m_rowCount);
    // inform supvisor about the scan informations
    if( !ipQStrToUint(this->ui->lineEditIPStart->text(),m_supvisor->m_ipStart) ){
        QMessageBox::information( this, tr("Invalid ip address!"),tr("the ip start address is not valid!") );
        return;
    }
    if( !ipQStrToUint(this->ui->lineEditIPEnd->text(),m_supvisor->m_ipEnd) ){
        QMessageBox::information( this, tr("Invalid ip address!"),tr("the ip end address is not valid!") );
        return;
    }
    // if the ip end is 0,set it to the ipstart
    if( !m_supvisor->m_ipEnd )
        m_supvisor->m_ipEnd=m_supvisor->m_ipStart;
    m_supvisor->m_portStart = this->ui->lineEditPortStart->text().toUInt();
    m_supvisor->m_portEnd = this->ui->lineEditPortEnd->text().toUInt();
    // if the end is zero, then set it to the start
    if( !m_supvisor->m_portEnd )
        m_supvisor->m_portEnd=m_supvisor->m_portStart;
    m_supvisor->m_bICMP=this->ui->checkBoxICMP->isChecked();
    m_supvisor->m_bTCP_C=this->ui->checkBoxTCPC->isChecked();
    m_supvisor->m_bTCP_S=this->ui->checkBoxTCPS->isChecked();
    m_supvisor->m_bTCP_F=this->ui->checkBoxTCPF->isChecked();
    m_supvisor->m_bUDP=this->ui->checkBoxUDP->isChecked();
    // start supvisor
    m_supvisor->start();
}

void MainWindow::addTableItem(unsigned int ip, unsigned short port, unsigned short protocol)
{
    // make an alias for convinience
    QTableWidget * &table = this->ui->tableResult;
    // add the rowCount
    this->m_rowCount++;
    // dynamically set the rowCount
    table->setRowCount(m_rowCount);
    unsigned char *p = (unsigned char*)&ip;
    QString ipStr = QString::number(uint(*p))+"."+
            QString::number(uint(*(p+1)))+"."+
            QString::number(uint(*(p+2)))+"."+
            QString::number(uint(*(p+3)));
    QString portStr = QString::number(port);
    QString protoStr;
    Qt::GlobalColor itemColor;
    switch (protocol)
    {
    case PROTOCOL_ICMP:
        protoStr="ICMP";
        portStr = "NULL";   // icmp doesn't have a port
        itemColor=Qt::cyan;
        break;
    case PROTOCOL_TCP_C:
        protoStr="TCP_C";
        itemColor=Qt::yellow;
        break;
    case PROTOCOL_TCP_S:
        protoStr="TCP_S";
        itemColor=Qt::green;
        break;
    case PROTOCOL_TCP_F:
        protoStr="TCP_F";
        itemColor=Qt::lightGray;
        break;
    case PROTOCOL_UDP:
        protoStr="UDP";
        itemColor=Qt::darkGray;
        break;
    default:
        break;
    }
    // add it to the table widget
    QTableWidgetItem *pItem = new QTableWidgetItem(ipStr);
    pItem->setBackgroundColor(QColor(itemColor));
    table->setItem(m_rowCount-1, 0, pItem);
    pItem = new QTableWidgetItem(portStr);
    pItem->setBackgroundColor(QColor(itemColor));
    table->setItem(m_rowCount-1, 1, pItem);
    pItem = new QTableWidgetItem(protoStr);
    pItem->setBackgroundColor(QColor(itemColor));
    table->setItem(m_rowCount-1, 2, pItem);
    return;
}

void MainWindow::lockInput()
{
    // disable the inputs and hide some of them
    this->m_startAction->setDisabled(true);
    this->ui->buttonStart->setDisabled(true);
    this->ui->lineEditIPStart->setDisabled(true);
    this->ui->lineEditIPStart->setVisible(false);
    this->ui->lineEditIPEnd->setDisabled(true);
    this->ui->lineEditIPEnd->setVisible(false);
    this->ui->lineEditPortStart->setDisabled(true);
    this->ui->lineEditPortStart->setVisible(false);
    this->ui->lineEditPortEnd->setDisabled(true);
    this->ui->lineEditPortEnd->setVisible(false);
    this->ui->checkBoxICMP->setDisabled(true);
    this->ui->checkBoxICMP->setVisible(false);
    this->ui->checkBoxTCPC->setDisabled(true);
    this->ui->checkBoxTCPC->setVisible(false);
    this->ui->checkBoxTCPS->setDisabled(true);
    this->ui->checkBoxTCPS->setVisible(false);
    this->ui->checkBoxTCPF->setDisabled(true);
    this->ui->checkBoxTCPF->setVisible(false);
    this->ui->checkBoxUDP->setDisabled(true);
    this->ui->checkBoxUDP->setVisible(false);
    this->ui->label_ipsettings->setVisible(false);
    this->ui->label_ipstart->setVisible(false);
    this->ui->label_ipend->setVisible(false);
    this->ui->label_portsettings->setVisible(false);
    this->ui->label_portstart->setVisible(false);
    this->ui->label_portend->setVisible(false);
    // remove the spacer for appearance
    this->ui->verticalLayout_right->removeItem(m_spacer);
    // show the radar
    m_radar->setVisible(true);

}

void MainWindow::freeInput()
{
    // hide radar
    m_radar->setVisible(false);
    // free input
    this->m_startAction->setDisabled(false);
    this->ui->buttonStart->setDisabled(false);
    this->ui->lineEditIPStart->setDisabled(false);
    this->ui->lineEditIPEnd->setDisabled(false);
    this->ui->lineEditPortStart->setDisabled(false);
    this->ui->lineEditPortEnd->setDisabled(false);
    this->ui->checkBoxICMP->setDisabled(false);
    this->ui->checkBoxTCPC->setDisabled(false);
    this->ui->checkBoxTCPS->setDisabled(false);
    this->ui->checkBoxTCPF->setDisabled(false);
    this->ui->checkBoxUDP->setDisabled(false);
    // show everything
    this->ui->lineEditIPStart->setVisible(true);
    this->ui->lineEditIPEnd->setVisible(true);
    this->ui->lineEditPortStart->setVisible(true);
    this->ui->lineEditPortEnd->setVisible(true);
    this->ui->checkBoxICMP->setVisible(true);
    this->ui->checkBoxTCPC->setVisible(true);
    this->ui->checkBoxTCPS->setVisible(true);
    this->ui->checkBoxTCPF->setVisible(true);
    this->ui->checkBoxUDP->setVisible(true);
    this->ui->label_ipsettings->setVisible(true);
    this->ui->label_ipstart->setVisible(true);
    this->ui->label_ipend->setVisible(true);
    this->ui->label_portsettings->setVisible(true);
    this->ui->label_portstart->setVisible(true);
    this->ui->label_portend->setVisible(true);
    // add the spacer for appearance
    this->ui->verticalLayout_right->addItem(m_spacer);
}

MainWindow::~MainWindow()
{
    delete ui;
    delete m_supvisor;
    delete m_startAction;
    delete m_stopAction;
    delete m_radar;
    //delete m_spacer;  // needn't to delete because it seems the framework did it for us
}
