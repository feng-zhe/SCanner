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

    /* initial components */
    // set tableWidget
    ui->tableResult->setColumnCount(3);
    ui->tableResult->setRowCount(m_rowCount);
    QStringList headers;
    headers << "IP" << "PORT" << "PROTOCOL";
    ui->tableResult->setHorizontalHeaderLabels(headers);
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
    connect(m_stopAction, &QAction::triggered, m_supvisor, &Supervisor::stop);
    //buttonStart to startScan
    connect(this->ui->buttonStart,&QPushButton::clicked,this,&MainWindow::startScan);
    //Found to addTableItem
    connect(this->m_supvisor,&Supervisor::Founded,this,&MainWindow::addTableItem);
    // signals between MainWindows and supvisor
    connect(this->ui->buttonStop,&QPushButton::clicked,this->m_supvisor,&Supervisor::stop);// stop
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
    m_supvisor->m_portStart = this->ui->lineEditPortStart->text().toUInt();
    m_supvisor->m_portEnd = this->ui->lineEditPortEnd->text().toUInt();
    m_supvisor->m_bICMP=this->ui->checkBoxICMP->isChecked();
    m_supvisor->m_bTCP_C=this->ui->checkBoxTCPC->isChecked();
    m_supvisor->m_bTCP_S=this->ui->checkBoxTCPS->isChecked();
    m_supvisor->m_bTCP_F=this->ui->checkBoxTCPF->isChecked();
    // start supvisor
    m_supvisor->start();
}

void MainWindow::addTableItem(unsigned int ip, unsigned short port, unsigned short protocol)
{
    // make an alias for convinience
    QTableWidget * (&table) = this->ui->tableResult;
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
    switch (protocol)
    {
    case PROTOCOL_ICMP:
        protoStr="ICMP";
        portStr = "NULL";
        break;
    case PROTOCOL_TCP_C:
        protoStr="TCP_C";
        break;
    case PROTOCOL_TCP_S:
        protoStr="TCP_S";
        break;
    case PROTOCOL_TCP_F:
        protoStr="TCP_F";
        break;
    default:
        break;
    }
    // add it to the table widget
    table->setItem(m_rowCount-1, 0, new QTableWidgetItem(ipStr));
    table->setItem(m_rowCount-1, 1, new QTableWidgetItem(portStr));
    table->setItem(m_rowCount-1, 2, new QTableWidgetItem(protoStr));
    return;
}

void MainWindow::lockInput()
{
    this->m_startAction->setDisabled(true);
    this->ui->buttonStart->setDisabled(true);
    this->ui->lineEditIPStart->setDisabled(true);
    this->ui->lineEditIPEnd->setDisabled(true);
    this->ui->lineEditPortStart->setDisabled(true);
    this->ui->lineEditPortEnd->setDisabled(true);
    this->ui->checkBoxICMP->setDisabled(true);
    this->ui->checkBoxTCPC->setDisabled(true);
    this->ui->checkBoxTCPS->setDisabled(true);
    this->ui->checkBoxTCPF->setDisabled(true);
}

void MainWindow::freeInput()
{
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
}

MainWindow::~MainWindow()
{
    delete ui;
    delete m_supvisor;
}
