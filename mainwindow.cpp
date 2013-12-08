#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "supervisor.h"
#include "defines.h"
#include <QAction>
#include <QMenuBar>
#include <QToolBar>
#include <QStatusBar>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),ui(new Ui::MainWindow),supvisor(new Supervisor(this)),rowCount(0)
{
    ui->setupUi(this);
    // now it's my code
    // set menubar, toolbar and statusbar
    startAction = new QAction(QIcon(":/images/tool-start"),tr("&Start"),this);
    startAction->setStatusTip(tr("Start a new SCanner"));
    connect(startAction, &QAction::triggered, this, &MainWindow::start);
    QMenu *menu = this->menuBar()->addMenu(tr("Settings"));
    menu->addAction(startAction);
    QToolBar *toolBar = this->addToolBar(tr("Shortcuts"));
    toolBar->addAction(startAction);
    this->statusBar();

    // set tableWidget
    ui->tableResult->setColumnCount(3);
    ui->tableResult->setRowCount(rowCount);
    QStringList headers;
    headers << "IP" << "PORT" << "PROTOCOL";
    ui->tableResult->setHorizontalHeaderLabels(headers);

    // connect signals and slots
    connect(this->ui->buttonStart,&QPushButton::clicked,this,&MainWindow::start);
    connect(this->supvisor,&Supervisor::Founded,this,&MainWindow::addTableItem);
}

void MainWindow::start()
{
    supvisor->start();
}

void MainWindow::addTableItem(unsigned int ip, unsigned short port, unsigned short protocol)
{
    // make an alias for convinience
    QTableWidget * (&table) = this->ui->tableResult;
    // add the rowCount
    this->rowCount++;
    // dynamically set the rowCount
    table->setRowCount(rowCount);
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
    case PROTOCOL_TCP_S:
    case PROTOCOL_TCP_F:
        protoStr="TCP";
        break;
    default:
        break;
    }
    // add it to the table widget
    table->setItem(rowCount-1, 0, new QTableWidgetItem(ipStr));
    table->setItem(rowCount-1, 1, new QTableWidgetItem(portStr));
    table->setItem(rowCount-1, 2, new QTableWidgetItem(protoStr));
    return;
}

MainWindow::~MainWindow()
{
    delete ui;
}
