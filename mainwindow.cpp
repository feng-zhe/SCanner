#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "supervisor.h"
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
    connect(this->supvisor,&Supervisor::pingFounded,this,&MainWindow::addTableItem);
}

void MainWindow::start()
{
    supvisor->start();

}

void MainWindow::addTableItem(unsigned int ip, unsigned short icmpID, unsigned short ipID)
{
    return;
}

MainWindow::~MainWindow()
{
    delete ui;
}
