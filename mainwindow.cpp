#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QAction>
#include <QMenuBar>
#include <QToolBar>
#include <QStatusBar>
#include <QMessageBox>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
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

    // connect buttons and slots
    connect(this->ui->buttonStart,&QPushButton::clicked,this,&MainWindow::start);
}

void MainWindow::start()
{
    QMessageBox::information(NULL, "Title", "licked!", QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes);
}

MainWindow::~MainWindow()
{
    delete ui;
}
