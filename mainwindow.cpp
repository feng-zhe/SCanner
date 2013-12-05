#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QAction>
#include <QMenuBar>
#include <QToolBar>
#include <QStatusBar>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    // now it's my code
    startAction = new QAction(QIcon(":/image/tool-start"),tr("&Start"),this);

}

MainWindow::~MainWindow()
{
    delete ui;
}
