#-------------------------------------------------
#
# Project created by QtCreator 2013-12-04T22:04:25
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = Scanner
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    icmpsender.cpp \
    supervisor.cpp \
    icmpsniffer.cpp

HEADERS  += mainwindow.h \
    icmpsender.h \
    defines.h \
    supervisor.h \
    icmpsniffer.h

FORMS    += mainwindow.ui

RESOURCES += \
    res.qrc

LIBS += -lnet
