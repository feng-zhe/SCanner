#-------------------------------------------------
#
# Project created by QtCreator 2013-12-04T22:04:25
#
#-------------------------------------------------

QT       += core gui
QT       += network

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = Scanner
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    icmpsender.cpp \
    supervisor.cpp \
    icmpsniffer.cpp \
    tcpconnecter.cpp \
    tcpsfsender.cpp \
    tcpssniffer.cpp \
    tcp_f_sniffer.cpp \
    functions.cpp \
    udpsender.cpp \
    udpsniffer.cpp \
    devicemaster.cpp

HEADERS  += mainwindow.h \
    icmpsender.h \
    defines.h \
    supervisor.h \
    icmpsniffer.h \
    tcpconnecter.h \
    tcpsfsender.h \
    tcpssniffer.h \
    tcp_f_sniffer.h \
    functions.h \
    udpsender.h \
    udpsniffer.h \
    devicemaster.h

FORMS    += mainwindow.ui

RESOURCES += \
    res.qrc

LIBS += -lnet
LIBS += -L/usr/local/lib -lpcap
# for C++11
QMAKE_CXXFLAGS += -std=c++11
CONFIG += c++11
