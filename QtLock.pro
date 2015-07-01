TEMPLATE = app

QT += qml quick widgets

SOURCES += main.cpp \
    nfcthread.cpp

RESOURCES += qml.qrc

LIBS += -lnfc -lssl -lcrypto
# Additional import path used to resolve QML modules in Qt Creator's code model
QML_IMPORT_PATH =

# Default rules for deployment.
include(deployment.pri)

HEADERS += \
    nfcthread.h
