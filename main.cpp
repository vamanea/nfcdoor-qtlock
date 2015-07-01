#include <QApplication>
#include <QQmlApplicationEngine>
#include "nfcthread.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    QQmlApplicationEngine engine;
    engine.load(QUrl(QStringLiteral("qrc:/main.qml")));

    if (engine.rootObjects().length() < 1) {
        qFatal("No root objects");
        QApplication::exit();
    }

    QObject *mainWindow = engine.rootObjects().at(0);
    NFCThread *nfcThread = new NFCThread(NULL);
    QObject::connect(&app, SIGNAL(aboutToQuit()),
                     nfcThread, SLOT(terminate()));

    QObject::connect(nfcThread, SIGNAL(nfcLog(QVariant)),
                     mainWindow, SLOT(nfcLog(QVariant)));

    QObject::connect(nfcThread, SIGNAL(sigValidated(QVariant)),
                     mainWindow, SLOT(sigValidated(QVariant)));
    QObject::connect(nfcThread, SIGNAL(certValidated(QVariant)),
                     mainWindow, SLOT(certValidated(QVariant)));

    nfcThread->start(QThread::HighestPriority);

    return app.exec();
}
