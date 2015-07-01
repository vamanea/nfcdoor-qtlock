#include <QApplication>
#include <QQmlApplicationEngine>
#include "nfcthread.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    QQmlApplicationEngine engine;
    engine.load(QUrl(QStringLiteral("qrc:/main.qml")));

    NFCThread *nfcThread = new NFCThread(NULL);
    QObject::connect(&app, SIGNAL(aboutToQuit()),
                     nfcThread, SLOT(terminate()));
    nfcThread->start(QThread::HighestPriority);

    return app.exec();
}
