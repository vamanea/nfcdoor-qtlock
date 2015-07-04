#ifndef NFCTHREAD_H
#define NFCTHREAD_H

#include <QThread>
#include <QVariant>
#include <QTemporaryFile>
#include <nfc/nfc.h>

class NFCThread : public QThread
{
    Q_OBJECT
public:
    explicit NFCThread(QObject *parent = 0);

    void run();
signals:
    void nfcLog(const QVariant &line);
    void certValidated(const QVariant &valid, const QVariant &certName);
    void sigValidated(const QVariant &valid);


public slots:
    void terminate();

private:
    nfc_device *m_nfcDevice = NULL;
    nfc_context *m_nfcContext = NULL;
    QTemporaryFile *caFile;
    void debugLine(QString line);
    int send(uint8_t *capdu, size_t capdulen, uint8_t *rapdu, size_t *rapdulen);
};

#endif // NFCTHREAD_H
