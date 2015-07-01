#include <inttypes.h>
#include "nfcthread.h"
#include "QDebug"

#include <nfc/nfc.h>

static const nfc_modulation nmReader = {
    .nmt = NMT_ISO14443A,
    .nbr = NBR_106,
};


/* Send key ident command */
static uint8_t apdu_ident[] = { 0x00, 0xe0, 0x00, 0x00};
/* Read key cert fragment */
static uint8_t apdu_ident_frag[] = { 0x00, 0xe0, 0x01, 0x00};
/* Challenge APDU header */
static uint8_t apdu_challenge[] = { 0x00, 0xe0, 0x02, 0x00};


void
print_hex(const uint8_t *pbtData, const size_t szBytes)
{
    size_t  szPos;

    for (szPos = 0; szPos < szBytes; szPos++) {
        printf("%02x  ", pbtData[szPos]);
    }
    printf("\n");
}


int
NFCThread::send(uint8_t *capdu, size_t capdulen, uint8_t *rapdu, size_t *rapdulen)
{
    int res;
    printf("=> ");
    print_hex(capdu, capdulen);
    if ((res = nfc_initiator_transceive_bytes(m_nfcDevice, capdu, capdulen, rapdu, *rapdulen, 500)) < 0) {
        return -1;
    } else {
        *rapdulen = (size_t) res;
        printf("<= ");
        print_hex(rapdu, *rapdulen);
        return 0;
    }
}

NFCThread::NFCThread(QObject *parent) :
    QThread(parent)
{
}

void NFCThread::terminate()
{
    qDebug() << "Thread end";
    if (m_nfcDevice) {
        nfc_close(m_nfcDevice);
    }

    nfc_exit(m_nfcContext);
    exit(EXIT_SUCCESS);
}

void NFCThread::run()
{
    nfc_init(&m_nfcContext);

    if (m_nfcContext == NULL) {
        qFatal("Unable to init libnfc (malloc)");
        exit(EXIT_FAILURE);
    }

    for (;;) {
        nfc_target nt;

        m_nfcDevice = nfc_open(m_nfcContext, NULL);

        if (m_nfcDevice == NULL) {
            qFatal("Unable to open NFC device: %s", nfc_strerror(m_nfcDevice));
            exit(EXIT_FAILURE);
        }
        if (nfc_initiator_init(m_nfcDevice) < 0) {
            qFatal("%s", nfc_strerror(m_nfcDevice));
            exit(EXIT_FAILURE);
        }

        qDebug() << "NFC reader opened: " << nfc_device_get_name(m_nfcDevice);

        while (nfc_initiator_select_passive_target(m_nfcDevice, nmReader, NULL, 0, &nt) <= 0);

        qDebug() << "Target detected! Running command set...";


        nfc_close(m_nfcDevice);
        m_nfcDevice = NULL;
        sleep(1);
    }
}
