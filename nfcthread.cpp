#include <inttypes.h>
#include "nfcthread.h"
#include "QDebug"
#include <qfile.h>
#include <QTemporaryFile>

#include <nfc/nfc.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/evp.h>


#define MAX_FRAME_LEN 264

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


void do_sha256(uint8_t *digest, const uint8_t *message, size_t len) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, message, len);
    SHA256_Final(digest, &ctx);
}

QString cert_common_name(X509* cert)
{
    char buf[256];
    int loc;
    X509_NAME_ENTRY *e;
    X509_NAME *certsubject;

    /*  get the offending certificate causing the failure */
    certsubject = X509_NAME_new();
    certsubject = X509_get_subject_name(cert);

    loc = -1;
    for (;;) {
        loc = X509_NAME_get_index_by_NID(certsubject, NID_commonName, loc);
        if (loc == -1)
                break;
        e = X509_NAME_get_entry(certsubject, loc);
        /* Do something with e */
        ASN1_STRING *s = X509_NAME_ENTRY_get_data(e);
        memset(buf, 0, sizeof(buf));
        memcpy(buf, s->data, s->length);
        return QString(buf);
    }
    return QString("");
}


QString print_hex(const uint8_t *pbtData, const size_t szBytes)
{
    size_t szPos;
    QString str;

    for (szPos = 0; szPos < szBytes; szPos++) {

        str += QString("%1 ").arg(pbtData[szPos], 2, 16, QChar('0'));
    }
    return str;
}


int
NFCThread::send(uint8_t *capdu, size_t capdulen, uint8_t *rapdu, size_t *rapdulen)
{
    int res;
    debugLine("=> " + print_hex(capdu, capdulen));
    if ((res = nfc_initiator_transceive_bytes(m_nfcDevice, capdu, capdulen, rapdu, *rapdulen, 500)) < 0) {
        return -1;
    } else {
        *rapdulen = (size_t) res;

        debugLine("<= " + print_hex(rapdu, *rapdulen));

        if (res < 2 || rapdu[res - 2] != 0x90 || rapdu[res - 1] != 0x00) {
            return -2;
        }

        return 0;
    }
}

NFCThread::NFCThread(QObject *parent) :
    QThread(parent)
{
    QFile file(":/certs/cert.pem");
    caFile = QTemporaryFile::createNativeFile(file);
}

void NFCThread::terminate()
{
    qDebug() << "Thread end";
    if (m_nfcDevice) {
        nfc_close(m_nfcDevice);
    }
    delete caFile;

    nfc_exit(m_nfcContext);
    //exit(EXIT_SUCCESS);
}

void NFCThread::debugLine(QString line)
{
    qDebug() << line;
    emit nfcLog(QVariant(line));
}

void NFCThread::run()
{
    uint8_t capdu[MAX_FRAME_LEN];
    size_t capdulen;
    uint8_t rapdu[MAX_FRAME_LEN];
    size_t rapdulen;
    uint32_t certlen, framelen, siglength;
    int frag, fragments;
    uint8_t *cert = NULL, *certbuff, *signature = NULL;
    X509_STORE* store;


    nfc_target nt;

    nfc_init(&m_nfcContext);

    if (m_nfcContext == NULL) {
        qFatal("Unable to init libnfc (malloc)");
        exit(EXIT_FAILURE);
    }

    debugLine("CAFile :" + caFile->fileName());

    store = X509_STORE_new();
    X509_STORE_load_locations(store,caFile->fileName().toLatin1(), NULL);
    X509_STORE_set_default_paths(store);


    for (;;) {
        m_nfcDevice = nfc_open(m_nfcContext, NULL);

        if (m_nfcDevice == NULL) {
            qFatal("Unable to open NFC device: %s", nfc_strerror(m_nfcDevice));
            exit(EXIT_FAILURE);
        }
        if (nfc_initiator_init(m_nfcDevice) < 0) {
            qFatal("%s", nfc_strerror(m_nfcDevice));
            exit(EXIT_FAILURE);
        }

        debugLine(QString("NFC reader opened: %1").arg(nfc_device_get_name(m_nfcDevice)));


        while (nfc_initiator_select_passive_target(m_nfcDevice, nmReader, NULL, 0, &nt) <= 0);
        emit certValidated(QVariant(false), QVariant(QString("")));
        emit sigValidated(QVariant(false));


        debugLine("Target detected! Running command set...");

        // Select application
        memcpy(capdu, "\x00\xA4\x04\x00\x07\xF0\xA9\x41\x48\x14\x81\x00\x00", 13);
        capdulen = 13;
        rapdulen = sizeof(rapdu);

        debugLine("Sending ADPU SELECT...\n");
        if (send(capdu, capdulen, rapdu, &rapdulen) < 0) {
            goto restart;
        }

        debugLine("Application selected!");


        /*---challenge---*/
        debugLine("Allocate challenge\n");
        uint8_t challenge[16];
        if (!RAND_bytes(challenge, 16)) {
            if (!RAND_pseudo_bytes(challenge, 16)) {
                goto restart;
            }
        }

        debugLine("Sending lock ident...");
        memcpy(capdu, apdu_ident, sizeof(apdu_ident));
        capdulen = sizeof(apdu_ident);
        rapdulen = sizeof(rapdu);

        if (send(capdu, capdulen, rapdu, &rapdulen) < 0)
            goto restart;

        memcpy(&framelen, rapdu + 1, 4);
        memcpy(&certlen, rapdu + 5, 4);
        cert = (uint8_t*)malloc(certlen);
        certbuff = cert;
        fragments = certlen / framelen + ((certlen % framelen) > 0);
        debugLine(QString("Ident: Frame len %1 certlen %2 fragments %3")
               .arg(framelen)
               .arg(certlen)
               .arg(fragments));
        debugLine("Ident sent!");

        for (frag = 0; frag < fragments; frag++) {
            debugLine(QString("Sending read cert fragment %1... ").arg(frag));
            memcpy(capdu, apdu_ident_frag, sizeof(apdu_ident_frag));
            capdu[3] = frag;
            capdulen = sizeof(apdu_ident_frag);
            rapdulen = sizeof(rapdu);

            if (send(capdu, capdulen, rapdu, &rapdulen) < 0)
                goto restart;

            rapdulen -= 2;
            memcpy(cert + (frag * framelen), rapdu, rapdulen);
            debugLine(QString("Read frag %1 sent!... ").arg(frag));

        }

        debugLine("Sending lock challenge...");
        memcpy(capdu, apdu_challenge, sizeof(apdu_challenge));
        capdulen = sizeof(apdu_challenge);
        memcpy(capdu + capdulen, challenge, 16);
        capdulen += 16;
        rapdulen=sizeof(rapdu);

        if (send(capdu, capdulen, rapdu, &rapdulen) < 0)
            goto restart;
        if (rapdulen <= 2)
            goto restart;

        siglength = rapdulen - 2;
        signature = (uint8_t*)malloc(siglength);
        memcpy(signature, rapdu, siglength);
        debugLine("Challenge sent!");

        {
            X509* phone;
            X509_STORE_CTX *ctx;

            OpenSSL_add_all_algorithms();


            phone = d2i_X509(NULL, (const unsigned char **)&cert, certlen);
            cert = cert - certlen;
            ctx = X509_STORE_CTX_new();

            X509_STORE_CTX_init(ctx, store, phone, NULL);

            debugLine("Verifying Certificate");
            if (X509_verify_cert(ctx) > 0) {
                debugLine("Certificate Valid");
                emit certValidated(QVariant(true), QVariant(cert_common_name(phone)));

                debugLine("Verifying Signature\n");

                EVP_PKEY *pkey = X509_get_pubkey(phone);
                EC_KEY *key = EVP_PKEY_get1_EC_KEY(pkey);
                uint8_t digest[32];
                ECDSA_SIG *sig;
                const unsigned char *sig_copy = signature;
                sig = d2i_ECDSA_SIG(NULL, &sig_copy, siglength);
                    printf("r: %s\n", BN_bn2hex(sig->r));
                    printf("s: %s\n", BN_bn2hex(sig->s));

                do_sha256(digest, challenge, 16);
                int verified = ECDSA_do_verify(digest, 32, sig, key);
                if(verified == 1) {
                   debugLine("Signature valid");
                    emit sigValidated(QVariant(true));
                } else {
                    debugLine("Signature invalid");
                    emit sigValidated(QVariant(false));
                }

            } else {
                debugLine(QString("Certificate Invalid %1\n").arg(X509_STORE_CTX_get_error(ctx)));
                debugLine(QString("Valid error: %1\n").arg(X509_verify_cert_error_string(ctx->error)));
#if 0
                /*  get the offending certificate causing the failure */
                error_cert  = X509_STORE_CTX_get_current_cert(ctx);
                certsubject = X509_NAME_new();
                certsubject = X509_get_subject_name(error_cert);
                printf("Failed certificate:");
                X509_NAME_print_ex(outbio, certsubject, 0, XN_FLAG_MULTILINE);
                printf("\n");
#endif
                emit certValidated(QVariant(false), QVariant(cert_common_name(phone)));

            }

            X509_STORE_CTX_free(ctx);
            X509_free(phone);
        }

        debugLine("Wrapping up, closing session.\n\n");


restart:
        if (cert)
            free(certbuff);
        if (signature)
            free(signature);

        cert = NULL;
        signature = NULL;

        nfc_close(m_nfcDevice);
        m_nfcDevice = NULL;
        sleep(1);
    }
}
