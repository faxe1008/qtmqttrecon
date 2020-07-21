#include <QCoreApplication>
#include <QTimer>
#include <QtNetwork/QSslSocket>
#include <QtMqtt/QMqttClient>
#include <QCommandLineParser>
#include <QTimer>
#include <QFileInfo>
#include <QDebug>
#include <QObject>
#include <netinet/in.h>
#include <netinet/tcp.h>

static QMqttClient* mqtt_client;
static QSslSocket* ssl_socket;
static bool ping_response_received = false;
static QString url = "";

static QFileInfo ca_cert;
static QFileInfo device_cert;
static QFileInfo private_key;

void onSSLEncrypted(){
    qDebug() << "SSL Socket encryption started!";
    if(mqtt_client->state() == QMqttClient::Connected)
    {
        mqtt_client->disconnectFromHost();
    }
    mqtt_client->connectToHostEncrypted();
}

void onCheckPingResponse(){
    if (!ping_response_received)
    {
        qDebug() << "Mqtt client ping timed out";

        if(ssl_socket && ssl_socket->state() != QAbstractSocket::ConnectedState && ssl_socket->state() != QAbstractSocket::ConnectingState)
        {
            qDebug() << "Socket is disconnect, trying to reconnect ... " << url;
            ssl_socket->flush();

            ssl_socket->connectToHostEncrypted(url, 8333);
            if(!ssl_socket->waitForEncrypted(3000)){
                qDebug() << "ERROR SSL SOCKET!! " << QString::number(ssl_socket->error());
            }
        }
    }

}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    QCommandLineParser parser;
    parser.addHelpOption();
    parser.addPositionalArgument("cacert", QCoreApplication::translate("main", "path to ca-cert"));
    parser.addPositionalArgument("certpem", QCoreApplication::translate("main", "path to certpem"));
    parser.addPositionalArgument("privatekey", QCoreApplication::translate("main", "path to privatekey"));
    parser.addPositionalArgument("clientid", QCoreApplication::translate("main", "clientid associated with certificates"));
    parser.addPositionalArgument("url", QCoreApplication::translate("main", "mqtt broker url"));

    parser.process(a);
    const QStringList args = parser.positionalArguments();

    url = args.at(4);
    mqtt_client = new QMqttClient(&a);
    ssl_socket = new QSslSocket(&a);

     ca_cert = QFileInfo(args.at(0));
     device_cert= QFileInfo(args.at(1));
     private_key= QFileInfo(args.at(2));

    ssl_socket->setLocalCertificate(device_cert.filePath(), QSsl::EncodingFormat::Pem);
    ssl_socket->addCaCertificates(ca_cert.filePath(), QSsl::Pem,  QRegExp::FixedString);
    ssl_socket->setPrivateKey(private_key.filePath(), QSsl::Rsa, QSsl::EncodingFormat::Pem);
    ssl_socket->setProtocol(QSsl::SslProtocol::TlsV1_2);

    QObject::connect(ssl_socket, &QSslSocket::encrypted, &onSSLEncrypted);

    QObject::connect(ssl_socket, &QSslSocket::connected, [=](){
        qDebug() << "SSL Socket connected!";
        ssl_socket->setSocketOption(QAbstractSocket::KeepAliveOption, 1);

        /*int fd = (int) ssl_socket->socketDescriptor();
        int maxIdle = 10;
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &maxIdle, sizeof(maxIdle));

        int count = 3;  // send up to 3 keepalive packets out, then disconnect if no response
        setsockopt(fd, SOL_TCP, TCP_KEEPCNT, &count, sizeof(count));

        int interval = 2;   // send a keepalive packet out every 2 seconds (after the 5 second idle period)
        setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, &interval, sizeof(interval));*/
    });
    QObject::connect(ssl_socket, &QSslSocket::disconnected, [=](){
        qDebug() << "SSL Socket disconnected!";
    });



    mqtt_client->setHostname(url);
    mqtt_client->setPort(8883);
    mqtt_client->setClientId(args.at(3));
    mqtt_client->setKeepAlive(20);
    mqtt_client->setTransport(ssl_socket,  QMqttClient::TransportType::SecureSocket);
    mqtt_client->setProtocolVersion(QMqttClient::ProtocolVersion::MQTT_3_1_1);

    QObject::connect(mqtt_client, &QMqttClient::stateChanged, [=](QMqttClient::ClientState state){
        qDebug() << "MQTT Client state changed! " << QString::number(state);
    });

    QObject::connect(mqtt_client, &QMqttClient::errorChanged, [=](QMqttClient::ClientError error){
        qDebug() << "MQTT Client error changed! " << QString::number(error);
    });

    QObject::connect(mqtt_client, &QMqttClient::connected, [=](){
        qDebug() << "MQTT client connected to broker now";
    });

    QObject::connect(mqtt_client, &QMqttClient::disconnected, [=](){
        qDebug() << "MQTT client disconnected from broker";
    });

    QObject::connect(mqtt_client, &QMqttClient::pingResponseReceived, [=](){
        ping_response_received = true;
        qDebug() << "################################### ping response received";
    });

    QObject::connect(ssl_socket, &QSslSocket::stateChanged, [=](QAbstractSocket::SocketState state){
        qDebug() << "Socket state changed " << QString::number(state);
    });

    QObject::connect(ssl_socket, static_cast<void (QSslSocket::*)(QAbstractSocket::SocketError)>(&QSslSocket::error), [=](QAbstractSocket::SocketError error){
        qDebug() << "Socket error changed " << QString::number(error);
        ssl_socket->resume();
    });

    QObject::connect(ssl_socket, &QSslSocket::hostFound, [=](){
        qDebug() << "Socket host found ";
    });


    QObject::connect(ssl_socket, &QSslSocket::peerVerifyError, [=](QSslError error){
          qDebug() << "Socket peer verify error " << error.errorString();
    });

    QObject::connect(ssl_socket,  QOverload<const QList<QSslError> &>::of(&QSslSocket::sslErrors), [=](QList<QSslError> errors){
        for(QSslError err : errors){
            qDebug() << "Socket QSslError " << err.errorString();
        }
    });


    QObject::connect(ssl_socket, &QSslSocket::modeChanged, [=](QSslSocket::SslMode newMode){
        qDebug() << "Socket mode changed " << QString::number(newMode);
    });

    QTimer* keepalive_timer = new QTimer(&a);
    keepalive_timer->setInterval(20000);
    QObject::connect(keepalive_timer, &QTimer::timeout, [=](){
        qDebug() << "Sending ping request";
        ping_response_received = false;
        mqtt_client->requestPing();
        QTimer::singleShot(5000, &onCheckPingResponse);
    });
    keepalive_timer->start();

    qDebug() << "Connecting to " << url << " on port 8333 as " << args.at(3);

    ssl_socket->connectToHostEncrypted(args.at(4), 8883);
    if(!ssl_socket->waitForEncrypted(5000)){
        qWarning() << "Error waiting for socket encryption";
    }

    return a.exec();
}
