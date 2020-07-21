#include <QCoreApplication>
#include <QTimer>
#include <QtNetwork/QSslSocket>
#include <QtMqtt/QMqttClient>
#include <QCommandLineParser>
#include <QTimer>
#include <QFileInfo>
#include <QDebug>
#include <QObject>

static QMqttClient* mqtt_client;
static QSslSocket* ssl_socket;
static bool ping_response_received = false;
static QString url = "";

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

        if(ssl_socket->state() != QAbstractSocket::ConnectedState && ssl_socket->state() != QAbstractSocket::ConnectingState)
        {
            qDebug() << "Socket is disconnect, trying to reconnect ...";
            ssl_socket->disconnectFromHost();
            ssl_socket->abort();
            ssl_socket->close();
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

    QFileInfo ca_cert(args.at(0));
    QFileInfo device_cert(args.at(1));
    QFileInfo private_key(args.at(2));

    ssl_socket->setLocalCertificate(device_cert.filePath(), QSsl::EncodingFormat::Pem);
    ssl_socket->addCaCertificates(ca_cert.filePath(), QSsl::Pem,  QRegExp::FixedString);
    ssl_socket->setPrivateKey(private_key.filePath(), QSsl::Rsa, QSsl::EncodingFormat::Pem);
    ssl_socket->setProtocol(QSsl::SslProtocol::TlsV1_2);

    QObject::connect(ssl_socket, &QSslSocket::encrypted, &onSSLEncrypted);

    QObject::connect(ssl_socket, &QSslSocket::connected, [=](){
        qDebug() << "SSL Socket connected!";
        //ssl_socket->setSocketOption(QAbstractSocket::KeepAliveOption, 1);
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
