#define POLKIT_AGENT_I_KNOW_API_IS_SUBJECT_TO_CHANGE 1

#include <print>
#include <QJsonDocument>
#include <QStandardPaths>
#ifdef signals
#undef signals
#endif
#include <polkitagent/polkitagent.h>

#include "Agent.hpp"

CAgent::CAgent() {
    ;
}

CAgent::~CAgent() {
    ;
}

bool CAgent::start(QCoreApplication& app, const QString& socketPath) {
    sessionSubject = makeShared<PolkitQt1::UnixSessionSubject>(getpid());

    listener.registerListener(*sessionSubject, "/org/hyprland/PolicyKit1/AuthenticationAgent");

    app.setApplicationName("Hyprland Polkit Agent");

    ipcSocketPath = socketPath;
    setupIpcServer();

    app.exec();

    return true;
}

void CAgent::resetAuthState() {
    if (authState.authing) {
        authState.authing = false;
    }
}

void CAgent::initAuthPrompt() {
    resetAuthState();

    if (!listener.session.inProgress) {
        std::print(stderr, "INTERNAL ERROR: Auth prompt requested but session isn't in progress\n");
        return;
    }

    std::print("Auth prompt requested\n");

    authState.authing = true;
    // The actual request is emitted when the session provides a prompt.
}

void CAgent::enqueueEvent(const QJsonObject& event) {
    eventQueue.enqueue(event);
}

QJsonObject CAgent::buildRequestEvent() const {
    QJsonObject event;
    event["type"] = "request";
    event["id"] = listener.session.cookie;
    event["actionId"] = listener.session.actionId;
    event["message"] = listener.session.message;
    event["icon"] = listener.session.iconName;
    event["user"] = listener.session.selectedUser.toString();
    event["prompt"] = listener.session.prompt;
    event["echo"] = listener.session.echoOn;

    QJsonObject details;
    const auto keys = listener.session.details.keys();
    for (const auto& key : keys) {
        details.insert(key, listener.session.details.lookup(key));
    }
    event["details"] = details;

    if (!listener.session.errorText.isEmpty())
        event["error"] = listener.session.errorText;

    return event;
}

void CAgent::enqueueRequest() {
    enqueueEvent(buildRequestEvent());
}

void CAgent::enqueueError(const QString& error) {
    QJsonObject event;
    event["type"] = "update";
    event["id"] = listener.session.cookie;
    event["error"] = error;
    enqueueEvent(event);
}

void CAgent::enqueueComplete(const QString& result) {
    QJsonObject event;
    event["type"] = "complete";
    event["id"] = listener.session.cookie;
    event["result"] = result;
    enqueueEvent(event);
}

bool CAgent::handleRespond(const QString& cookie, const QString& password) {
    if (!listener.session.inProgress || listener.session.cookie != cookie)
        return false;
    listener.submitPassword(password);
    return true;
}

bool CAgent::handleCancel(const QString& cookie) {
    if (!listener.session.inProgress || listener.session.cookie != cookie)
        return false;
    listener.cancelPending();
    return true;
}

void CAgent::setupIpcServer() {
    if (ipcSocketPath.isEmpty()) {
        const auto runtimeDir = QStandardPaths::writableLocation(QStandardPaths::RuntimeLocation);
        ipcSocketPath = runtimeDir + "/noctalia-polkit-agent.sock";
    }

    QLocalServer::removeServer(ipcSocketPath);

    ipcServer = new QLocalServer();
    ipcServer->setSocketOptions(QLocalServer::UserAccessOption);

    QObject::connect(ipcServer, &QLocalServer::newConnection, [this]() {
        while (ipcServer->hasPendingConnections()) {
            auto* socket = ipcServer->nextPendingConnection();
            QObject::connect(socket, &QLocalSocket::readyRead, [this, socket]() {
                const QByteArray data = socket->readAll();
                handleSocket(socket, data);
            });
            QObject::connect(socket, &QLocalSocket::disconnected, socket, &QObject::deleteLater);
        }
    });

    ipcServer->listen(ipcSocketPath);
}

void CAgent::handleSocket(QLocalSocket* socket, const QByteArray& data) {
    const QList<QByteArray> lines = data.split('\n');
    const QString command = QString::fromUtf8(lines.value(0)).trimmed();
    const QString payload = QString::fromUtf8(lines.value(1)).trimmed();

    if (command == "PING") {
        socket->write("PONG\n");
        socket->flush();
        socket->disconnectFromServer();
        return;
    }

    if (command == "NEXT") {
        if (eventQueue.isEmpty()) {
            socket->write("\n");
        } else {
            const auto event = eventQueue.dequeue();
            const auto json = QJsonDocument(event).toJson(QJsonDocument::Compact);
            socket->write(json + "\n");
        }
        socket->flush();
        socket->disconnectFromServer();
        return;
    }

    if (command.startsWith("RESPOND ")) {
        const QString cookie = command.mid(QString("RESPOND ").length()).trimmed();
        const bool ok = handleRespond(cookie, payload);
        socket->write(ok ? "OK\n" : "ERROR\n");
        socket->flush();
        socket->disconnectFromServer();
        return;
    }

    if (command.startsWith("CANCEL ")) {
        const QString cookie = command.mid(QString("CANCEL ").length()).trimmed();
        const bool ok = handleCancel(cookie);
        socket->write(ok ? "OK\n" : "ERROR\n");
        socket->flush();
        socket->disconnectFromServer();
        return;
    }

    socket->write("ERROR\n");
    socket->flush();
    socket->disconnectFromServer();
}
