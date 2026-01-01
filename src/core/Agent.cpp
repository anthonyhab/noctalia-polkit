#define POLKIT_AGENT_I_KNOW_API_IS_SUBJECT_TO_CHANGE 1

#include <print>
#include <cstring>
#include <QDBusConnection>
#include <QDBusInterface>
#include <QDBusReply>
#include <QJsonDocument>
#include <QStandardPaths>
#ifdef signals
#undef signals
#endif
#include <polkitagent/polkitagent.h>

#include "Agent.hpp"

namespace {
// Secure memory zeroing that won't be optimized away
void secureZero(void* ptr, size_t len) {
    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    while (len--) *p++ = 0;
}
}

CAgent::CAgent() {
    ;
}

CAgent::~CAgent() {
    ;
}

bool CAgent::start(QCoreApplication& app, const QString& socketPath) {
    sessionSubject = std::make_shared<PolkitQt1::UnixSessionSubject>(getpid());

    listener.registerListener(*sessionSubject, "/org/noctalia/PolicyKit1/AuthenticationAgent");

    app.setApplicationName("Noctalia Polkit Agent");

    // Setup keyring service symlink before IPC server
    if (!setupKeyringServiceSymlink())
        std::print(stderr, "Warning: Failed to setup keyring service symlink\n");

    ipcSocketPath = socketPath;
    setupIpcServer();

    fingerprintAvailable = checkFingerprintAvailable();
    if (fingerprintAvailable)
        std::print("Fingerprint authentication available\n");

    app.exec();

    return true;
}

bool CAgent::checkFingerprintAvailable() {
    // Check if fprintd is available and user has enrolled fingerprints
    QDBusInterface manager("net.reactivated.Fprint",
                           "/net/reactivated/Fprint/Manager",
                           "net.reactivated.Fprint.Manager",
                           QDBusConnection::systemBus());

    if (!manager.isValid())
        return false;

    // Get the default fingerprint device
    QDBusReply<QDBusObjectPath> deviceReply = manager.call("GetDefaultDevice");
    if (!deviceReply.isValid())
        return false;

    QString devicePath = deviceReply.value().path();
    if (devicePath.isEmpty())
        return false;

    // Check if current user has enrolled fingerprints on this device
    QDBusInterface device("net.reactivated.Fprint",
                          devicePath,
                          "net.reactivated.Fprint.Device",
                          QDBusConnection::systemBus());

    if (!device.isValid())
        return false;

    // ListEnrolledFingers returns the list of enrolled fingers for a user
    QString username = qgetenv("USER");
    QDBusReply<QStringList> fingersReply = device.call("ListEnrolledFingers", username);

    if (!fingersReply.isValid())
        return false;

    return !fingersReply.value().isEmpty();
}

bool CAgent::setupKeyringServiceSymlink() {
    // Get XDG_DATA_HOME (defaults to ~/.local/share)
    const QString dataHome = QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation);
    if (dataHome.isEmpty()) {
        std::print(stderr, "Could not determine XDG_DATA_HOME\n");
        return false;
    }

    const QString servicesDir = dataHome + "/dbus-1/services";
    const QString symlinkPath = servicesDir + "/org.gnome.keyring.SystemPrompter.service";

#ifdef KEYRING_SERVICE_FILE_PATH
    const QString sourcePath = KEYRING_SERVICE_FILE_PATH;
#else
    const QString sourcePath = "/usr/share/noctalia-polkit/org.gnome.keyring.SystemPrompter.service";
#endif

    // Create parent directories
    if (!QDir().mkpath(servicesDir)) {
        std::print(stderr, "Failed to create directory: {}\n", servicesDir.toStdString());
        return false;
    }

    // Check if source file exists
    if (!QFile::exists(sourcePath)) {
        std::print(stderr, "Keyring service file not found: {}\n", sourcePath.toStdString());
        return false;
    }

    // Check existing symlink
    if (QFile::exists(symlinkPath)) {
        QString existingTarget = QFile::symLinkTarget(symlinkPath);
        if (existingTarget == sourcePath) {
            std::print("Keyring service symlink already configured\n");
            return true;
        }
        // Remove stale symlink/file
        if (!QFile::remove(symlinkPath)) {
            std::print(stderr, "Failed to remove stale symlink: {}\n", symlinkPath.toStdString());
            return false;
        }
    }

    // Create symlink
    if (!QFile::link(sourcePath, symlinkPath)) {
        std::print(stderr, "Failed to create symlink: {} -> {}\n",
                   symlinkPath.toStdString(), sourcePath.toStdString());
        return false;
    }

    std::print("Created keyring service symlink: {} -> {}\n",
               symlinkPath.toStdString(), sourcePath.toStdString());
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
    event["type"]                 = "request";
    event["source"]               = "polkit";
    event["id"]                   = listener.session.cookie;
    event["actionId"]             = listener.session.actionId;
    event["message"]              = listener.session.message;
    event["icon"]                 = listener.session.iconName;
    event["user"]                 = listener.session.selectedUser.toString();
    event["prompt"]               = listener.session.prompt;
    event["echo"]                 = listener.session.echoOn;
    event["fingerprintAvailable"] = fingerprintAvailable;

    QJsonObject details;
    const auto  keys = listener.session.details.keys();
    for (const auto& key : keys) {
        details.insert(key, listener.session.details.lookup(key));
    }
    event["details"] = details;

    if (!listener.session.errorText.isEmpty())
        event["error"] = listener.session.errorText;

    return event;
}

QJsonObject CAgent::buildKeyringRequestEvent(const KeyringRequest& req) const {
    QJsonObject event;
    event["type"]                 = "request";
    event["source"]               = "keyring";
    event["id"]                   = req.cookie;
    event["message"]              = req.title;
    event["prompt"]               = req.message;
    event["echo"]                 = false;
    event["passwordNew"]          = req.passwordNew;
    event["confirmOnly"]          = req.confirmOnly;
    event["fingerprintAvailable"] = fingerprintAvailable;

    if (!req.description.isEmpty())
        event["description"] = req.description;

    return event;
}

void CAgent::enqueueRequest() {
    enqueueEvent(buildRequestEvent());
}

void CAgent::enqueueError(const QString& error) {
    QJsonObject event;
    event["type"]  = "update";
    event["id"]    = listener.session.cookie;
    event["error"] = error;
    enqueueEvent(event);
}

void CAgent::enqueueComplete(const QString& result) {
    QJsonObject event;
    event["type"]   = "complete";
    event["id"]     = listener.session.cookie;
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
        ipcSocketPath         = runtimeDir + "/noctalia-polkit-agent.sock";
    }

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

    // Try to listen without removing first (avoids TOCTOU race)
    if (!ipcServer->listen(ipcSocketPath)) {
        // If socket exists, check if it's stale by trying to connect
        QLocalSocket testSocket;
        testSocket.connectToServer(ipcSocketPath);
        if (!testSocket.waitForConnected(100)) {
            // Socket exists but no server - it's stale, safe to remove
            QLocalServer::removeServer(ipcSocketPath);
            if (!ipcServer->listen(ipcSocketPath)) {
                std::print(stderr, "IPC listen failed on {}: {}\n",
                           ipcSocketPath.toStdString(),
                           ipcServer->errorString().toStdString());
                return;
            }
        } else {
            // Another instance is running
            std::print(stderr, "Another noctalia-polkit instance is already running\n");
            return;
        }
    }

    std::print("IPC listening on {}\n", ipcSocketPath.toStdString());
}

void CAgent::handleSocket(QLocalSocket* socket, const QByteArray& data) {
    // Input validation: reject oversized messages
    constexpr qsizetype MAX_MESSAGE_SIZE = 64 * 1024; // 64KB
    if (data.size() > MAX_MESSAGE_SIZE) {
        std::print(stderr, "Rejected oversized message: {} bytes\n", data.size());
        socket->write("ERROR: message too large\n");
        socket->flush();
        socket->disconnectFromServer();
        return;
    }

    const QList<QByteArray> lines   = data.split('\n');
    const QString           command = QString::fromUtf8(lines.value(0)).trimmed();
    const QString           payload = QString::fromUtf8(lines.value(1)).trimmed();

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
            const auto json  = QJsonDocument(event).toJson(QJsonDocument::Compact);
            socket->write(json + "\n");
        }
        socket->flush();
        socket->disconnectFromServer();
        return;
    }

    // Handle keyring password requests
    if (command == "KEYRING_REQUEST") {
        handleKeyringRequest(socket, payload.toUtf8());
        // Don't disconnect - keep socket open for response
        return;
    }

    // Handle keyring confirm requests
    if (command == "KEYRING_CONFIRM") {
        handleKeyringConfirm(socket, payload.toUtf8());
        // Don't disconnect - keep socket open for response
        return;
    }

    if (command.startsWith("RESPOND ")) {
        const QString cookie = command.mid(QString("RESPOND ").length()).trimmed();

        // Check if this is a keyring request first
        if (pendingKeyringRequests.contains(cookie)) {
            respondToKeyringRequest(cookie, payload);
            socket->write("OK\n");
            socket->flush();
            socket->disconnectFromServer();
            return;
        }

        // Otherwise handle as polkit
        const bool ok = handleRespond(cookie, payload);
        socket->write(ok ? "OK\n" : "ERROR\n");
        socket->flush();
        socket->disconnectFromServer();
        return;
    }

    if (command.startsWith("CANCEL ")) {
        const QString cookie = command.mid(QString("CANCEL ").length()).trimmed();

        // Check if this is a keyring request first
        if (pendingKeyringRequests.contains(cookie)) {
            cancelKeyringRequest(cookie);
            socket->write("OK\n");
            socket->flush();
            socket->disconnectFromServer();
            return;
        }

        // Otherwise handle as polkit
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

void CAgent::handleKeyringRequest(QLocalSocket* socket, const QByteArray& payload) {
    QJsonParseError parseError;
    QJsonDocument   doc = QJsonDocument::fromJson(payload, &parseError);

    if (parseError.error != QJsonParseError::NoError) {
        std::print(stderr, "Keyring request JSON parse error: {}\n", parseError.errorString().toStdString());
        socket->write("ERROR\n");
        socket->flush();
        socket->disconnectFromServer();
        return;
    }

    QJsonObject obj = doc.object();

    KeyringRequest req;
    req.cookie      = obj["cookie"].toString();
    req.title       = obj["title"].toString();
    req.message     = obj["message"].toString();
    req.description = obj["description"].toString();
    req.passwordNew = obj["password_new"].toBool(false);
    req.confirmOnly = false;
    req.replySocket = socket;

    if (req.cookie.isEmpty()) {
        std::print(stderr, "Keyring request missing cookie\n");
        socket->write("ERROR\n");
        socket->flush();
        socket->disconnectFromServer();
        return;
    }

    std::print("Keyring request received: cookie={} title={}\n", req.cookie.toStdString(), req.title.toStdString());

    pendingKeyringRequests[req.cookie] = req;

    // Enqueue event for UI
    enqueueEvent(buildKeyringRequestEvent(req));

    // Keep socket open - will respond when user enters password
    // The socket will be cleaned up when we respond or cancel
}

void CAgent::handleKeyringConfirm(QLocalSocket* socket, const QByteArray& payload) {
    QJsonParseError parseError;
    QJsonDocument   doc = QJsonDocument::fromJson(payload, &parseError);

    if (parseError.error != QJsonParseError::NoError) {
        std::print(stderr, "Keyring confirm JSON parse error: {}\n", parseError.errorString().toStdString());
        socket->write("ERROR\n");
        socket->flush();
        socket->disconnectFromServer();
        return;
    }

    QJsonObject obj = doc.object();

    KeyringRequest req;
    req.cookie      = obj["cookie"].toString();
    req.title       = obj["title"].toString();
    req.message     = obj["message"].toString();
    req.description = obj["description"].toString();
    req.passwordNew = false;
    req.confirmOnly = true;
    req.replySocket = socket;

    if (req.cookie.isEmpty()) {
        std::print(stderr, "Keyring confirm request missing cookie\n");
        socket->write("ERROR\n");
        socket->flush();
        socket->disconnectFromServer();
        return;
    }

    std::print("Keyring confirm request received: cookie={}\n", req.cookie.toStdString());

    pendingKeyringRequests[req.cookie] = req;

    // Enqueue event for UI
    enqueueEvent(buildKeyringRequestEvent(req));

    // Keep socket open for response
}

void CAgent::respondToKeyringRequest(const QString& cookie, const QString& password) {
    if (!pendingKeyringRequests.contains(cookie)) {
        std::print(stderr, "Keyring respond: unknown cookie {}\n", cookie.toStdString());
        return;
    }

    KeyringRequest req = pendingKeyringRequests.take(cookie);

    std::print("Responding to keyring request: cookie={}\n", cookie.toStdString());

    if (req.replySocket && req.replySocket->isOpen()) {
        if (req.confirmOnly) {
            req.replySocket->write("CONFIRMED\n");
        } else {
            QByteArray response = "OK\n" + password.toUtf8() + "\n";
            req.replySocket->write(response);
            // Securely zero password data after sending
            secureZero(response.data(), response.size());
        }
        req.replySocket->flush();
        req.replySocket->disconnectFromServer();
    }

    // Notify UI that the request is complete
    QJsonObject event;
    event["type"]   = "complete";
    event["id"]     = cookie;
    event["result"] = "success";
    enqueueEvent(event);
}

void CAgent::cancelKeyringRequest(const QString& cookie) {
    if (!pendingKeyringRequests.contains(cookie)) {
        std::print(stderr, "Keyring cancel: unknown cookie {}\n", cookie.toStdString());
        return;
    }

    KeyringRequest req = pendingKeyringRequests.take(cookie);

    std::print("Cancelling keyring request: cookie={}\n", cookie.toStdString());

    if (req.replySocket && req.replySocket->isOpen()) {
        req.replySocket->write("CANCEL\n");
        req.replySocket->flush();
        req.replySocket->disconnectFromServer();
    }

    // Notify UI that the request is complete (cancelled)
    QJsonObject event;
    event["type"]   = "complete";
    event["id"]     = cookie;
    event["result"] = "cancelled";
    enqueueEvent(event);
}
