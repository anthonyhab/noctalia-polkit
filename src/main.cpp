#include "core/Agent.hpp"

#include <QCommandLineParser>
#include <QLocalSocket>
#include <QStandardPaths>
#include <QTextStream>

namespace {
QString defaultSocketPath() {
    const auto runtimeDir = QStandardPaths::writableLocation(QStandardPaths::RuntimeLocation);
    return runtimeDir + "/noctalia-polkit-agent.sock";
}

bool sendCommand(const QString& socketPath, const QString& command, const QString& payload, QString* response) {
    QLocalSocket socket;
    socket.connectToServer(socketPath);
    if (!socket.waitForConnected(1000))
        return false;

    QByteArray data = command.toUtf8();
    data.append("\n");
    if (!payload.isEmpty()) {
        data.append(payload.toUtf8());
        data.append("\n");
    }

    if (socket.write(data) == -1 || !socket.waitForBytesWritten(1000))
        return false;

    if (!socket.waitForReadyRead(1000))
        return false;

    const QByteArray reply = socket.readAll();
    if (response)
        *response = QString::fromUtf8(reply).trimmed();
    return true;
}
}

int main(int argc, char* argv[]) {
    QCoreApplication app(argc, argv);
    QCommandLineParser parser;
    parser.setApplicationDescription("Noctalia Polkit Agent (hyprpolkitagent fork)");
    parser.addHelpOption();

    QCommandLineOption optDaemon(QStringList{"daemon"}, "Run the polkit agent daemon.");
    QCommandLineOption optPing(QStringList{"ping"}, "Check if the daemon is reachable.");
    QCommandLineOption optNext(QStringList{"next"}, "Fetch the next pending request.");
    QCommandLineOption optRespond(QStringList{"respond"}, "Respond to a request (cookie).", "cookie");
    QCommandLineOption optCancel(QStringList{"cancel"}, "Cancel a request (cookie).", "cookie");
    QCommandLineOption optSocket(QStringList{"socket"}, "Override socket path.", "path");

    parser.addOption(optDaemon);
    parser.addOption(optPing);
    parser.addOption(optNext);
    parser.addOption(optRespond);
    parser.addOption(optCancel);
    parser.addOption(optSocket);

    parser.process(app);

    const QString socketPath = parser.isSet(optSocket) ? parser.value(optSocket) : defaultSocketPath();

    if (parser.isSet(optPing)) {
        QString response;
        const bool ok = sendCommand(socketPath, "PING", "", &response);
        return (ok && response == "PONG") ? 0 : 1;
    }

    if (parser.isSet(optNext)) {
        QString response;
        const bool ok = sendCommand(socketPath, "NEXT", "", &response);
        if (ok && !response.isEmpty())
            fprintf(stdout, "%s\n", response.toUtf8().constData());
        return ok ? 0 : 1;
    }

    if (parser.isSet(optRespond)) {
        const QString cookie = parser.value(optRespond);
        QTextStream stdinStream(stdin);
        const QString password = stdinStream.readLine();
        QString response;
        const bool ok = sendCommand(socketPath, "RESPOND " + cookie, password, &response);
        return (ok && response == "OK") ? 0 : 1;
    }

    if (parser.isSet(optCancel)) {
        const QString cookie = parser.value(optCancel);
        QString response;
        const bool ok = sendCommand(socketPath, "CANCEL " + cookie, "", &response);
        return (ok && response == "OK") ? 0 : 1;
    }

    g_pAgent = std::make_unique<CAgent>();
    return g_pAgent->start(app, socketPath) == false ? 1 : 0;
}
