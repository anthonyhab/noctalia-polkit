#pragma once

#include <QCoreApplication>
#include <QDBusInterface>
#include <QHash>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLocalServer>
#include <QLocalSocket>
#include <QQueue>
#include <QString>

#include "PolkitListener.hpp"
#include <polkitqt1-subject.h>

#include <memory>

class CAgent {
  public:
    CAgent();
    ~CAgent();

    void resetAuthState();
    bool start(QCoreApplication& app, const QString& socketPath);
    void initAuthPrompt();
    void enqueueRequest();
    void enqueueError(const QString& error);
    void enqueueComplete(const QString& result);
    bool handleRespond(const QString& cookie, const QString& password);
    bool handleCancel(const QString& cookie);

  private:
    struct {
        bool authing = false;
    } authState;

    // Keyring request tracking
    struct KeyringRequest {
        QString       cookie;
        QString       title;
        QString       message;
        QString       description;
        bool          passwordNew  = false;
        bool          confirmOnly  = false;
        QLocalSocket* replySocket  = nullptr;
    };

    QHash<QString, KeyringRequest> pendingKeyringRequests;

    CPolkitListener                                listener;
    std::shared_ptr<PolkitQt1::UnixSessionSubject> sessionSubject;

    QLocalServer*                     ipcServer = nullptr;
    QQueue<QJsonObject>               eventQueue;
    QString                           ipcSocketPath;
    bool                              fingerprintAvailable = false;

    void        setupIpcServer();
    bool        checkFingerprintAvailable();
    void        handleSocket(QLocalSocket* socket, const QByteArray& data);
    void        enqueueEvent(const QJsonObject& event);
    QJsonObject buildRequestEvent() const;
    QJsonObject buildKeyringRequestEvent(const KeyringRequest& req) const;

    // Keyring request handlers
    void handleKeyringRequest(QLocalSocket* socket, const QByteArray& payload);
    void handleKeyringConfirm(QLocalSocket* socket, const QByteArray& payload);
    void respondToKeyringRequest(const QString& cookie, const QString& password);
    void cancelKeyringRequest(const QString& cookie);

    friend class CPolkitListener;
};

inline std::unique_ptr<CAgent> g_pAgent;
