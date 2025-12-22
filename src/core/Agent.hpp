#pragma once

#include <QCoreApplication>
#include <QJsonObject>
#include <QLocalServer>
#include <QLocalSocket>
#include <QQueue>
#include <QString>

#include "PolkitListener.hpp"
#include <polkitqt1-subject.h>

#include <hyprutils/memory/WeakPtr.hpp>
using namespace Hyprutils::Memory;
#define SP CSharedPointer
#define WP CWeakPointer

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

    CPolkitListener                   listener;
    SP<PolkitQt1::UnixSessionSubject> sessionSubject;

    QLocalServer*                     ipcServer = nullptr;
    QQueue<QJsonObject>               eventQueue;
    QString                           ipcSocketPath;

    void setupIpcServer();
    void handleSocket(QLocalSocket* socket, const QByteArray& data);
    void enqueueEvent(const QJsonObject& event);
    QJsonObject buildRequestEvent() const;

    friend class CPolkitListener;
};

inline std::unique_ptr<CAgent> g_pAgent;
