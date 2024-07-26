#pragma once

#include <array>
#include <QTimer>
#include <QVector>
#include <QThread>
#include <QWidget>
#include <QTreeView>
#include <QStandardItem>
#include <QStandardItemModel>

#include "Header.h"
#include "ArpSpoof.h"
#include "ReadOnlyDelegate.h"
#include "ui_CreateFakePacket.h"

QT_BEGIN_NAMESPACE
namespace Ui { class CreateFakePacketClass; };
QT_END_NAMESPACE

class CreateFakePacket : public QWidget 
{
	Q_OBJECT

public:
	explicit CreateFakePacket(QWidget *parent = nullptr);
	~CreateFakePacket();

private:
	void InitScreen();

private:
	Ui::CreateFakePacketClass *ui;

	QTimer *m_timer{};
	QString m_nicName{};
	QByteArray m_pktArray{};
	std::array<bool, 6> m_flags{};		// eth, arp, ip, icmp, tcp, udp
	QVector<QStandardItem *> m_pktItemVec;
	QStandardItemModel *m_model;
	ReadOnlyDelegate *m_ReadOnlyDelegate{};
	ArpSpoof *m_spoof{};
	QThread *m_spoofThread{};

signals:
	void SendPkt(QByteArray &pktArray, bool &ok);
	void StartArpSpoofSignal(const QString &nicName, const QString &spoofDstIpStr, 
		const QString spoofDstMacStr, const QString spoofIpStr, const QString spoofMacStr);

private slots:
	void on_fakePktTree_clicked(const QModelIndex &index);
	void on_ethOkBtn_clicked();
	void on_arpOkBtn_clicked();
	void on_ipOkBtn_clicked();
	void on_icmpOkBtn_clicked();
	void on_tcpOkBtn_clicked();
	void on_udpOkBtn_clicked();
	void on_pktInfoOkBtn_clicked();
	void on_pktInfoCancelBtn_clicked();
	void on_spoofStartBtn_clicked();
	void on_spoofStopBtn_clicked();

public slots:
	void HandleRecvPktOk(const bool &ok);
	void SetText(const QString &text);
	void GetNicName(const QString &nicName);
};
