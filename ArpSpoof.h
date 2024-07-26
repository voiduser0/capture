#pragma once

#include <QMutex>
#include <QObject>
#include <WinSock2.h>

#include "pcap.h"
#include "Header.h"


class ArpSpoof  : public QObject
{
	Q_OBJECT

public:
	ArpSpoof(QObject *parent = nullptr);
	~ArpSpoof();

	void StartArpSpoof(const QString &nicName, const QString &spoofDstIpStr, 
		const QString spoofDstMacStr, const QString spoofIpStr, const QString spoofMacStr);

private:
	bool m_keepSend{};
	QByteArray m_packet{};
	QMutex m_mutex;
	QString m_nicName{};
	pcap_t *m_fp{};

public:
	void SetKeepSend(bool keepSend);

signals:
	void SendText(const QString &text);
};
