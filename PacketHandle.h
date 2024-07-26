#pragma once

#include <QThread>
#include <QObject>
#include <QMetaType>

#include "pcap.h"
#include "Header.h"
#include "GlobalFcn.h"
#include "DataPacket.h"

class PacketHandle :public QThread
{
	Q_OBJECT

	friend QString ToHex(const unsigned char *chs, const int size);

private:
	pcap_t *m_adHandle{};
	pcap_dumper_t **m_dumper{};
	struct pcap_pkthdr *m_pktHeader{};
	const u_char *m_pktData{};

	struct tm m_localTime {};
	char m_timeStr[16]{};
	time_t m_localTvSec{};

	bool m_isFinish{true};
	bool m_isDumper{};

public:
	PacketHandle(QThread *parent = nullptr);
	void SetAdHandle(pcap_t *adhandle);
	void SetDumper(pcap_dumper_t *&dumper);
	void SetFlag();
	void ResetFlag();

	int ethernetPktHandle(const u_char *pktData, QString &info);
	u_char ipPktHandle(const u_char *pktData, int &ipPayload);
	int arpPktHandle(const u_char *pktData, QString &info);
	int icmpPktHandle(const u_char *pktData, QString &info);
	int tcpPktHandle(const u_char *pktData, QString &info, const int &ipPayload);
	int udpPktHandle(const u_char *pktData, QString &info);
	QString dnsPktHandle(const u_char *pktData);
	void SetDumperState(bool isDumper);

protected:
	void run() Q_DECL_OVERRIDE;

signals:
	void SendData(const DataPacket &pktData);
};

