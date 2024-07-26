#include "Header.h"
#include "DataPacket.h"
#include "PacketHandle.h"

PacketHandle::PacketHandle(QThread *parent)
	: QThread(parent)
{
}

void PacketHandle::SetAdHandle(pcap_t *adhandle)
{
	m_adHandle = adhandle;
}

void PacketHandle::SetDumper(pcap_dumper_t *&dumper)
{
	m_dumper = &dumper;
}

void PacketHandle::SetFlag()
{
	m_isFinish = false;
}

void PacketHandle::ResetFlag()
{
	m_isFinish = true;
}

void PacketHandle::SetDumperState(bool isDumper)
{
	m_isDumper = isDumper;
}

void PacketHandle::run()
{
	while (1)
	{
		if (m_isFinish)
			break;

		// pcap_next_ex() 用于从已打开的网络设备中读取下一个数据包的函数。
		if (int res; (res = pcap_next_ex(m_adHandle, &m_pktHeader, &m_pktData)) < 0)
			break;
		else if (!res)				// res为0，则 pcap_open_live() 设置的时间超时。未捕获到数据包
			continue;
		
		m_localTvSec = m_pktHeader->ts.tv_sec;  // 获取数据包的时间戳（秒部分）
		localtime_s(&m_localTime, &m_localTvSec);  // 将时间戳转换为本地时间
		strftime(m_timeStr, sizeof(m_timeStr), "%H:%M:%S", &m_localTime); // 将本地时间格式化为字符串
		QString Info{};
		int pktHandleType{ ethernetPktHandle(m_pktData, Info) };
		if (pktHandleType)
		{
			u_int pktLen = m_pktHeader->len;
			DataPacket pktData(pktLen, m_timeStr, pktHandleType, Info, m_pktData, pktLen);
			if (!m_isDumper)
				pcap_dump((u_char *)(*m_dumper), m_pktHeader, m_pktData);
			emit SendData(pktData);
		}
	}
}

int PacketHandle::ethernetPktHandle(const u_char *pktData, QString &info)
{
	ethernet_header *ethHeader{ (ethernet_header *)(pktData) };
	u_short typeField{ ntohs(ethHeader->type) };			// ntohs() 网络字节顺序（大端） -> 主机字节顺序

	switch (typeField)
	{
	case 0x0800:
	{			// ip
		int ipPayload{};
		u_char protocol_type{ ipPktHandle(pktData, ipPayload) };		// ipPayload获取ip载荷。并且返回传输层地址或协议号
		switch (protocol_type)
		{
		case 1:			// ICMP
		{
			return icmpPktHandle(pktData, info);
		}
		case 6:					// TCP
			return tcpPktHandle(pktData, info, ipPayload);
		case 17:				// UDP
			return udpPktHandle(pktData, info);
		default:
			break;
		}
		break;
	}
	case 0x0806:
	{			// ARP
		return arpPktHandle(pktData, info);
	}
	default:
		break;
	}
	return 0;
}

u_char PacketHandle::ipPktHandle(const u_char *pktData, int &ipPayload)
{
	ip_header *ipHeader{ (ip_header *)(pktData + 14) };
	ipPayload = ntohs(ipHeader->total_length) -
		((ipHeader->head_length & 0x0F) * 4);
	return ipHeader->protocol;
}

int PacketHandle::tcpPktHandle(const u_char *pktData, QString &info, const int &ipPayload)
{
	tcp_header *tcpHeader{ (tcp_header *)(pktData + 14 + 20) };

	info += QString::number(ntohs(tcpHeader->src_port)) +
		QStringLiteral(" -> ") + QString::number(ntohs(tcpHeader->des_port));

	QString flags{};

	if (tcpHeader->flags & 0x01) flags += QStringLiteral("FIN, ");
	if (tcpHeader->flags & 0x02) flags += QStringLiteral("SYN, ");
	if (tcpHeader->flags & 0x04) flags += QStringLiteral("RST, ");
	if (tcpHeader->flags & 0x08) flags += QStringLiteral("PSH, ");
	if (tcpHeader->flags & 0x10) flags += QStringLiteral("ACK, ");
	if (tcpHeader->flags & 0x20) flags += QStringLiteral("URG, ");
	if (tcpHeader->flags & 0x40) flags += QStringLiteral("ECE, ");
	if (tcpHeader->flags & 0x80) flags += QStringLiteral("CWR, ");
	if (tcpHeader->header_length & 0x01) flags += QStringLiteral("AECN, ");
	if (flags != "")
	{
		flags = flags.left(flags.size() - 2);
		info += " [" + flags + "]";
	}

	int tcpPayload{ ipPayload - ((tcpHeader->header_length >> 4) & 0x0F) * 4 };

	info += QStringLiteral(" Seq=") + QString::number(ntohl(tcpHeader->seq)) +
		QStringLiteral(" Ack=") + QString::number(ntohl(tcpHeader->ack)) +
		QStringLiteral(" Win=") + QString::number(ntohs(tcpHeader->window_size)) +
		QStringLiteral(" Len=") + QString::number(tcpPayload);

	return static_cast<int>(EProtocolType::TCP);
}

int PacketHandle::udpPktHandle(const u_char *pktData, QString &info)
{
	udp_header *udpHeader{ (udp_header *)(pktData + 14 + 20) };
	u_short src_port{ ntohs(udpHeader->src_port) };
	u_short des_port{ ntohs(udpHeader->des_port) };
	if (src_port == 53 || des_port == 53)
	{
		info = dnsPktHandle(pktData);
		return static_cast<int>(EProtocolType::DNS);
	}

	info += QString::number(src_port) + "->" + QString::number(des_port);
	info += " len=" + QString::number(ntohs(udpHeader->data_length) - 8);

	return static_cast<int>(EProtocolType::UDP);
}

QString PacketHandle::dnsPktHandle(const u_char *pktData)
{
	dns_header *dnsHeader{ (dns_header *)(pktData + 14 + 20 + 8) };
	u_short identification{ ntohs(dnsHeader->identification) };
	u_short flags{ ntohs(dnsHeader->flags) };
	QString info{};

	if ((flags & 0xf800) == 0x0000)
		info = QStringLiteral("Standard query ");
	else if ((flags & 0xf800) == 0x8000)
		info = QStringLiteral("Standard query response ");

	u_char *pDnsData{ (u_char *)(pktData + 14 + 20 + 8 + 12) };
	QString name{};
	while (pDnsData && *pDnsData > 0 && *pDnsData <= 64)
	{
		int sectionLen = *pDnsData++;
		for (int i{}; i != sectionLen; ++i)
		{
			name += *pDnsData++;
		}
		name += ".";
	}
	name = name.left(name.size() - 1);
	info += "0x" + QString::number(identification, 16) + " " + name;
	return info;
}

int PacketHandle::arpPktHandle(const u_char *pktData, QString &info)
{
	arp_header *arpHeader{ (arp_header *)(pktData + 14) };

	u_char *pSrcIp{ arpHeader->src_ip };
	QString srcIp{
		QString::number(*pSrcIp) + '.' +
		QString::number(*(pSrcIp + 1)) + "." +
		QString::number(*(pSrcIp + 2)) + "." +
		QString::number(*(pSrcIp + 3))
	};

	u_char *pDesIp{ arpHeader->des_ip };
	QString desIp{
		QString::number(*pDesIp) + '.' +
		QString::number(*(pDesIp + 1)) + "." +
		QString::number(*(pDesIp + 2)) + "." +
		QString::number(*(pDesIp + 3))
	};

	u_char *pSrcMac{ arpHeader->src_mac };

	QString srcMac{
		ToHex(pSrcMac) + ":" +
		ToHex(pSrcMac + 1) + ":" +
		ToHex(pSrcMac + 2) + ":" +
		ToHex(pSrcMac + 3) + ":" +
		ToHex(pSrcMac + 4) + ":" +
		ToHex(pSrcMac + 5)
	};

	u_short opCode = ntohs(arpHeader->op_code);
	if (opCode == 1)
		info = "Who has " + desIp + "? Tell " + srcIp;
	else
		info = srcIp + " is at " + srcMac;
	return static_cast<int>(EProtocolType::ARP);
}

int PacketHandle::icmpPktHandle(const u_char *pktData, QString &info)
{
	icmp_header *icmpHeader{ (icmp_header *)(pktData + 14 + 20) };
	u_char type{ icmpHeader->type };
	u_char code{ icmpHeader->code };

	switch (type)
	{
	case 0:
		if (code == 0)
			info = QStringLiteral("Echo (ping) reply");
		break;
	case  3:
	{
		switch (code)
		{
		case 0:
			info = QStringLiteral("Destination network unreachable");
			break;
		case 1:
			info = QStringLiteral("	Destination host unreachable");
			break;
		case 2:
			info = QStringLiteral("Destination protocol unreachable");
			break;
		case 3:
			info = QStringLiteral("Destination port unreachable");
			break;
		case 6:
			info = QStringLiteral("Destination network unknown");
			break;
		case 7:
			info = QStringLiteral("Destination host unreachable");
			break;
		default:
			break;
		}
		break;
	}
	case 4:
		if (code == 0)
			info = QStringLiteral("Source quench (congestion control)");
		break;
	case 8:
		if (code == 0)
			info = QStringLiteral("Echo (ping) request");
		break;
	case 9:
		if (code == 0)
			info = QStringLiteral("Router Advertisement");
		break;
	case 10:
		if (code == 0)
			info = QStringLiteral("Router discovery/selection/solicitation");
		break;
	case 11:
		if (code == 0)
			info = QStringLiteral("TTL expired in transit");
		break;
	case 12:
		if (code == 0)
			info = QStringLiteral("Pointer indicates the error");
		break;
	default:
		break;
	}
	return static_cast<int>(EProtocolType::ICMP);
}
