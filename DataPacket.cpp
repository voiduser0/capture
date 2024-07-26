#include <QMetaType>
#include <WinSock2.h>

#include "DataPacket.h"

DataPacket::DataPacket()
	:DataPacket(0, "", 0, "", Q_NULLPTR, 0)
{
}

DataPacket::DataPacket(const u_char *pktData, const u_int len)
	:DataPacket(0, "", 0, "", pktData, len)
{
}

DataPacket::DataPacket(const u_int length, const QString timeStamp, const int protocolType, 
	const QString info, const u_char *pktData, const u_int len)
	:m_length(length), m_timeStamp(timeStamp), m_protocolType(protocolType), m_info(info)
{
	qRegisterMetaType<DataPacket>("DataPacket");
	if (len != 0)
	{
		m_pktData = new u_char[len];
		if (m_pktData != Q_NULLPTR)
			memcpy((u_char *)m_pktData, pktData, len);
	}
}

void DataPacket::SetLength(const u_int length)
{
	m_length = length;
}

void DataPacket::SetTimeStamp(const QString timeStamp)
{
	m_timeStamp = timeStamp;
}

void DataPacket::SetProtocolType(const int protocol)
{
	m_protocolType = protocol;
}

void DataPacket::SetInfo(const QString info)
{
	m_info = info;
}

void DataPacket::SetPktData(const u_char *pktData, const u_int len)
{
	m_pktData = new u_char[len];
	if (m_pktData != Q_NULLPTR)
		memcpy((u_char *)m_pktData, pktData, len);
}

QString DataPacket::GetLength() const
{
	return QString::number(m_length);
}

QString DataPacket::GetTimeStamp() const
{
	return m_timeStamp;
}

QString DataPacket::GetProtocolType() const
{
	switch (m_protocolType)
	{
	case 1:
		return QStringLiteral("ARP");
	case 2:
		return QStringLiteral("ICMP");
	case 3:
		return QStringLiteral("TCP");
	case 4:
		return QStringLiteral("UDP");
	case 5:
		return QStringLiteral("DNS");
	default:
		return "";
	}
}

QString DataPacket::GetInfo() const
{
	return m_info;
}

QString DataPacket::GetSrcAddr() const
{
	if (m_protocolType == static_cast<int>(EProtocolType::ARP))
		return GetEthSrcMac();
	else
		return GetIpSrcIp();
}

QString DataPacket::GetDesAddr() const
{
	if (m_protocolType == static_cast<int>(EProtocolType::ARP))
		return GetEthDesMac();
	else
		return GetIpDesIp();
}

QString DataPacket::GetMacInfo(const u_char *mac) const
{
	return ToHex(mac, 1) + ":" +
		ToHex((mac + 1), 1) + ":" +
		ToHex((mac + 2), 1) + ":" +
		ToHex((mac + 3), 1) + ":" +
		ToHex((mac + 4), 1) + ":" +
		ToHex((mac + 5), 1);
}

QString DataPacket::GetEthSrcMac() const
{
	ethernet_header *ethHeader{ (ethernet_header *)(m_pktData) };
	u_char *pSrcMac{ ethHeader->src_mac };
	QString scrMac{GetMacInfo(pSrcMac)};
	return scrMac == QStringLiteral("FF:FF:FF:FF:FF:FF") ? 
		QStringLiteral("FF:FF:FF:FF:FF:FF(Broadcast)") : scrMac;
}

QString DataPacket::GetEthDesMac() const
{
	ethernet_header *ethHeader{ (ethernet_header *)(m_pktData) };
	u_char *pDesMac{ ethHeader->des_mac };
	QString desMac{ GetMacInfo(pDesMac)};
	return desMac == QStringLiteral("FF:FF:FF:FF:FF:FF") ?
		QStringLiteral("FF:FF:FF:FF:FF:FF(Broadcast)") : desMac;
}

QString DataPacket::GetEthType() const
{
	ethernet_header *ethHeader{ (ethernet_header *)(m_pktData) };
	u_short type{ ntohs(ethHeader->type) };
	QString res{};
	if (type == 0x0800)
		res = QStringLiteral("IPv4(0x0800)");
	else if (type == 0x0806)
		res = QStringLiteral("ARP(0x0806)");
	return res;
}

QString DataPacket::GetArpHardewareType() const
{
	arp_header *arpHeader{ (arp_header *)(m_pktData + 14) };
	u_short hType{ ntohs(arpHeader->hardware_type) };
	QString res{};

	if (hType == 0x0001)
		res = QStringLiteral("Ethernet (1)");
	return res;
}

QString DataPacket::GetArpProtocolType() const
{
	arp_header *arpHeader{ (arp_header *)(m_pktData + 14) };
	u_short pType{ ntohs(arpHeader->protocol_type) };
	QString res{};
	if (pType == 0x0800)
		res = QStringLiteral("IPv4 (0x0800)");
	return res;
}

QString DataPacket::GetArpMacLength() const
{
	arp_header *arpHeader{ (arp_header *)(m_pktData + 14) };
	u_char macLength{ arpHeader->mac_length };
	return QString::number(macLength);
}

QString DataPacket::GetArpIpLength() const
{
	arp_header *arpHeader{ (arp_header *)(m_pktData + 14) };
	u_char ipLength{ arpHeader->ip_length };
	return QString::number(ipLength);
}

QString DataPacket::GetArpOperationCode() const
{
	arp_header *arpHeader{ (arp_header *)(m_pktData + 14) };
	u_short opCode{ ntohs(arpHeader->op_code) };
	QString res{};

	if (opCode == 0x0001)
		res = QStringLiteral("request");
	else if (opCode == 0x0002)
		res = QStringLiteral("reply");
	return res;
}

QString DataPacket::GetArpSourceMac() const
{
	arp_header *arpHeader{ (arp_header *)(m_pktData + 14) };
	u_char *pSrcMac{ arpHeader->src_mac };
	QString srcMac{ GetMacInfo(pSrcMac)};
	return srcMac;
}

QString DataPacket::GetIpInfo(const u_char *ip) const
{
	return 	QString::number(*ip) + "." +
		QString::number(*(ip + 1)) + "." +
		QString::number(*(ip + 2)) + "." +
		QString::number(*(ip + 3));
}

QString DataPacket::GetArpSourceIp() const
{
	arp_header *arpHeader{ (arp_header *)(m_pktData + 14) };
	u_char *pSrcIp{ arpHeader->src_ip };
	QString srcIp{GetIpInfo(pSrcIp)};
	return srcIp;
}

QString DataPacket::GetArpDestinationMac() const
{
	arp_header *arpHeader{ (arp_header *)(m_pktData + 14) };
	u_char *pDesMac{ arpHeader->des_mac };
	QString desMac{ GetMacInfo(pDesMac)};
	return desMac;
}

QString DataPacket::GetArpDestinationIp() const
{
	arp_header *arpHeader{ (arp_header *)(m_pktData + 14) };
	u_char *pDesIp{ arpHeader->des_ip };
	QString desIp{ GetIpInfo(pDesIp)};
	return desIp;
}

QString DataPacket::GetIpVersion() const
{
	ip_header *ipHeader{ (ip_header *)(m_pktData + 14) };
	u_char version{ ipHeader->version };
	return QString::number((version) & 0x0F);
}

QString DataPacket::GetIpHeadlength(QString &info) const
{
	ip_header *ipHeader{ (ip_header *)(m_pktData + 14) };
	u_char headLength{ ipHeader->head_length };
	int len{ (headLength & 0x0F) };
	if (20 <= len * 4 && len * 4 <= 60)
		info = QString::number(len * 4) + " bytes (" + QString::number(len) + ")";
	return QString::number(len);
}

QString DataPacket::GetIpServiceType() const
{
	ip_header *ipHeader{ (ip_header *)(m_pktData + 14) };
	u_char tos{ ipHeader->TOS };
	return QString::number(tos, 16);
}

QString DataPacket::GetIpTotalLength() const
{
	ip_header *ipHeader{ (ip_header *)(m_pktData + 14) };
	u_short totalLength{ ntohs(ipHeader->total_length) };
	return QString::number(totalLength);
}

QString DataPacket::GetIpIdentification() const
{
	ip_header *ipHeader{ (ip_header *)(m_pktData + 14) };
	u_short id{ ntohs(ipHeader->identification) };
	return QString::number(id, 16);
}

QString DataPacket::GetIpFlags() const
{
	ip_header *ipHeader{ (ip_header *)(m_pktData + 14) };
	u_short flag{ ntohs(ipHeader->flag_offset) };
	return QString::number((flag >> 13) & 0x0007, 16);
}

QString DataPacket::GetIpFlagsReservedBit() const
{
	ip_header *ipHeader{ (ip_header *)(m_pktData + 14) };
	u_short flag{ ntohs(ipHeader->flag_offset) };
	return QString::number((flag >> 15) & 0x0001);
}

QString DataPacket::GetIpFlagsDF() const
{
	ip_header *ipHeader{ (ip_header *)(m_pktData + 14) };
	u_short flag{ ntohs(ipHeader->flag_offset) };
	return QString::number((flag >> 14) & 0x0001);
}

QString DataPacket::GetIpFlagsMF() const
{
	ip_header *ipHeader{ (ip_header *)(m_pktData + 14) };
	u_short flag{ ntohs(ipHeader->flag_offset) };
	return QString::number((flag >> 13) & 0x0001);
}

QString DataPacket::GetIpOffset() const
{
	ip_header *ipHeader{ (ip_header *)(m_pktData + 14) };
	u_short offset{ ntohs(ipHeader->flag_offset) };
	return QString::number((offset & 0x1FFF));
}

QString DataPacket::GetIpTTL() const
{
	ip_header *ipHeader{ (ip_header *)(m_pktData + 14) };
	u_char ttl{ ipHeader->ttl };
	return QString::number(ttl);
}

QString DataPacket::GetIpProtocol() const
{
	ip_header *ipHeader{ (ip_header *)(m_pktData + 14) };
	u_char protocol{ ipHeader->protocol };
	QString res{};
	switch (protocol)
	{
	case 1:
		res = QStringLiteral("ICMP (1)");
		break;
	case 6:
		res = QStringLiteral("TCP (6)");
		break;
	case 17:
		res = QStringLiteral("UDP (17)");
		break;
	default:
		break;
	}
	return res;
}

QString DataPacket::GetIpChecksum() const
{
	ip_header *ipHeader{ (ip_header *)(m_pktData + 14) };
	u_short checksum{ ntohs(ipHeader->checksum) };
	return QString::number(checksum, 16);
}

QString DataPacket::GetIpSrcIp() const
{
	ip_header *ipHeader{ (ip_header *)(m_pktData + 14) };
	sockaddr_in srcIp;
	srcIp.sin_addr.s_addr = ipHeader->src_ip_addr;
	return QString(inet_ntoa(srcIp.sin_addr));
}

QString DataPacket::GetIpDesIp() const
{
	ip_header *ipHeader{ (ip_header *)(m_pktData + 14) };
	sockaddr_in desIp;
	desIp.sin_addr.s_addr = ipHeader->des_ip_addr;
	// 这行代码从 IP_HEADER 结构体 (ip) 中提取目的 IP 地址并将其存储在 desAddr.sin_addr.s_addr 中。
	// des_addr 是 IP_HEADER 结构体的一个成员，通常表示目的 IP 地址。 
	// sin_addr 是 sockaddr_in 结构体的一个成员，包含一个 s_addr 字段，用于存储 IP 地址值 (32 位无符号整数)。

	return QString(inet_ntoa(desIp.sin_addr));
	// inet_ntoa 是一个函数，用于将网络字节序的 IP 地址(32 位无符号整数) 
	// 转换为可读的字符串格式(点分十进制表示法，例如 "192.168.1.1")。
	//	desAddr.sin_addr 传递给 inet_ntoa 函数，将目的 IP 地址转换为字符串。
	//	最后，该字符串通过 QString 构造函数转换为 Qt 的字符串类型 QString 并返回。
}



QString DataPacket::GetIcmpType() const
{
	icmp_header *icmpHeader{ (icmp_header *)(m_pktData + 14 + 20) };
	u_char type{ icmpHeader->type };
	return QString::number(type);
}

QString DataPacket::GetIcmpCode() const
{
	icmp_header *icmpHeader{ (icmp_header *)(m_pktData + 14 + 20) };
	u_char code{ icmpHeader->code };
	return QString::number(code);
}

QString DataPacket::GetIcmpChecksum() const
{
	icmp_header *icmpHeader{ (icmp_header *)(m_pktData + 14 + 20) };
	u_short checksum{ ntohs(icmpHeader->checksum) };
	return QString::number(checksum, 16);
}

QString DataPacket::GetIcmpIdentification() const
{
	icmp_header *icmpHeader{ (icmp_header *)(m_pktData + 14 + 20) };
	u_short id{ ntohs(icmpHeader->identification) };
	return QString::number(id);
}

QString DataPacket::GetIcmpSequence() const
{
	icmp_header *icmpHeader{ (icmp_header *)(m_pktData + 14 + 20) };
	u_short seq{ ntohs(icmpHeader->sequence) };
	return QString::number(seq);
}

QString DataPacket::GetIcmpData(const int size) const
{
	u_char *icmpData{ (u_char *)(m_pktData + 14 + 20 + 8) };
	QString res{};
	for (int i{}; i != size; ++i)
	{
		res += *icmpData;
		++icmpData;
	}
	return res;
}

QString DataPacket::GetTcpSrcPort() const
{
	tcp_header *tcpHeader{ (tcp_header *)(m_pktData + 14 + 20) };
	u_short srcPort{ ntohs(tcpHeader->src_port) };
	return QString::number(srcPort);
}

QString DataPacket::GetTcpDesPort() const
{
	tcp_header *tcpHeader{ (tcp_header *)(m_pktData + 14 + 20) };
	u_short desPort{ ntohs(tcpHeader->des_port) };
	return QString::number(desPort);
}

QString DataPacket::GetTcpSeq() const
{
	tcp_header *tcpHeader{ (tcp_header *)(m_pktData + 14 + 20) };
	u_int seq{ ntohl(tcpHeader->seq) };
	return QString::number(seq);
}

QString DataPacket::GetTcpAck() const
{
	tcp_header *tcpHeader{ (tcp_header *)(m_pktData + 14 + 20) };
	u_int ack{ ntohl(tcpHeader->ack) };
	return QString::number(ack);
}

QString DataPacket::GetTcpHeaderLength(QString &info) const
{
	tcp_header *tcpHeader{ (tcp_header *)(m_pktData + 14 + 20) };
	int len{ tcpHeader->header_length >> 4 };
	if (20 <= len * 4 && len <= 60)
		info = QString::number(len * 4) + " bytes (" + QString::number(len) + ")";
	return QString::number(len);
}

QString DataPacket::GetTcpFlags() const
{
	tcp_header *tcpHeader{ (tcp_header *)(m_pktData + 14 + 20) };
	u_char flags{ tcpHeader->flags };
	return QString::number(flags, 16);
}

QString DataPacket::GetTcpFlagsFIN() const
{
	tcp_header *tcpHeader{ (tcp_header *)(m_pktData + 14 + 20) };
	u_char	fin{ tcpHeader->flags };
	return QString::number((fin & 0x01));
}

QString DataPacket::GetTcpFlagsSYN() const
{
	tcp_header *tcpHeader{ (tcp_header *)(m_pktData + 14 + 20) };
	u_char	syn{ tcpHeader->flags };
	return QString::number((syn >> 1) & 0x01);
}

QString DataPacket::GetTcpFlagsRST() const
{
	tcp_header *tcpHeader{ (tcp_header *)(m_pktData + 14 + 20) };
	u_char	rst{ tcpHeader->flags };
	return QString::number((rst >> 2) & 0x01);
}

QString DataPacket::GetTcpFlagsPSH() const
{
	tcp_header *tcpHeader{ (tcp_header *)(m_pktData + 14 + 20) };
	u_char	psh{ tcpHeader->flags };
	return QString::number((psh >> 3) & 0x01);
}

QString DataPacket::GetTcpFlagsACK() const
{
	tcp_header *tcpHeader{ (tcp_header *)(m_pktData + 14 + 20) };
	u_char	ack{ tcpHeader->flags };
	return QString::number((ack >> 4) & 0x01);
}

QString DataPacket::GetTcpFlagsURG() const
{
	tcp_header *tcpHeader{ (tcp_header *)(m_pktData + 14 + 20) };
	u_char	urg{ tcpHeader->flags };
	return QString::number((urg >> 5) & 0x01);
}

QString DataPacket::GetTcpFlagsECE() const
{
	tcp_header *tcpHeader{ (tcp_header *)(m_pktData + 14 + 20) };
	u_char	ece{ tcpHeader->flags };
	return QString::number((ece >> 6) & 0x01);
}

QString DataPacket::GetTcpFlagsCWR() const
{
	tcp_header *tcpHeader{ (tcp_header *)(m_pktData + 14 + 20) };
	u_char	cwr{ tcpHeader->flags };
	return QString::number((cwr >> 7) & 0x01);
}

QString DataPacket::GetTcpFlagsAECN() const
{
	tcp_header *tcpHeader{ (tcp_header *)(m_pktData + 14 + 20) };
	u_char	aecn{ tcpHeader->header_length };
	return QString::number(aecn & 0x01);
}

QString DataPacket::GetTcpWinSize() const
{
	tcp_header *tcpHeader{ (tcp_header *)(m_pktData + 14 + 20) };
	u_short winSize{ ntohs(tcpHeader->window_size) };
	return QString::number(winSize);
}

QString DataPacket::GetTcpChecksum() const
{
	tcp_header *tcpHeader{ (tcp_header *)(m_pktData + 14 + 20) };
	u_short checksum{ ntohs(tcpHeader->checksum) };
	return QString::number(checksum, 16);
}

QString DataPacket::GetTcpUrgent() const
{
	tcp_header *tcpHeader{ (tcp_header *)(m_pktData + 14 + 20) };
	u_short urgent{ ntohs(tcpHeader->urgent) };
	return QString::number(urgent);
}

QString DataPacket::GetUdpSrcPort() const
{
	udp_header *udpHeader{ (udp_header *)(m_pktData + 14 + 20) };
	u_short srcPort{ ntohs(udpHeader->src_port) };
	return QString::number(srcPort);
}

QString DataPacket::GetUdpDesPort() const
{
	udp_header *udpHeader{ (udp_header *)(m_pktData + 14 + 20) };
	u_short desPort{ ntohs(udpHeader->des_port) };
	return QString::number(desPort);
}

QString DataPacket::GetUdpDataLength() const
{
	udp_header *udpHeader{ (udp_header *)(m_pktData + 14 + 20) };
	u_short dataLength{ ntohs(udpHeader->data_length) };
	return QString::number(dataLength);
}

QString DataPacket::GetUdpChecksum() const
{
	udp_header *udpHeader{ (udp_header *)(m_pktData + 14 + 20) };
	u_short checksum{ ntohs(udpHeader->checksum) };
	return QString::number(checksum);
}

QString DataPacket::GetDnsTransactionId() const
{
	dns_header *dnsHeader{ (dns_header *)(m_pktData + 14 + 20 + 8) };
	u_short id{ ntohs(dnsHeader->identification) };
	return QString::number(id);
}

QString DataPacket::GetDnsFlags() const
{
	dns_header *dnsHeader{ (dns_header *)(m_pktData + 14 + 20 + 8) };
	u_short flags{ ntohs(dnsHeader->flags) };
	QString info{};
	if ((flags & 0xf800) == 0x0000)
		info += " Standard query";
	else if ((flags & 0xf800) == 0x8000)
		info = " Standard query response";
	return QString::number(flags, 16) + info;
}

QString DataPacket::GetDnsFlagsQR() const
{
	dns_header *dnsHeader{ (dns_header *)(m_pktData + 14 + 20 + 8) };
	u_short flags{ ntohs(dnsHeader->flags) };
	return QString::number((flags >> 15) & 0x0001);
}

QString DataPacket::GetDnsFlagsOpcode() const
{
	dns_header *dnsHeader{ (dns_header *)(m_pktData + 14 + 20 + 8) };
	u_short flags{ ntohs(dnsHeader->flags) };
	return QString::number((flags >> 11) & 0x000f);
}

QString DataPacket::GetDnsFlagsAA() const
{
	dns_header *dnsHeader{ (dns_header *)(m_pktData + 14 + 20 + 8) };
	u_short flags{ ntohs(dnsHeader->flags) };
	return QString::number((flags >> 10) & 0x0001);
}

QString DataPacket::GetDnsFlagsTC() const
{
	dns_header *dnsHeader{ (dns_header *)(m_pktData + 14 + 20 + 8) };
	u_short flags{ ntohs(dnsHeader->flags) };
	return QString::number((flags >> 9) & 0x0001);
}

QString DataPacket::GetDnsFlagsRD() const
{
	dns_header *dnsHeader{ (dns_header *)(m_pktData + 14 + 20 + 8) };
	u_short flags{ ntohs(dnsHeader->flags) };
	return QString::number((flags >> 8) & 0x0001);
}

QString DataPacket::GetDnsFlagsRA() const
{
	dns_header *dnsHeader{ (dns_header *)(m_pktData + 14 + 20 + 8) };
	u_short flags{ ntohs(dnsHeader->flags) };
	return QString::number((flags >> 7) & 0x0001);
}

QString DataPacket::GetDnsFlagsZ() const
{
	dns_header *dnsHeader{ (dns_header *)(m_pktData + 14 + 20 + 8) };
	u_short flags{ ntohs(dnsHeader->flags) };
	return QString::number((flags >> 6) & 0x0001);
}

QString DataPacket::GetDnsFlagsAD() const
{
	dns_header *dnsHeader{ (dns_header *)(m_pktData + 14 + 20 + 8) };
	u_short flags{ ntohs(dnsHeader->flags) };
	return QString::number((flags >> 5) & 0x0001);
}

QString DataPacket::GetDnsFlagsCD() const
{
	dns_header *dnsHeader{ (dns_header *)(m_pktData + 14 + 20 + 8) };
	u_short flags{ ntohs(dnsHeader->flags) };
	return QString::number((flags >> 4) & 0x0001);
}

QString DataPacket::GetDnsFlagsRcode() const
{
	dns_header *dnsHeader{ (dns_header *)(m_pktData + 14 + 20 + 8) };
	u_short flags{ ntohs(dnsHeader->flags) };
	return QString::number(flags & 0x000f);
}

QString DataPacket::GetDnsQuestionRRs() const
{
	dns_header *dnsHeader{ (dns_header *)(m_pktData + 14 + 20 + 8) };
	u_short question{ ntohs(dnsHeader->question) };
	return QString::number(question);
}

QString DataPacket::GetDnsAnswerRRs() const
{
	dns_header *dnsHeader{ (dns_header *)(m_pktData + 14 + 20 + 8) };
	u_short answer{ ntohs(dnsHeader->answer) };
	return QString::number(answer);
}

QString DataPacket::GetDnsAuthorityRRs() const
{
	dns_header *dnsHeader{ (dns_header *)(m_pktData + 14 + 20 + 8) };
	u_short authority{ ntohs(dnsHeader->authority) };
	return QString::number(authority);
}

QString DataPacket::GetDnsAdditionalRRs() const
{
	dns_header *dnsHeader{ (dns_header *)(m_pktData + 14 + 20 + 8) };
	u_short addtional{ ntohs(dnsHeader->additional) };
	return QString::number(addtional);
}

QString DataPacket::GetDnsDomainType(const u_short type) const
{
	switch (type)
	{
	case 1: return QStringLiteral("A (Host Address)");
	case 2:return QStringLiteral("NS");
	case 5:return QStringLiteral("CNAME (Canonical NAME for an alias)");
	case 6:return QStringLiteral("SOA");
	case 11:return QStringLiteral("WSK");
	case 12:return QStringLiteral("PTR");
	case 13:return QStringLiteral("HINFO");
	case 15:return QStringLiteral("MX");
	case 28:return QStringLiteral("AAAA");
	case 65:return QStringLiteral("HTTPS");
	case 252:return QStringLiteral("AXFR");
	case 255:return QStringLiteral("ANY");
	default: return "";
	}
}

QString DataPacket::GetDnsDomainClass(const u_short dnsClass) const
{
	QString res{};
	switch (dnsClass)
	{
	case 1:
		res = "IN";
		break;
	default:
		break;
	}
	return res;
}

void DataPacket::GetDnsQueriesDomain(QString &name, u_short &Type, u_short &Class) const
{
	u_char *dnsData{ (u_char *)(m_pktData + 14 + 20 + 8 + 12) };
	while (dnsData && *dnsData != 0 && *dnsData <= 64)
	{
		int len{ *dnsData++ };
		for (int i{}; i != len; ++i)
		{
			name += *dnsData++;
		}
		name += ".";
	}
	++dnsData;
	name = name.left(name.size() - 1);
	dns_question *dnsQuestion{ (dns_question *)(dnsData) };
	Type = ntohs(dnsQuestion->query_type);
	Class = ntohs(dnsQuestion->query_class);
}

QString DataPacket::GetDnsDomainName(const int offset) const
{
	u_char *dnsData{ (u_char *)(m_pktData + 14 + 20 + 8 + offset) };
	QString name{};
	while (dnsData && *dnsData != 0)
	{
		if (*dnsData <= 64)
		{
			int len{ *dnsData++ };
			for (int i{}; i != len; ++i)
			{
				name += *dnsData++;
			}
			name += ".";
		}
		else if ((*dnsData & 0xc0) == 0xc0)
		{
			int offsetTmp{ ((*dnsData & 0x3f) << 8) };
			++dnsData;
			offsetTmp += *dnsData;
			name += GetDnsDomainName(offsetTmp) + ".";
			++dnsData;
			break;
		}
	}
	name = name.left(name.size() - 1);
	return name;
}


int DataPacket::GetDnsAnswersDomain(const int offset, QString &name1, u_short &type, u_short &Class,
	u_int &ttl, u_short &dataLength, QString &name2) const
{
	u_char *dnsData = (u_char *)(m_pktData + 14 + 20 + 8 + 12 + offset);

	auto GetDnsName = [&] {
		if (GetDnsDomainType(type) == "AAAA")
		{
			for (int i{}; i != dataLength; ++i)
			{
				name2 += ToHex(dnsData, 1);
				dnsData++;
				if (i % 2 == 1)
					name2 += ":";
			}
		}
		else if (dataLength == 4)
		{
			//dnsData += (2 + 2 + 4 + 2 + name1.size() + 1);	
			for (int i{}; i != 4; ++i)
			{
				name2 += QString::number(*dnsData++);
				name2 += ".";
			}
		}
		else
		{
			while (dnsData && *dnsData != 0)
			{
				if (*dnsData <= 64)
				{
					int len{ *dnsData++ };
					for (int i{}; i != len; ++i)
					{
						name2 += *dnsData++;
					}
					name2 += ".";
				}
				else if ((*dnsData & 0xc0) == 0xc0)
				{
					int offsetTmp{ ((*dnsData & 0x3f) << 8) };
					++dnsData;
					offsetTmp += *dnsData;
					name2 += GetDnsDomainName(offsetTmp) + ".";
					++dnsData;
					break;
				}
			}
		}
		};

	if (((*dnsData) & 0xc0) == 0xc0)
	{
		int dnsOffset{ (((*dnsData) & 0x3f) << 8)};
		dnsData++;
		dnsOffset += *dnsData;
		name1 = GetDnsDomainName(dnsOffset);
		dnsData++;
		dns_answer *answer = (dns_answer *)(dnsData);
		type = ntohs(answer->answer_type);
		Class = ntohs(answer->answer_class);
		ttl = ntohl(answer->TTL);
		dataLength = ntohs(answer->dataLength);
		dnsData += (2 + 2 + 4 + 2);
		GetDnsName();
		name2 = name2.left(name2.size() - 1);
		return 2 + 2 + 2 + 4 + 2 + dataLength;
		// 多个+2是因为加上域名压缩的那两个字节（理由同下）
	}
	else
	{
		name1 = GetDnsDomainName(offset + 12);
		// +12 是因为GetDnsDomainName 没有加dns头，这里要加上

		dns_answer *answer{ (dns_answer *)(dnsData + name1.size() + 2) };
		// 跳过域名压缩的那两个字节（因为cname和name是重复的）

		type = ntohs(answer->answer_type);
		Class = ntohs(answer->answer_class);
		ttl = ntohl(answer->TTL);
		dataLength = ntohs(answer->dataLength);
		dnsData += (2 + 2 + 4 + 2 + name1.size() + 1);	// +1 为了进入到域名2
		GetDnsName();
		name2 = name2.left(name2.size() - 1);
		return dataLength + 2 + 2 + 2 + 4 + 2 + name1.size() + 2;
		// 有新的域名，所以要name1.size()，并且还要加上上面的+2
	}
}