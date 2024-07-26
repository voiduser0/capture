#pragma once

#include <QString>

#include "Header.h"

enum class EProtocolType {
	ETH, ARP, ICMP, TCP, UDP, DNS
};

class DataPacket
{
	friend QString ToHex(const unsigned char *chs, const int size);

private:
	int m_protocolType{};
	u_int m_length{};
	QString m_info{};
	QString m_timeStamp{};

public:
	u_char *m_pktData{};

public:
	DataPacket();
	DataPacket(const u_char *pktData, const u_int size);
	DataPacket(const u_int length, const QString timeStamp, const int protocolType,
		const QString info, const u_char *pktData, const u_int size);
	~DataPacket() = default;

	void SetLength(const u_int length);
	void SetTimeStamp(const QString timeStamp);
	void SetProtocolType(const int protocolType);
	void SetInfo(const QString info);
	void SetPktData(const u_char *pktData, const u_int size);

	QString GetLength() const;
	QString GetTimeStamp() const;
	QString GetProtocolType() const;
	QString GetInfo() const;
	QString GetMacInfo(const u_char *mac) const;
	QString GetIpInfo(const u_char *ip) const;

	QString GetSrcAddr() const;
	QString GetDesAddr() const;

	QString GetEthSrcMac() const;
	QString GetEthDesMac() const;
	QString GetEthType() const;

	QString GetArpHardewareType() const;
	QString GetArpProtocolType() const;
	QString GetArpMacLength() const;
	QString GetArpIpLength() const;
	QString GetArpOperationCode() const;
	QString GetArpSourceMac() const;
	QString GetArpSourceIp() const;
	QString GetArpDestinationMac() const;
	QString GetArpDestinationIp() const;

	QString GetIpVersion() const;
	QString GetIpHeadlength(QString &info) const;
	QString GetIpServiceType() const;
	QString GetIpTotalLength() const;
	QString GetIpIdentification() const;
	QString GetIpFlags() const;
	QString GetIpFlagsReservedBit() const;
	QString GetIpFlagsDF() const;
	QString GetIpFlagsMF() const;
	QString GetIpOffset() const;
	QString GetIpTTL() const;
	QString GetIpProtocol() const;
	QString GetIpChecksum() const;
	QString GetIpSrcIp() const;
	QString GetIpDesIp() const;

	QString GetIcmpType() const;
	QString GetIcmpCode() const;
	QString GetIcmpChecksum() const;
	QString GetIcmpIdentification() const;
	QString GetIcmpSequence() const;
	QString GetIcmpData(const int size) const;

	QString GetTcpSrcPort() const;
	QString GetTcpDesPort() const;
	QString GetTcpSeq() const;
	QString GetTcpAck() const;
	QString GetTcpHeaderLength(QString &info) const;
	QString GetTcpFlags() const;
	QString GetTcpFlagsFIN() const;
	QString GetTcpFlagsSYN() const;
	QString GetTcpFlagsRST() const;
	QString GetTcpFlagsPSH() const;
	QString GetTcpFlagsACK() const;
	QString GetTcpFlagsURG() const;
	QString GetTcpFlagsECE() const;
	QString GetTcpFlagsCWR() const;
	QString GetTcpFlagsAECN() const;
	QString GetTcpWinSize() const;
	QString GetTcpChecksum() const;
	QString GetTcpUrgent() const;

	QString GetUdpSrcPort() const;
	QString GetUdpDesPort() const;
	QString GetUdpDataLength() const;
	QString GetUdpChecksum() const;

	QString GetDnsTransactionId() const;
	QString GetDnsFlags() const;
	QString GetDnsFlagsQR() const;
	QString GetDnsFlagsOpcode() const;
	QString GetDnsFlagsAA() const;
	QString GetDnsFlagsTC() const;
	QString GetDnsFlagsRD() const;
	QString GetDnsFlagsRA() const;
	QString GetDnsFlagsZ() const;
	QString GetDnsFlagsAD() const;
	QString GetDnsFlagsCD() const;
	QString GetDnsFlagsRcode() const;
	QString GetDnsQuestionRRs() const;
	QString GetDnsAnswerRRs() const;
	QString GetDnsAuthorityRRs() const;
	QString GetDnsAdditionalRRs() const;
	QString GetDnsDomainType(const u_short type) const;
	QString GetDnsDomainClass(const u_short dnsClass) const;
	QString GetDnsDomainName(const int offset) const;
	void GetDnsQueriesDomain(QString &name, u_short &Type, u_short &Class) const;
	int GetDnsAnswersDomain(const int offset, QString &name1, u_short &type, u_short &Class,
		u_int &ttl, u_short &dataLength, QString &name2) const;
};

