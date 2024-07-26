#include <WinSock2.h>
#include <QModelIndex>

#include "CreateFakePacket.h"

CreateFakePacket::CreateFakePacket(QWidget *parent)
	: QWidget(parent)
	, ui(new Ui::CreateFakePacketClass())
{
	ui->setupUi(this);

	InitScreen();

	m_spoof = new ArpSpoof;
	m_spoofThread = new QThread;
	m_spoof->moveToThread(m_spoofThread);

	connect(this, &CreateFakePacket::StartArpSpoofSignal, m_spoof, &ArpSpoof::StartArpSpoof);
	connect(m_spoof, &ArpSpoof::SendText, this, &CreateFakePacket::SetText);
	
	connect(m_timer, &QTimer::timeout, [&] {
		ui->pktInfoPlainEdit->clear();
		m_timer->stop();
		});
}

CreateFakePacket::~CreateFakePacket()
{
	delete ui;
	delete m_spoof;
	m_spoofThread->quit();
	m_spoofThread->wait();
	delete m_spoofThread;
}

void CreateFakePacket::InitScreen()
{
	setFixedSize(800, 800);
	setWindowTitle(QStringLiteral("构造封包"));
	m_ReadOnlyDelegate = new ReadOnlyDelegate();

	m_model = new QStandardItemModel(this);
	m_timer = new QTimer(this);

	m_pktItemVec.push_back(new QStandardItem(QStringLiteral("构造封包")));
	m_pktItemVec.push_back(new QStandardItem("ETHER"));
	m_pktItemVec.push_back(new QStandardItem("ARP"));
	m_pktItemVec.push_back(new QStandardItem("IP"));
	m_pktItemVec.push_back(new QStandardItem("ICMP"));
	m_pktItemVec.push_back(new QStandardItem("TCP"));
	m_pktItemVec.push_back(new QStandardItem("UDP"));
	m_pktItemVec.push_back(new QStandardItem(QStringLiteral("ARP欺骗")));

	m_pktItemVec[0]->appendRows({ m_pktItemVec[1] });
	m_pktItemVec[1]->appendRows({ m_pktItemVec[2], m_pktItemVec[3] });
	m_pktItemVec[3]->appendRows({ m_pktItemVec[4], m_pktItemVec[5], m_pktItemVec[6] });

	m_model->appendRow({ m_pktItemVec[0] });
	m_model->appendRow({ m_pktItemVec[7] });
	ui->fakePktTree->setModel(m_model);

	ui->fakePktTree->setItemDelegate(m_ReadOnlyDelegate);
	ui->fakePktTree->setHeaderHidden(true);
	ui->fakePktInfo->setCurrentIndex(0);

	ui->pktInfoPlainEdit->setReadOnly(true);
	ui->ethInfoPlainEdit->setReadOnly(true);
	ui->arpInfoPlainEdit->setReadOnly(true);
	ui->ipInfoPlainEdit->setReadOnly(true);
	ui->icmpInfoPlainEdit->setReadOnly(true);
	ui->tcpInfoPlainEdit->setReadOnly(true);
	ui->udpInfoPlainEdit->setReadOnly(true);
	ui->spoofInfoPlainEdit->setReadOnly(true);

	ui->spoofStartBtn->setCheckable(false);
	ui->spoofStopBtn->setCheckable(false);
}

void CreateFakePacket::on_ethOkBtn_clicked()
{
	QStringList dst = ui->ethDstLEdit->text().split(":");
	QStringList src = ui->ethSrcLEdit->text().split(":");
	QString type = ui->ethTypeLEdit->text();
	if (dst.isEmpty() || src.isEmpty() || type.isEmpty())
	{
		m_flags[0] = false;
		ui->ethInfoPlainEdit->appendPlainText(QStringLiteral("请输入Ethernet对应字段"));
		return;
	}

	ethernet_header eth;
	for (int i{}; i != 6; ++i)
	{
		eth.des_mac[i] = static_cast<u_char>(dst[i].toUInt(nullptr, 16));
		eth.src_mac[i] = static_cast<u_char>(src[i].toUInt(nullptr, 16));
	}
	eth.type = htons(type.toUShort(nullptr, 16));
	m_pktArray.append((char *)&eth, sizeof(eth));

	QString payload = ui->ethPayloadLEdit->text();
	if (!payload.isEmpty())
	{
		m_pktArray.append(payload.toLocal8Bit());
	}
	else
	{
		m_flags[0] = true;
	}
	ui->ethInfoPlainEdit->appendPlainText(QStringLiteral("Ethernet封包保存成功"));

	ui->pktInfoPlainEdit->appendPlainText(QStringLiteral("### ETH ###"));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2:%3:%4:%5:%6:%7").
		arg(ui->ethDstLabel->text(), dst[0], dst[1], dst[2], dst[3], dst[4], dst[5]));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2:%3:%4:%5:%6:%7").
		arg(ui->ethSrcLabel->text(), src[0], src[1], src[2], src[3], src[4], src[5]));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2").arg(ui->ethTypeLabel->text(), type));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2").arg(ui->ethPayloadLabel->text(), payload));
}

void CreateFakePacket::on_arpOkBtn_clicked()
{
	if (!m_flags[0])
	{
		ui->arpInfoPlainEdit->setPlainText(QStringLiteral("请先设置ETHER"));
		return;
	}
	if (m_flags[2])
	{
		ui->arpInfoPlainEdit->setPlainText(QStringLiteral("已设置IP，无法设置ARP"));
		return;
	}

	QString hardwareTypeStr = ui->arpHardwareTypeLEdit->text();
	QString protocolTypeStr = ui->arpProtocolTypeLEdit->text();
	QString macLengthStr = ui->arpMacLengthLEdit->text();
	QString protocolLengthStr = ui->arpIplengthLEdit->text();
	QString opCodeStr = ui->arpOpCodeLEdit->text();
	QString srcMacStr = ui->arpSrcMacLEdit->text();
	QString srcIpStr = ui->arpSrcIpLEdit->text();
	QString dstMacStr = ui->arpDstMacLEdit->text();
	QString dstIpStr = ui->arpDstIpLEdit->text();

	if (hardwareTypeStr.isEmpty() || protocolTypeStr.isEmpty() || macLengthStr.isEmpty() || protocolLengthStr.isEmpty() ||
		opCodeStr.isEmpty() || srcMacStr.isEmpty() || srcIpStr.isEmpty() || dstMacStr.isEmpty() || dstIpStr.isEmpty())
	{
		m_flags[1] = false;
		ui->arpInfoPlainEdit->appendPlainText(QStringLiteral("请输入ARP对应字段"));
		return;
	}

	arp_header arp;
	arp.hardware_type = htons(hardwareTypeStr.toUShort(nullptr, 16));
	arp.protocol_type = htons(protocolTypeStr.toUShort(nullptr, 16));
	arp.mac_length = macLengthStr.toUInt(nullptr, 16);
	arp.ip_length = protocolLengthStr.toUInt(nullptr, 16);
	arp.op_code = htons(opCodeStr.toUShort(nullptr, 16));
	QStringList srcMac = srcMacStr.split(":");
	QStringList dstMac = dstMacStr.split(":");
	for (int i{}; i != 6; ++i)
	{
		arp.src_mac[i] = static_cast<u_char>(srcMac[i].toUInt(nullptr, 16));
		arp.des_mac[i] = static_cast<u_char>(dstMac[i].toUInt(nullptr, 16));
	}

	QStringList srcIp = srcIpStr.split(".");
	QStringList dstIp = dstIpStr.split(".");
	for (int i{}; i != 4; ++i)
	{
		arp.src_ip[i] = static_cast<u_char>(srcIp[i].toUInt(nullptr, 16));
		arp.des_ip[i] = static_cast<u_char>(dstIp[i].toUInt(nullptr, 16));
	}
	m_pktArray.append((char *)&arp, sizeof(arp));

	QString arpPayloadStr = ui->arpPayloadLEdit->text();
	if (!arpPayloadStr.isEmpty())
	{
		m_pktArray.append(arpPayloadStr.toLocal8Bit());
	}
	m_flags[1] = true;
	ui->arpInfoPlainEdit->appendPlainText(QStringLiteral("ARP封包保存成功"));

	ui->pktInfoPlainEdit->appendPlainText(QStringLiteral(""));
	ui->pktInfoPlainEdit->appendPlainText(QStringLiteral("### ARP ###"));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2").arg(ui->arpHardwareTypeLabel->text(), hardwareTypeStr));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2").arg(ui->arpProtocolTypeLabel->text(), protocolTypeStr));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2").arg(ui->arpMacLengthLabel->text(), macLengthStr));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2").arg(ui->arpIplengthLabel->text(), protocolLengthStr));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2").arg(ui->arpOpCodeLabel->text(), opCodeStr));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2:%3:%4:%5:%6:%7").
		arg(ui->arpSrcMacLabel->text(), srcMac[0], srcMac[1], srcMac[2], srcMac[3], srcMac[4], srcMac[5]));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2.%3.%4.%5").
		arg(ui->arpSrcIpLabel->text(), srcIp[0], srcIp[1], srcIp[2], srcIp[3]));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2:%3:%4:%5:%6:%7").
		arg(ui->arpDstMacLabel->text(), dstMac[0], dstMac[1], dstMac[2], dstMac[3], dstMac[4], dstMac[5]));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2.%3.%4.%5").
		arg(ui->arpDstIpLabel->text(), dstIp[0], dstIp[1], dstIp[2], dstIp[3]));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2").arg(ui->arpPayloadLabel->text(), arpPayloadStr));
}

void CreateFakePacket::on_ipOkBtn_clicked()
{
	if (!m_flags[0])
	{
		ui->ipInfoPlainEdit->setPlainText(QStringLiteral("请先设置ETHER"));
		return;
	}
	if (m_flags[1])
	{
		ui->ipInfoPlainEdit->setPlainText(QStringLiteral("已设置ARP，无法设置IP"));
		return;
	}

	QString ipVersionStr = ui->ipVersionLEdit->text();
	QString ipHeadLengthStr = ui->ipHeadLengthLEdit->text();
	QString ipTOSStr = ui->ipTOSLEdit->text();
	QString ipTotalLengthStr = ui->ipTotalLEdit->text();
	QString ipIdentificationStr = ui->ipIdentificationLEdit->text();
	QString ipFlagStr = ui->ipFlagLEdit->text();
	QString ipOffsetStr = ui->ipOffsetLEdit->text();
	QString ipTTLStr = ui->ipTTLLEdit->text();
	QString ipProtocoStr = ui->IpProtocolLEdit->text();
	QString ipChecksumStr = ui->ipChecksumLEdit->text();
	QString ipSrcStr = ui->ipSrcLEdit->text();
	QString ipDstStr = ui->ipDstLEdit->text();

	if (ipVersionStr.isEmpty() || ipHeadLengthStr.isEmpty() || ipTOSStr.isEmpty() || ipTotalLengthStr.isEmpty() ||
		ipIdentificationStr.isEmpty() || ipFlagStr.isEmpty() || ipOffsetStr.isEmpty() || ipTTLStr.isEmpty()
		|| ipProtocoStr.isEmpty() || ipChecksumStr.isEmpty() || ipSrcStr.isEmpty() || ipDstStr.isEmpty())
	{
		m_flags[2] = false;
		ui->ipInfoPlainEdit->appendPlainText(QStringLiteral("请输入IP对应字段"));
		return;
	}

	ip_header ip;
	ip.version = ipVersionStr.toUInt() & 0x0F;
	ip.head_length = ipHeadLengthStr.toUInt() & 0x0F;
	ip.TOS = ipTOSStr.toUInt();
	ip.total_length = htons(ipTotalLengthStr.toUShort());
	ip.identification = htons(ipIdentificationStr.toUShort(nullptr, 16));
	ip.flag_offset = htons(((ipFlagStr.toUShort()) & 0x0007) << 13) | ((ipOffsetStr.toUShort()) & 0x1FFF);
	ip.ttl = ipTTLStr.toInt();
	ip.protocol = ipProtocoStr.toInt();
	ip.checksum = htons(ipChecksumStr.toUShort(nullptr, 16));
	QStringList srcIp = ipSrcStr.split(".");
	QStringList dstIp = ipDstStr.split(".");
	auto IpToInt = [](const QStringList &ip)->u_int {
		u_int res = 0;
		for (int i = 3; i != -1; --i) {
			res = (res << 8) + ip[i].toUInt();
		}
		return res;
		};
	ip.src_ip_addr = IpToInt(srcIp);
	ip.des_ip_addr = IpToInt(dstIp);

	m_pktArray.append((char *)&ip, sizeof(ip));
	QString ipPayloadStr = ui->ipPayloadLEdit->text();
	if (!ipPayloadStr.isEmpty())
	{
		m_pktArray.append(ipPayloadStr.toLocal8Bit());
	}

	m_flags[2] = true;
	ui->ipInfoPlainEdit->appendPlainText(QStringLiteral("IP封包保存成功"));

	ui->pktInfoPlainEdit->appendPlainText(QStringLiteral(""));
	ui->pktInfoPlainEdit->appendPlainText(QStringLiteral("### IP ###"));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2").arg(ui->ipVersionLabel->text(), ipVersionStr));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2").arg(ui->ipHeadLengthLabel->text(), ipHeadLengthStr));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2").arg(ui->ipTOSLabel->text(), ipTOSStr));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2").arg(ui->ipFlagLabel->text(), ipFlagStr));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2").arg(ui->ipOffsetLabel->text(), ipOffsetStr));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2").arg(ui->ipTTLLabel->text(), ipTTLStr));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2").arg(ui->IpProtocolLabel->text(), ipProtocoStr));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2").arg(ui->ipChecksumLabel->text(), ipChecksumStr));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2.%3.%4.%5").
		arg(ui->ipSrcLabel->text(), srcIp[0], srcIp[1], srcIp[2], srcIp[3]));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2.%3.%4.%5").
		arg(ui->ipDstLabel->text(), dstIp[0], dstIp[1], dstIp[2], dstIp[3]));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2").arg(ui->ipPayloadLabel->text(), ipPayloadStr));

}

void CreateFakePacket::on_icmpOkBtn_clicked()
{
	if (!m_flags[2])
	{
		ui->icmpInfoPlainEdit->setPlainText(QStringLiteral("请先设置IP"));
		return;
	}
	if (m_flags[4])
	{
		ui->icmpInfoPlainEdit->setPlainText(QStringLiteral("已设置TCP"));
		return;
	}
	if (m_flags[5])
	{
		ui->icmpInfoPlainEdit->setPlainText(QStringLiteral("已设置UDP"));
		return;
	}

	QString icmpTypeStr = ui->icmpTypeLEdit->text();
	QString icmpCodeStr = ui->icmpCodeLEdit->text();
	QString icmpChecksumStr = ui->icmpChecksumLEdit->text();
	QString icmpIdentificationStr = ui->icmpIdentificationLEdit->text();
	QString icmpSequenceStr = ui->icmpSequenceLEdit->text();

	if (icmpTypeStr.isEmpty() || icmpCodeStr.isEmpty() || icmpChecksumStr.isEmpty() ||
		icmpIdentificationStr.isEmpty() || icmpSequenceStr.isEmpty())
	{
		m_flags[3] = false;
		ui->ipInfoPlainEdit->appendPlainText(QStringLiteral("请输入ICMP对应字段"));
		return;
	}

	icmp_header icmp;
	icmp.type = icmpTypeStr.toUInt();
	icmp.code = icmpCodeStr.toUInt();
	icmp.checksum = htons(icmpChecksumStr.toUShort());
	icmp.identification = htons(icmpIdentificationStr.toUShort());
	icmp.sequence = htons(icmpChecksumStr.toUShort());

	m_pktArray.append((char *)&icmp, sizeof(icmp));

	QString icmpPayloadStr = ui->icmpPayloadLEdit->text();
	if (!icmpPayloadStr.isEmpty())
	{
		m_pktArray.append(icmpPayloadStr.toLocal8Bit());
	}
	m_flags[3] = true;
	ui->icmpInfoPlainEdit->appendPlainText(QStringLiteral("ICMP封包保存成功"));

	ui->pktInfoPlainEdit->appendPlainText(QStringLiteral(""));
	ui->pktInfoPlainEdit->appendPlainText(QStringLiteral("### ICMP ###"));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2").arg(ui->icmpTypeLabel->text(), icmpTypeStr));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2").arg(ui->icmpCodeLabel->text(), icmpCodeStr));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2").arg(ui->icmpChecksumLabel->text(), icmpChecksumStr));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2").arg(ui->icmpIdentificationLabel->text(), icmpIdentificationStr));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2").arg(ui->icmpSequenceLabel->text(), icmpSequenceStr));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2").arg(ui->icmpPayloadLabel->text(), icmpPayloadStr));
}

void CreateFakePacket::on_tcpOkBtn_clicked()
{
	if (!m_flags[2])
	{
		ui->tcpInfoPlainEdit->setPlainText(QStringLiteral("请先设置IP"));
		return;
	}
	if (m_flags[3])
	{
		ui->tcpInfoPlainEdit->setPlainText(QStringLiteral("已设置ICMP"));
		return;
	}
	if (m_flags[5])
	{
		ui->tcpInfoPlainEdit->setPlainText(QStringLiteral("已设置UDP"));
		return;
	}
	QString tcpSrcPortStr = ui->tcpSrcPortLEdit->text();
	QString tcpDstPortStr = ui->tcpDstPortLEdit->text();
	QString tcpSeqStr = ui->tcpSeqLEdit->text();
	QString tcpAckStr = ui->tcpAckLEdit->text();
	QString tcpHeadLengthStr = ui->tcpHeadLengthLEdit->text();
	QString tcpFlagStr = ui->tcpFlagLEdit->text();
	QString tcpWinSizeStr = ui->tcpWinSizeLEdit->text();
	QString tcpChecksumStr = ui->tcpChecksumLEdit->text();
	QString tcpUrgentStr = ui->tcpUrgentLEdit->text();

	if (tcpSrcPortStr.isEmpty() || tcpDstPortStr.isEmpty() || tcpSeqStr.isEmpty() || tcpAckStr.isEmpty() ||
		tcpHeadLengthStr.isEmpty() || tcpFlagStr.isEmpty() || tcpWinSizeStr.isEmpty()
		|| tcpChecksumStr.isEmpty() || tcpUrgentStr.isEmpty())
	{
		m_flags[4] = false;
		ui->tcpInfoPlainEdit->appendPlainText(QStringLiteral("请输入TCP对应字段"));
		return;
	}

	tcp_header tcp;
	tcp.src_port = htons(tcpSrcPortStr.toUShort());
	tcp.des_port = htons(tcpDstPortStr.toUShort());
	tcp.seq = htonl(tcpSeqStr.toUInt());
	tcp.ack = htonl(tcpAckStr.toUInt());
	tcp.header_length = tcpHeadLengthStr.toUInt();
	tcp.flags = tcpFlagStr.toUInt();
	tcp.window_size = htons(tcpWinSizeStr.toUShort());
	tcp.checksum = htons(tcpChecksumStr.toUShort());
	tcp.urgent = htons(tcpUrgentStr.toUShort());

	m_pktArray.append((char *)&tcp, sizeof(tcp));

	QString tcpPayloadStr = ui->tcpPayloadLEdit->text();
	if (!tcpPayloadStr.isEmpty())
	{
		m_pktArray.append(tcpPayloadStr.toLocal8Bit());
	}
	m_flags[4] = true;
	ui->tcpInfoPlainEdit->appendPlainText(QStringLiteral("TCP封包保存成功"));

	ui->pktInfoPlainEdit->appendPlainText(QStringLiteral(""));
	ui->pktInfoPlainEdit->appendPlainText(QStringLiteral("### TCP ###"));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2").arg(ui->tcpSrcPortLabel->text(), tcpSrcPortStr));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2").arg(ui->tcpDstPortLabel->text(), tcpDstPortStr));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2").arg(ui->tcpSeqLabel->text(), tcpSeqStr));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2").arg(ui->tcpAckLabel->text(), tcpAckStr));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2").arg(ui->tcpHeadLengthLabel->text(), tcpHeadLengthStr));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2").arg(ui->tcpFlagLabel->text(), tcpFlagStr));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2").arg(ui->tcpWinSizeLabel->text(), tcpWinSizeStr));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2").arg(ui->tcpChecksumLabel->text(), tcpChecksumStr));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2").arg(ui->tcpUrgentLabel->text(), tcpUrgentStr));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2").arg(ui->tcpPayloadLabel->text(), tcpPayloadStr));

}

void CreateFakePacket::on_udpOkBtn_clicked()
{
	if (!m_flags[2])
	{
		ui->udpInfoPlainEdit->setPlainText(QStringLiteral("请先设置IP"));
		return;
	}
	if (m_flags[3])
	{
		ui->udpInfoPlainEdit->setPlainText(QStringLiteral("已设置ICMP"));
		return;
	}
	if (m_flags[4])
	{
		ui->udpInfoPlainEdit->setPlainText(QStringLiteral("已设置TCP"));
		return;
	}

	QString udpSrcPortStr = ui->udpSrcPortLEdit->text();
	QString udpDstPortStr = ui->udpDstPortLEdit->text();
	QString udpDataLengthStr = ui->udpDataLengthLEdit->text();
	QString udpChecksumStr = ui->udpChecksumLEdit->text();

	if (udpSrcPortStr.isEmpty() || udpDstPortStr.isEmpty() || udpDataLengthStr.isEmpty() || udpChecksumStr.isEmpty())
	{
		m_flags[5] = false;
		ui->udpInfoPlainEdit->appendPlainText(QStringLiteral("请输入UDP对应字段"));
		return;
	}

	udp_header udp;
	udp.src_port = htons(udpSrcPortStr.toUShort());
	udp.des_port = htons(udpDstPortStr.toUShort());
	udp.data_length = htons(udpDataLengthStr.toUShort());
	udp.checksum = htons(udpChecksumStr.toUShort());

	m_pktArray.append((char *)&udp, sizeof(udp));

	QString udpPayloadStr = ui->udpPayloadLEdit->text();
	if (!udpPayloadStr.isEmpty())
	{
		m_pktArray.append(udpPayloadStr.toLocal8Bit());
	}
	m_flags[5] = true;
	ui->udpInfoPlainEdit->appendPlainText(QStringLiteral("UDP封包保存成功"));

	ui->pktInfoPlainEdit->appendPlainText(QStringLiteral(""));
	ui->pktInfoPlainEdit->appendPlainText(QStringLiteral("### UDP ###"));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2").arg(ui->udpSrcPortLabel->text(), udpSrcPortStr));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2").arg(ui->udpDstPortLabel->text(), udpDstPortStr));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2").arg(ui->udpDataLengthLabel->text(), udpDataLengthStr));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2").arg(ui->udpChecksumLabel->text(), udpChecksumStr));
	ui->pktInfoPlainEdit->appendPlainText(QString("%1: %2").arg(ui->udpPayloadLabel->text(), udpPayloadStr));
}

void CreateFakePacket::on_pktInfoOkBtn_clicked()
{
	if (ui->pktInfoPlainEdit->toPlainText().isEmpty())
		return;
	bool ok{};
	
	emit SendPkt(m_pktArray, ok);
}

void CreateFakePacket::on_pktInfoCancelBtn_clicked()
{
	m_flags = {};
	ui->pktInfoPlainEdit->clear();
	ui->pktInfoPlainEdit->appendPlainText(QStringLiteral("请重新设置封包"));
	m_timer->start(4000);
}

void CreateFakePacket::on_spoofStartBtn_clicked()
{
	QString spoofDstIpStr = ui->sproofDstIpLEdit->text();
	QString spoofDstMacStr = ui->sproofDstMacLEdit->text();
	QString spoofIpStr = ui->sproofIpLEdit->text();
	QString spoofMacStr = ui->sproofMacLEdit->text();
	if (spoofDstIpStr.isEmpty() || spoofDstMacStr.isEmpty() || spoofIpStr.isEmpty() || spoofMacStr.isEmpty())
	{
		ui->spoofInfoPlainEdit->setPlainText(QStringLiteral("请先填入信息"));
		return;
	}
	ui->spoofStartBtn->setEnabled(false);
	ui->spoofStopBtn->setEnabled(true);
	m_spoof->SetKeepSend(true);
	emit StartArpSpoofSignal(m_nicName, spoofDstIpStr, spoofDstMacStr, spoofIpStr, spoofMacStr);
	m_spoofThread->start();
}

void CreateFakePacket::on_spoofStopBtn_clicked()
{
	m_spoof->SetKeepSend(false);
	m_spoofThread->quit();
	m_spoofThread->wait();
	ui->spoofStartBtn->setEnabled(true);
	ui->spoofStopBtn->setEnabled(false);
	ui->spoofInfoPlainEdit->setPlainText(QStringLiteral("停止发送..."));
}

void CreateFakePacket::GetNicName(const QString &nicName)
{
	m_nicName = nicName;
	ui->pktNicInfoLabel->setText(m_nicName);
	ui->spoofNicInfoLabel->setText(m_nicName);
}

void CreateFakePacket::SetText(const QString &text)
{
	ui->spoofInfoPlainEdit->appendPlainText(text);
}

void CreateFakePacket::HandleRecvPktOk(const bool &ok)
{
	if (ok)
	{
		ui->pktInfoPlainEdit->clear();
		ui->pktInfoPlainEdit->appendPlainText(QStringLiteral("发送成功，请重新设置封包"));
		m_timer->start(4000);
	}
}

void CreateFakePacket::on_fakePktTree_clicked(const QModelIndex &index)
{
	QString type = index.data().toString();
	if (type == QStringLiteral("构造封包"))
	{
		ui->fakePktInfo->setCurrentIndex(0);
	}
	else if (type == "ETHER")
	{
		ui->fakePktInfo->setCurrentIndex(1);
	}
	else if (type == "ARP")
	{
		ui->fakePktInfo->setCurrentIndex(2);
	}
	else if (type == "IP")
	{
		ui->fakePktInfo->setCurrentIndex(3);
	}
	else if (type == "ICMP")
	{
		ui->fakePktInfo->setCurrentIndex(4);
	}
	else if (type == "TCP")
	{
		ui->fakePktInfo->setCurrentIndex(5);
	}
	else if (type == "UDP")
	{
		ui->fakePktInfo->setCurrentIndex(6);
	}
	else if (type == QStringLiteral("ARP欺骗"))
	{
		ui->fakePktInfo->setCurrentIndex(7);
	}
}