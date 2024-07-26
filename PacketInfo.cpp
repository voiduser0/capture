#include <QDir>
#include <qDebug>
#include <QColor>
#include <QString>
#include <QRegExp>
#include <QFileDialog>
#include <QCompleter>
#include <QMessageBox>
#include <QTreeWidgetItem>
#include <QTableWidgetItem>

#include "PacketInfo.h"
#include "PacketHandle.h"

constexpr int kColumnCount{ 7 };
constexpr int kMinFrameLength{ 64 };

PacketInfo::PacketInfo(QWidget *parent)
	: QMainWindow(parent)
	, ui(new Ui::PacketInfoClass())
{
	ui->setupUi(this);

	m_cfpkt = new CreateFakePacket;
	m_pktHandle = new PacketHandle;
	m_updateChartTime = new QTimer(this);

	InitScreen();
	InitDatabase();
	ShowNetwordDevice();

	connect(m_pktHandle, &PacketHandle::SendData, this, &PacketInfo::RecvData);
	connect(m_updateChartTime, &QTimer::timeout, this, &PacketInfo::ShowPieChart);
	connect(this, &PacketInfo::SendNicName, m_cfpkt, &CreateFakePacket::GetNicName);
	connect(this, &PacketInfo::RecvPktOk, m_cfpkt, &CreateFakePacket::HandleRecvPktOk);
	connect(m_cfpkt, &CreateFakePacket::SendPkt, this, &PacketInfo::RecvPkt);
	connect(m_actSearch, &QAction::triggered, ui->lineEditFilter, &QLineEdit::returnPressed);
}

PacketInfo::~PacketInfo()
{
	delete ui;
	m_pktHandle->ResetFlag();
	m_pktHandle->quit();
	m_pktHandle->wait();
	delete m_pktHandle;
	m_pktHandle = Q_NULLPTR;

	ClearList();

	pcap_dump_close(m_dumper);  // 关闭 pcap_dump 句柄
	m_allDevices = Q_NULLPTR;
	if (m_adhandle)
	{
		pcap_close(m_adhandle);
		m_adhandle = Q_NULLPTR;
	}

	QString fileName{ "output.pcap" };
	if (QFile::exists(fileName))
		QFile::remove(fileName);

	delete m_cfpkt;
	m_cfpkt = Q_NULLPTR;

	delete m_chart;
	m_chart = Q_NULLPTR;

	if (m_updateChartTime->isActive())
		m_updateChartTime->stop();

}

void PacketInfo::closeEvent(QCloseEvent* e)
{
	QMessageBox::StandardButton msgBox = 
			QMessageBox::question(this, QStringLiteral("保存文件？"), QStringLiteral("是否保存为pcap文件"));
	if (msgBox == QMessageBox::Yes)
	{
		SaveFile();
	}
	e->accept();
}

void PacketInfo::InitScreen()
{
	setWindowTitle("Capture");
	setWindowIcon(QIcon("capture.ico"));
	resize(2400, 1600);

	InitTreeScreen();
	InitTableScreen();
	InitLEditScreen();
	InitPieChartScreen();
	ResetActionState();
}

void PacketInfo::InitDatabase()
{
	m_database = QSqlDatabase::addDatabase("QMYSQL");
	m_database.setHostName("127.0.0.1");
	m_database.setUserName("root");
	m_database.setPassword("123qwe");
	m_database.setDatabaseName("capture");
	m_database.setPort(13306);

	if (!m_database.open())
	{
		qDebug() << QStringLiteral("数据库连接失败") << m_database.lastError();
	}
	else
	{
		qDebug() << QStringLiteral("数据库连接成功");
	}

}

void PacketInfo::InitTableScreen()
{
	ui->tableWidgetPacketList->setColumnCount(kColumnCount);
	ui->tableWidgetPacketList->setHorizontalHeaderLabels({ "No.", "Time",
					"Source", "Destination", "Protocol", "Length", "Info" });
	ui->tableWidgetPacketList->horizontalHeaderItem(kColumnCount - 1)->setTextAlignment(Qt::AlignLeft);
	ui->tableWidgetPacketList->setColumnWidth(0, 100);
	ui->tableWidgetPacketList->setColumnWidth(1, 200);
	ui->tableWidgetPacketList->setColumnWidth(2, 300);
	ui->tableWidgetPacketList->setColumnWidth(3, 300);
	ui->tableWidgetPacketList->setColumnWidth(4, 150);
	ui->tableWidgetPacketList->setColumnWidth(5, 200);
	ui->tableWidgetPacketList->setColumnWidth(6, 2000);
	ui->tableWidgetPacketList->verticalHeader()->setVisible(false);
	ui->tableWidgetPacketList->setShowGrid(false);
	ui->tableWidgetPacketList->setSelectionBehavior(QTableWidget::SelectRows);
	m_ReadOnlyDelegate = new ReadOnlyDelegate();
	ui->tableWidgetPacketList->setItemDelegate(m_ReadOnlyDelegate);
	ui->tableWidgetDataInfo->setItemDelegate(m_ReadOnlyDelegate);
}

void PacketInfo::InitTreeScreen()
{
	ui->treeWidgetPktInfo->header()->setVisible(false);
}

void PacketInfo::InitLEditScreen()
{
	ui->lineEditFilter->setPlaceholderText(QStringLiteral("过滤器"));
	ui->lineEditFilter->setToolTip(QStringLiteral("不区分大小写"));
	QCompleter *completer = new QCompleter({ "UDP", "TCP", "DNS", "ARP", "ICMP",
		"IP.SRC==", "IP.DST==", "IP.ADDR==" }, ui->lineEditFilter);
	completer->setCaseSensitivity(Qt::CaseInsensitive);
	completer->setCompletionMode(QCompleter::PopupCompletion);
	ui->lineEditFilter->setCompleter(completer);
	ui->lineEditFilter->setAttribute(Qt::WA_InputMethodEnabled, false);
	QRegExp rx("^(|[A-Za-z0-9~!@#$%^&*()_-+=<>,.\\/]+)$");
	QRegExpValidator *latitude = new QRegExpValidator(rx, this);
	ui->lineEditFilter->setValidator(latitude);
	m_actSearch = new QAction(QIcon(":/Icons/search.png"), "", this);
	ui->lineEditFilter->addAction(m_actSearch, QLineEdit::TrailingPosition);
}

void PacketInfo::PacketInfo::InitPieChartScreen()
{
	using namespace QtCharts;

	m_pieChartWindow = new QMainWindow;
	QSharedPointer<QPieSeries> m_pktSeries = QSharedPointer<QPieSeries>(new QPieSeries);
	m_chart = new QChart;
	m_chartView = new QChartView(m_chart);

	m_pieChartWindow->setVisible(false);
	m_pktSeries->setVisible(false);
	m_chart->setVisible(false);
	m_chartView->setVisible(false);

	m_chart->setTitle(QStringLiteral("各封包比例"));  //设置标题

	m_pieChartWindow->setCentralWidget(m_chartView);
	m_pieChartWindow->resize(800, 800);
	m_pieChartWindow->setWindowModality(Qt::NonModal);
}

// 显示设备列表
void PacketInfo::ShowNetwordDevice()
{
	if (pcap_findalldevs(&m_allDevices, m_errBuf) == PCAP_ERROR)		// 设备获取失败
	{
		QString item = "Error in pcap_findalldevs: " + QString(m_errBuf);
		ui->comboBoxSelectDevices->addItem(item);
	}
	else
	{
		ui->comboBoxSelectDevices->clear();
		for (m_device = m_allDevices; m_device != nullptr; m_device = m_device->next)
		{
			QString deviceInfo = m_device->name + QString(" ") + m_device->description;
			ui->comboBoxSelectDevices->addItem(deviceInfo);
		}
	}
}

// 获取所选的设备
bool PacketInfo::OpenSelectedDevice()
{
	if (!m_device)
		return false;

	if ((m_adhandle = pcap_open_live(m_device->name,		// const char * device：指定要打开的网络设备
		65536,														// int snaplen：指定要捕获的最大字节数。
		PCAP_OPENFLAG_PROMISCUOUS,			// int promisc：指定是否将接口置于 混杂模式(即 PCAP_OPENFLAG_PROMISCUOUS)
		1000,														// int to_ms：指定读取超时（以毫秒为单位）
		m_errBuf														// char *ebuf：用于返回错误或警告文本。
	)) == Q_NULLPTR)
	{
		pcap_freealldevs(m_allDevices);
		m_device = Q_NULLPTR;
		return false;
	}

	// 链路层只捕获以太网的数据包
	if (pcap_datalink(m_adhandle) != DLT_EN10MB)		// DLT_EN10MB表示以太网数据链路类型
	{
		pcap_freealldevs(m_allDevices);
		pcap_close(m_adhandle);
		m_device = Q_NULLPTR;
		m_adhandle = Q_NULLPTR;
		return false;
	}

	m_dumper = pcap_dump_open(m_adhandle, "output.pcap");
	if (m_dumper == Q_NULLPTR) 
	{
		ui->statusBar->showMessage("err");;
		return false;
	}

	ui->statusBar->showMessage(m_device->description);
	return true;
}

void PacketInfo::ClearList()
{
	for (DataPacket &pkt : pktList)
	{
		delete pkt.m_pktData;
		pkt.m_pktData = Q_NULLPTR;			// 没有会报错，应该是重复删内存了
	}
	QList<DataPacket>().swap(pktList);
}

void PacketInfo::ClearContents()
{
	ui->tableWidgetPacketList->clearContents();
	ui->tableWidgetPacketList->setRowCount(0);
	ui->tableWidgetDataInfo->clear();
	ui->tableWidgetDataInfo->setRowCount(0);
	ui->treeWidgetPktInfo->clear();
	m_rowNumber = 0;
}

void PacketInfo::SetActionState()
{
	ui->actOpen->setEnabled(false);
	ui->actSave->setEnabled(false);
	ui->actStart->setEnabled(false);
	ui->actStop->setEnabled(true);
	ui->actRestart->setEnabled(true);
}

void PacketInfo::ResetActionState()
{
	ui->actOpen->setEnabled(true);
	ui->actSave->setEnabled(true);
	ui->actStart->setEnabled(true);
	ui->actStop->setEnabled(false);
	ui->actRestart->setEnabled(false);
}

void PacketInfo::ClearDB()
{
	QSqlQuery query(m_database);
	if (!query.exec("DELETE FROM packets"))
		qDebug() << "DELETE FROM packets error";
}

void PacketInfo::SaveFile()
{
	if (m_rowNumber == 0)
	{
		QMessageBox warnMessage(QMessageBox::Warning, QStringLiteral("Warning"),
			QStringLiteral("没有数据，不能保存"));
		warnMessage.exec();
		return;
	}
	QString fileName{ QFileDialog::getSaveFileName(this, tr("Save File"), QDir::currentPath(), tr("pcap (*.pcap)")) };
	QFile srcFile{ "output.pcap" };
	QFile dstFile{ fileName };
	if (!srcFile.open(QIODevice::ReadOnly))
	{
		ui->statusBar->showMessage(QStringLiteral("文件打开失败"));
		return;
	}
	if (!dstFile.open(QIODevice::WriteOnly))
	{
		ui->statusBar->showMessage(QStringLiteral("文件打开失败"));
		return;
	}
	while (!srcFile.atEnd())
	{
		dstFile.write(srcFile.readLine());
	}
	m_isStart = false;
	srcFile.close();
	dstFile.close();
}

// 接受子线程的数据，在QTableWidget显示数据
void PacketInfo::RecvData(const DataPacket &pkt)
{
	pktList.push_back(pkt);
	int id{ m_rowNumber + 1 };
	QTime timeStamp{ QTime::fromString(pkt.GetTimeStamp()) };
	QString srcIp{ pkt.GetSrcAddr() };
	QString dstIp{ pkt.GetDesAddr() };
	QString type{ pkt.GetProtocolType() };
	quint16 length{ pkt.GetLength().toUShort()};
	QString info{ pkt.GetInfo() };
	
	QString qureyStr{ QString("INSERT INTO `packets` (`id`, `time`, `srcIp`, `dstIp`, `protocol`, `length`, `info`)") +
		QString("VALUES(:id, :time, :srcIp, :dstIp, :protocol, :length, :info)") };
	QSqlQuery query(qureyStr, m_database);
	query.prepare(qureyStr);
	query.bindValue(":id", id);
	query.bindValue(":time", timeStamp);
	query.bindValue(":srcIp", srcIp);
	query.bindValue(":dstIp", dstIp);
	query.bindValue(":protocol", type);
	query.bindValue(":length", length);
	query.bindValue(":info", info);
	if (!query.exec())
	{
		qDebug() << "Query execution error: " << query.lastError().text();
	}

	query.exec(QString("SELECT * FROM packets WHERE id = %1").arg(id));
	query.next();
	ui->tableWidgetPacketList->insertRow(m_rowNumber);
	ui->tableWidgetPacketList->setItem(m_rowNumber, 0, new QTableWidgetItem(query.value("id").toString()));
	ui->tableWidgetPacketList->setItem(m_rowNumber, 1, new QTableWidgetItem(query.value("time").toString()));
	ui->tableWidgetPacketList->setItem(m_rowNumber, 2, new QTableWidgetItem(query.value("srcIp").toString()));
	ui->tableWidgetPacketList->setItem(m_rowNumber, 3, new QTableWidgetItem(query.value("dstIp").toString()));
	ui->tableWidgetPacketList->setItem(m_rowNumber, 4, new QTableWidgetItem(query.value("protocol").toString()));
	ui->tableWidgetPacketList->setItem(m_rowNumber, 5, new QTableWidgetItem(query.value("length").toString()));
	ui->tableWidgetPacketList->setItem(m_rowNumber, 6, new QTableWidgetItem(query.value("info").toString()));

	auto calPktNum = [&] {
		if (!m_pktNum.contains(type))
			m_pktNum.insert(type, 0);
		++m_pktNum[type];
		};

	QColor color{};
	if (type == "ARP")
	{
		calPktNum();
		color = QColor(255, 235, 205);
	}
	else if (type == "ICMP")
	{
		calPktNum();
		color = QColor(204, 204, 244);
	}
	else if (type == "TCP")
	{
		calPktNum();
		color = QColor(201, 255, 255);
	}
	else if (type == "UDP")
	{
		calPktNum();
		color = QColor(255, 255, 102);
	}
	else if (type == "DNS")
	{
		calPktNum();
		color = QColor(202, 235, 216);
	}

	for (int i{}; i != kColumnCount; ++i)
		ui->tableWidgetPacketList->item(m_rowNumber, i)->setBackground(color);
	++m_rowNumber;
}

void PacketInfo::RecvPkt(QByteArray &pktArray, bool &ok)
{
	if (!m_isStart)
	{
		ui->statusBar->showMessage(QStringLiteral("请先打开网卡，再发送网络封包"));
		return;
	}
	ok = true;
	emit RecvPktOk(ok);
	pcap_sendpacket(m_adhandle, (const u_char *)pktArray.data(), pktArray.size());
	ui->statusBar->showMessage(QStringLiteral("发送成功构造的网络封包"));
	pktArray.clear();
}

void PacketInfo::ShowPieChart()
{
	using namespace QtCharts;

	SPPieSeries newSeries{ SPPieSeries(new QPieSeries, [&](QPieSeries *series) {
	if (m_chart && m_pktSeries) {
		m_chart->removeSeries(series);
	}
	delete series;
		}) };

	m_pieChartWindow->setVisible(true);
	newSeries->setVisible(true);
	m_chart->setVisible(true);
	m_chartView->setVisible(true);

	newSeries->append(QString("ARP: %1").arg(m_pktNum["ARP"]), m_pktNum["ARP"]);
	newSeries->append(QString("ICMP: %1").arg(m_pktNum["ICMP"]), m_pktNum["ICMP"]);
	newSeries->append(QString("TCP: %1").arg(m_pktNum["TCP"]), m_pktNum["TCP"]);
	newSeries->append(QString("UDP: %1").arg(m_pktNum["UDP"]), m_pktNum["UDP"]);
	newSeries->append(QString("DNS: %1").arg(m_pktNum["DNS"]), m_pktNum["DNS"]);
	newSeries->setLabelsVisible();  //设置标签可见
	newSeries->setLabelsPosition(QPieSlice::LabelInsideNormal);

	std::array<QtCharts::QPieSlice *, 5> pSliceArr;
	for (int i{}; i != pSliceArr.size(); ++i)
	{
		pSliceArr[i] = newSeries->slices().at(i);
	}
	pSliceArr[0]->setColor(QColor(255, 235, 205));  //设置颜色
	pSliceArr[1]->setColor(QColor(204, 204, 244));
	pSliceArr[2]->setColor(QColor(201, 255, 255));
	pSliceArr[3]->setColor(QColor(255, 255, 102));
	pSliceArr[4]->setColor(QColor(202, 235, 216));

	m_pktSeries = newSeries;
	m_chart->addSeries(m_pktSeries.get());

	m_chartView->setRenderHint(QPainter::Antialiasing); //设置渲染属性
	m_pieChartWindow->show();
}

void PacketInfo::ActToStart(PacketHandle *pktHandle)
{
	m_isStart = true;
	ClearContents();
	ClearList();
	m_pktNum.clear();

	if (bool ok = OpenSelectedDevice(); !ok)
	{
		QMessageBox warnMessage(QMessageBox::Warning,
			"Warning", QStringLiteral("请先正确地选择网卡"));
		warnMessage.exec();
		ResetActionState();
	}
	else
	{
		m_isDumper = false;
		m_pktHandle->SetFlag();
		m_pktHandle->SetDumperState(m_isDumper);
		m_pktHandle->SetDumper(m_dumper);
		m_pktHandle->SetAdHandle(m_adhandle);
		m_pktHandle->start();
		ui->comboBoxSelectDevices->setEnabled(false);
		SetActionState();
	}

	ClearDB();
}

// 获取设备索引
void PacketInfo::on_comboBoxSelectDevices_currentIndexChanged(int index)
{
	int i = 0;
	for (m_device = m_allDevices; i != index; m_device = m_device->next, ++i)
	{
	}
	emit SendNicName(m_device->name);
}

void PacketInfo::on_actOpen_triggered()
{
	ClearDB();
	QString fileName{ QFileDialog::getOpenFileName(this, QStringLiteral("打开文件"),
	QDir::currentPath(), QStringLiteral("pcap (*.pcap)")) };
	m_adhandle = pcap_open_offline(fileName.toUtf8(), m_errBuf);
	if (!m_adhandle)
	{
		ui->statusBar->showMessage(QStringLiteral("文件打开失败"));
		return;
	}
	ui->statusBar->showMessage(QStringLiteral("文件打开成功"));

	m_isStart = false;
	m_isDumper = true;
	ClearContents();
	ClearList();
	m_pktNum.clear();

	m_pktHandle->SetFlag();
	m_pktHandle->SetDumperState(m_isDumper);;
	m_pktHandle->SetAdHandle(m_adhandle);
	m_pktHandle->start();
}

void PacketInfo::on_actSave_triggered()
{
	SaveFile();
}

void PacketInfo::on_actStart_triggered()
{
	ActToStart(m_pktHandle);
}

void PacketInfo::on_actStop_triggered()
{
	m_isStart = false;
	m_updateChartTime->stop();
	m_pktHandle->ResetFlag();
	m_pktHandle->quit();
	m_pktHandle->wait();
	pcap_close(m_adhandle);
	m_adhandle = Q_NULLPTR;
	ui->comboBoxSelectDevices->setEnabled(true);
	ResetActionState();
}

void PacketInfo::on_actRestart_triggered()
{
	ActToStart(m_pktHandle);
}

void PacketInfo::on_actUp_triggered()
{
	int selectedRow{ ui->tableWidgetPacketList->currentRow() };
	if (selectedRow > 0)
	{
		ui->tableWidgetPacketList->setCurrentCell(selectedRow - 1, 0);
		on_tableWidgetPacketList_cellClicked(selectedRow - 1, 0);
	}
}

void PacketInfo::on_actDown_triggered()
{
	int selectedRow{ ui->tableWidgetPacketList->currentRow() };
	if (selectedRow < ui->tableWidgetPacketList->rowCount() - 1)
	{
		ui->tableWidgetPacketList->setCurrentCell(selectedRow + 1, 0);
		on_tableWidgetPacketList_cellClicked(selectedRow + 1, 0);
	}
}

void PacketInfo::on_actTop_triggered()
{
	ui->tableWidgetPacketList->setCurrentCell(0, 0);
	on_tableWidgetPacketList_cellClicked(0, 0);
}

void PacketInfo::on_actBottom_triggered()
{
	int selectedRow{ ui->tableWidgetPacketList->rowCount() - 1 };
	ui->tableWidgetPacketList->setCurrentCell(selectedRow, 0);
	on_tableWidgetPacketList_cellClicked(selectedRow, 0);
}

void PacketInfo::on_actChart_triggered()
{
	if (m_isStart && !m_isTimeStart)
	{
		m_updateChartTime->start(100);
	}
	if (m_isStart && m_isTimeStart)
	{
		m_updateChartTime->stop();
	}
	if (m_rowNumber)
		ShowPieChart();
	m_isTimeStart = !m_isTimeStart;

}

void PacketInfo::on_actCreate_triggered()
{
	m_cfpkt->show();
}

void PacketInfo::on_lineEditFilter_textChanged()
{
	QString text{ ui->lineEditFilter->text().toUpper() };
	QString ipText{ text.left(8) };
	QString ipAddrText{ text.left(9) };
	if (text == "" || text == QStringLiteral("UDP") || text == QStringLiteral("TCP") || text == QStringLiteral("DNS")
		|| text == QStringLiteral("ARP") || text == QStringLiteral("ICMP") || ipText == QStringLiteral("IP.SRC==")
		|| ipText == QStringLiteral("IP.DST==") || ipAddrText == QStringLiteral("IP.ADDR=="))
	{
		ui->lineEditFilter->setStyleSheet("QLineEdit {background-color: rgb(160, 255,160);}");
	}
	else
		ui->lineEditFilter->setStyleSheet("QLineEdit {background-color: rgb(255,180,180);}");
}

void PacketInfo::on_lineEditFilter_returnPressed()
{
	QString text{ ui->lineEditFilter->text().toUpper() };
	auto filterItems = [=](const int col) {
		for (int row{}; row != ui->tableWidgetPacketList->rowCount(); ++row)
		{
			text == ui->tableWidgetPacketList->item(row, col)->text() ?
				ui->tableWidgetPacketList->setRowHidden(row, false) :
				ui->tableWidgetPacketList->setRowHidden(row, true);
		}
		};

	if (text == "")
	{
		for (int row{}; row != ui->tableWidgetPacketList->rowCount(); ++row)
			ui->tableWidgetPacketList->setRowHidden(row, false);
	}
	if (!m_isStart)
	{
		if (text == QStringLiteral("UDP") || text == QStringLiteral("TCP") || text == QStringLiteral("DNS")
			|| text == QStringLiteral("ARP") || text == QStringLiteral("ICMP"))
		{
			filterItems(4);
		}
		else if (QString tmpText{ text.left(8) }, ip{};
			tmpText == QStringLiteral("IP.SRC==") || tmpText == QStringLiteral("IP.DST=="))
		{
			ip = text.right(text.size() - 8);

			if (tmpText == QStringLiteral("IP.SRC=="))
				filterItems(2);
			else if (tmpText == QStringLiteral("IP.DST=="))
				filterItems(3);
		}
		else if (QString tmpText{ text.left(9) }, ip{}; tmpText == QStringLiteral("IP.ADDR=="))
		{
			ip = text.right(text.size() - 9);
			for (int i{}; i != ui->tableWidgetPacketList->rowCount(); ++i)
			{
				ip == ui->tableWidgetPacketList->item(i, 2)->text() ||
					ip == ui->tableWidgetPacketList->item(i, 3)->text() ?
					ui->tableWidgetPacketList->setRowHidden(i, false) :
					ui->tableWidgetPacketList->setRowHidden(i, true);
			}
		}
	}
}

void PacketInfo::on_tableWidgetPacketList_cellClicked(int row, int column)
{
	Q_UNUSED(column);

	if (row < 0 || row >= m_rowNumber)
		return;

	ui->treeWidgetPktInfo->clear();

	QTreeWidgetItem *ethRoot = GetEthTreeInfo(row);

	if (QString protocol{ pktList[row].GetProtocolType() }; protocol == "ARP")
	{
		GetArpTreeInfo(row);
	}
	else					// ip
	{
		int ipDataLength{};
		GetIpTreeInfo(row, ipDataLength);

		if (protocol == "TCP")
			GetTcpTreeInfo(row, ipDataLength);
		else if (protocol == "UDP" || protocol == "DNS")
		{
			GetUdpTreeInfo(row);

			if (protocol == "DNS")
				GetDnsTreeInfo(row);
		}
		else if (protocol == "ICMP")
			GetIcmpTreeInfo(row, ipDataLength);
	}

	int paddingNum{};
	GetEthPadding(row, ethRoot, paddingNum);
	GetDataInfo(row, paddingNum);
}

QTreeWidgetItem *PacketInfo::GetEthTreeInfo(const int &selectedRow)
{
	QString ethSrcMacStr{ pktList[selectedRow].GetEthSrcMac() };
	QString ethDesMacStr{ pktList[selectedRow].GetEthDesMac() };
	QString ethTypeStr{ pktList[selectedRow].GetEthType() };

	QTreeWidgetItem* ethRoot{ new QTreeWidgetItem{
		{ QStringLiteral("Ethernet II, Src: ") + ethSrcMacStr + QStringLiteral(", Dst: ") + ethDesMacStr} } };
	ui->treeWidgetPktInfo->addTopLevelItem(ethRoot);
	QTreeWidgetItem* ethDesMac{ new QTreeWidgetItem{ {QStringLiteral("Destination: ") + ethDesMacStr} } };
	QTreeWidgetItem* ethSrcMac{ new QTreeWidgetItem{ {QStringLiteral("Source: ") + ethSrcMacStr} } };
	QTreeWidgetItem* ethType{ new QTreeWidgetItem{ {QStringLiteral("Type: ") + ethTypeStr} } };
	ethRoot->addChildren({ ethDesMac, ethSrcMac, ethType });
	return ethRoot;
}

void PacketInfo::GetArpTreeInfo(const int &selectedRow)
{
	QString arpOpcode{ pktList[selectedRow].GetArpOperationCode() };
	QTreeWidgetItem* arpRoot{ new QTreeWidgetItem(
					{QStringLiteral("Address Resolution Protocol (") + arpOpcode + ")"}) };
	ui->treeWidgetPktInfo->addTopLevelItem(arpRoot);

	arpRoot->addChildren({
		new QTreeWidgetItem({QStringLiteral("Hardware Type: ") + pktList[selectedRow].GetArpHardewareType()}),
		new QTreeWidgetItem({QStringLiteral("Protocol Type: ") + pktList[selectedRow].GetArpProtocolType()}),
		new QTreeWidgetItem({QStringLiteral("Hardware Size: ") + pktList[selectedRow].GetArpMacLength() }),
		new QTreeWidgetItem({QStringLiteral("Protocol Size: ") + pktList[selectedRow].GetArpIpLength()}),
		new QTreeWidgetItem({QStringLiteral("Opcode: ") + arpOpcode + " (" +
						 (arpOpcode == QStringLiteral("request") ? "1)" : "2)") }),
		new QTreeWidgetItem({QStringLiteral("Sender MAC address: ") + pktList[selectedRow].GetArpSourceMac()}),
		new QTreeWidgetItem({QStringLiteral("Sender IP address: ") + pktList[selectedRow].GetArpSourceIp()}),
		new QTreeWidgetItem({QStringLiteral("Target MAC address: ") + pktList[selectedRow].GetArpDestinationMac()}),
		new QTreeWidgetItem({QStringLiteral("Target IP address: ") + pktList[selectedRow].GetArpDestinationIp()}),
		});
}

void PacketInfo::GetIpTreeInfo(const int &selectedRow, int &ipDataLength)
{
	QString ipTotalLength = pktList[selectedRow].GetIpTotalLength();
	ipDataLength = ipTotalLength.toUtf8().toInt() - 20;
	QString ipHeaderLengthInfo{};
	QString ipVersion{ pktList[selectedRow].GetIpVersion() };
	QString ipHeaderlength{ pktList[selectedRow].GetIpHeadlength(ipHeaderLengthInfo) };
	QString srcIp{ pktList[selectedRow].GetIpSrcIp() };
	QString desIp{ pktList[selectedRow].GetIpDesIp() };

	QTreeWidgetItem *ipRoot{ new QTreeWidgetItem({QStringLiteral("Internet Protocol Version ") +
							 ipVersion + QStringLiteral(", Src: ") + srcIp + QStringLiteral(", Dst: ") + desIp}) };
	ui->treeWidgetPktInfo->addTopLevelItem(ipRoot);

	ipRoot->addChildren({
		new QTreeWidgetItem({ToBin(ipVersion.toUtf8().toInt(), 4) + QStringLiteral(" . . . . = Version: ") + ipVersion}),
		new QTreeWidgetItem({". . . .  " + ToBin(ipHeaderlength.toUtf8().toInt() , 4) +
												QStringLiteral("= Header Length: ") + ipHeaderLengthInfo}),
		new QTreeWidgetItem({QStringLiteral("Differentiated Services Field: 0x") +
											 pktList[selectedRow].GetIpServiceType()}),
		new QTreeWidgetItem({QStringLiteral("Total Length: ") + ipTotalLength}),
		new QTreeWidgetItem({QStringLiteral("Identification: 0x") + pktList[selectedRow].GetIpIdentification()})
		});

	QString flags{ pktList[selectedRow].GetIpFlags() };
	QString reservedBit{ pktList[selectedRow].GetIpFlagsReservedBit() };
	QString DF{ pktList[selectedRow].GetIpFlagsDF() };
	QString MF{ pktList[selectedRow].GetIpFlagsMF() };

	QString flagStatus{};
	if (flags == "2")
		flagStatus += QStringLiteral("Don't fragment ");
	else if (flags == "4")
		flagStatus += QStringLiteral("More fragments");

	QTreeWidgetItem *flagItem{
		new QTreeWidgetItem({reservedBit + DF + MF +
		QStringLiteral(" .   . . . . = Flags: 0x") + flags + (flagStatus == "" ? "" : ", ") + flagStatus}) };
	ipRoot->addChild(flagItem);

	flagItem->addChildren({
		new QTreeWidgetItem({reservedBit + ". . .   . . . . = " +
						QStringLiteral("Reserved bit: ") + (reservedBit == "1" ? "Set" : "No set")}),
		new QTreeWidgetItem({"." + DF + " . .   . . . . = " +
						QStringLiteral("Don't fragment: ") + (DF == "1" ? "Set" : "No set")}),
		new QTreeWidgetItem({". ." + MF + ".    . . . . = " +
						QStringLiteral("More fragments: ") + (MF == "1" ? "Set" : "No set")}),
		});

	QString ipOffset{ pktList[selectedRow].GetIpOffset() };
	ipRoot->addChildren({
		new QTreeWidgetItem({". . .  " + ToBin(ipOffset.toUtf8().toInt(), 13) + " =" +
						QStringLiteral(" Fragment Offset: ") + ipOffset}),
		new QTreeWidgetItem({QStringLiteral("Time To Live: ") + pktList[selectedRow].GetIpTTL()}),
		new QTreeWidgetItem({QStringLiteral("Protocol: ") + pktList[selectedRow].GetIpProtocol()}),
		new QTreeWidgetItem({QStringLiteral("Header Checksum: 0x") + pktList[selectedRow].GetIpChecksum()}),
		new QTreeWidgetItem({QStringLiteral("Source Address: ") + srcIp}),
		new QTreeWidgetItem({QStringLiteral("Destination Address: ") + desIp}),
		});
}

void PacketInfo::GetTcpTreeInfo(const int &selectedRow, const int &ipDataLength)
{
	QString tcpSrcPort{ pktList[selectedRow].GetTcpSrcPort() };
	QString tcpDesPort{ pktList[selectedRow].GetTcpDesPort() };
	QString tcpSeq{ pktList[selectedRow].GetTcpSeq() };
	QString tcpAck{ pktList[selectedRow].GetTcpAck() };
	QString tcpHeaderLengthInfo{};
	QString tcpHeaderLength{ pktList[selectedRow].GetTcpHeaderLength(tcpHeaderLengthInfo) };
	int tcpDataLength{ ipDataLength - tcpHeaderLength.toUtf8().toInt() * 4 };
	QTreeWidgetItem *tcpRoot{ new QTreeWidgetItem({
		"Transmission Control Protocol, Src Port: " + tcpSrcPort + ", Dst Port: " +
		tcpDesPort + ", Seq: " + tcpSeq + ", Ack: " + tcpAck + ", Len: " + QString::number(tcpDataLength)}) };
	ui->treeWidgetPktInfo->addTopLevelItem(tcpRoot);
	tcpRoot->addChildren({
		new QTreeWidgetItem({QStringLiteral("Source Port: ") + tcpSrcPort}),
		new QTreeWidgetItem({QStringLiteral("Destination Port: ") + tcpDesPort}),
		new QTreeWidgetItem({QStringLiteral("Sequence Number (row): ") + tcpSeq}),
		new QTreeWidgetItem({QStringLiteral("Acknowledgment Number (row): ") + tcpAck}),
		new QTreeWidgetItem({ToBin(tcpHeaderLength.toUtf8().toInt(), 4) +
					QStringLiteral(".... = Header Length: ") + tcpHeaderLengthInfo}),
		});

	QString tcpFlags{ pktList[selectedRow].GetTcpFlags() };
	QString tcpFlagsFin{ pktList[selectedRow].GetTcpFlagsFIN() };
	QString tcpFlagsSyn{ pktList[selectedRow].GetTcpFlagsSYN() };
	QString tcpFlagsReset{ pktList[selectedRow].GetTcpFlagsRST() };
	QString tcpFlagsPush{ pktList[selectedRow].GetTcpFlagsPSH() };
	QString tcpFlagsAck{ pktList[selectedRow].GetTcpFlagsACK() };
	QString tcpFlagsUrgent{ pktList[selectedRow].GetTcpFlagsURG() };
	QString tcpFlagsECE{ pktList[selectedRow].GetTcpFlagsECE() };
	QString tcpFlagsCWR{ pktList[selectedRow].GetTcpFlagsCWR() };
	QString tcpFlagsAECN{ pktList[selectedRow].GetTcpFlagsAECN() };
	QString tcpFlagsInfo{};

	if (tcpFlagsFin == "1")
		tcpFlagsInfo += "FIN, ";
	if (tcpFlagsSyn == "1")
		tcpFlagsInfo += "SYN, ";
	if (tcpFlagsReset == "1")
		tcpFlagsInfo += "RST, ";
	if (tcpFlagsPush == "1")
		tcpFlagsInfo += "PSH, ";
	if (tcpFlagsAck == "1")
		tcpFlagsInfo += "ACK, ";
	if (tcpFlagsUrgent == "1")
		tcpFlagsInfo += "UGR, ";
	if (tcpFlagsECE == "1")
		tcpFlagsInfo += "ECE, ";
	if (tcpFlagsCWR == "1")
		tcpFlagsInfo += "CWR, ";
	if (tcpFlagsAECN == "1")
		tcpFlagsInfo += "AECN, ";
	if (tcpFlagsInfo != "")
		tcpFlagsInfo = tcpFlagsInfo.left(tcpFlagsInfo.size() - 2);

	QTreeWidgetItem *flagsRoot{ new QTreeWidgetItem({QStringLiteral("Flags: 0x") +
			 tcpFlags + " (" + tcpFlagsInfo + ")"}) };
	tcpRoot->addChild(flagsRoot);
	flagsRoot->addChildren({
		new QTreeWidgetItem({QStringLiteral("000.   . . . .   . . . . = Reserved: Not set")}),
		new QTreeWidgetItem({QStringLiteral(". . .") + tcpFlagsAECN +
			("   . . . .   . . . . = Accurate ECN : ") + (tcpFlagsAECN == "1" ? "Set" : "Not set")}),
		new QTreeWidgetItem({QStringLiteral(". . . .   ") + tcpFlagsCWR +
			(". . .   . . . . = Congestion Window Reduced : ") + (tcpFlagsCWR == "1" ? "Set" : "Not set")}),
		new QTreeWidgetItem({QStringLiteral(". . . .   . ") + tcpFlagsECE +
			(". .   . . . . = ECN - Echo: ") + (tcpFlagsECE == "1" ? "Set" : "Not set")}),
		new QTreeWidgetItem({QStringLiteral(". . . .   . . ") + tcpFlagsUrgent +
			(".   . . . . = Urgent: ") + (tcpFlagsUrgent == "1" ? "Set" : "Not set")}),
		new QTreeWidgetItem({QStringLiteral(". . . .   . . . ") + tcpFlagsAck +
			("  . . . . = Acknowledgment: ") + (tcpFlagsAck == "1" ? "Set" : "Not set")}),
		new QTreeWidgetItem({QStringLiteral(". . . .   . . . .  ") + tcpFlagsPush +
			(" . . . = Push: ") + (tcpFlagsPush == "1" ? "Set" : "Not set")}),
		new QTreeWidgetItem({QStringLiteral(". . . .   . . . .   .") + tcpFlagsReset +
			(" . . = Reset: ") + (tcpFlagsReset == "1" ? "Set" : "Not set")}),
		new QTreeWidgetItem({QStringLiteral(". . . .   . . . .   . . ") + tcpFlagsSyn +
			(". = Syn: ") + (tcpFlagsSyn == "1" ? "Set" : "Not set")}),
		new QTreeWidgetItem({QStringLiteral(". . . .   . . . .   . . .") + tcpFlagsFin +
			(" = Fin: ") + (tcpFlagsFin == "1" ? "Set" : "Not set")}),
		});

	tcpRoot->addChildren({
		new QTreeWidgetItem({QStringLiteral("Window: ") + pktList[selectedRow].GetTcpWinSize()}),
		new QTreeWidgetItem({QStringLiteral("Checksum: 0x") + pktList[selectedRow].GetTcpChecksum()}),
		new QTreeWidgetItem({QStringLiteral("Urgent Pointer: ") + pktList[selectedRow].GetTcpUrgent()}),
		});
}

void PacketInfo::GetUdpTreeInfo(const int &selectedRow)
{
	QString udpSrcPort{ pktList[selectedRow].GetUdpSrcPort() };
	QString udpDesPort{ pktList[selectedRow].GetUdpDesPort() };

	QTreeWidgetItem *udpRoot{
		new QTreeWidgetItem({
			QStringLiteral("User Datagram Protocol, Src Port: ") +
			udpSrcPort + QStringLiteral(", Dst Port: ") + udpDesPort
		}) };
	ui->treeWidgetPktInfo->addTopLevelItem(udpRoot);
	QString udpDataLen{ pktList[selectedRow].GetUdpDataLength() };
	udpRoot->addChildren({
		new QTreeWidgetItem({("Source Port: ") + udpSrcPort}),
		new QTreeWidgetItem({("Destination Port: ") + udpDesPort}),
		new QTreeWidgetItem({("Length: ") + udpDataLen}),
		new QTreeWidgetItem({("Checksum: 0x") + pktList[selectedRow].GetUdpChecksum()}),
		new QTreeWidgetItem({("UDP payload (") +
				QString::number(udpDataLen.toUtf8().toInt() - 8) + QStringLiteral(" bytes)")}),
		});
}

void PacketInfo::GetDnsTreeInfo(const int &selectedRow)
{
	QString dnsFlagsQR{ pktList[selectedRow].GetDnsFlagsQR() };
	QString dnsType{ dnsFlagsQR == "0" ? "(query)" : "(response)" };
	QTreeWidgetItem *dnsRoot{
		new QTreeWidgetItem({QStringLiteral("Domain Name System ") + dnsType}) };
	ui->treeWidgetPktInfo->addTopLevelItem(dnsRoot);

	QString dnsQuestionRRs{ pktList[selectedRow].GetDnsQuestionRRs() };
	QString dnsAnswerRRs{ pktList[selectedRow].GetDnsAnswerRRs() };
	dnsRoot->addChildren({
		new QTreeWidgetItem({QStringLiteral("Transaction ID: 0x") +
			pktList[selectedRow].GetDnsTransactionId()}),
		new QTreeWidgetItem({QStringLiteral("Questions: ") + dnsQuestionRRs}),
		new QTreeWidgetItem({QStringLiteral("Answer RRs: ") + dnsAnswerRRs}),
		new QTreeWidgetItem({QStringLiteral("Authority RRs: ") +
			pktList[selectedRow].GetDnsAuthorityRRs()}),
		new QTreeWidgetItem({QStringLiteral("Additional RRs: ") +
			pktList[selectedRow].GetDnsAdditionalRRs()}),
		});

	QTreeWidgetItem *dnsFlagsRoot{
		new QTreeWidgetItem({QStringLiteral("Flags: 0x") + pktList[selectedRow].GetDnsFlags()})
	};
	dnsRoot->insertChild(1, dnsFlagsRoot);

	dnsFlagsRoot->addChild({
			new QTreeWidgetItem({dnsFlagsQR +
			QStringLiteral(". . .   . . . .   . . . .   . . . . = Response: Message is a ") +
			(dnsFlagsQR == "0" ? "query" : "response")}) }
	);

	QString dnsOpcode{ pktList[selectedRow].GetDnsFlagsOpcode() };
	QString dnsOpcodeInfo{};
	QString dnsOpTmp{};
	QString val{ ToBin(dnsOpcode.toUtf8().toInt(), 4) };
	for (int i{}; i != 4; ++i)
	{
		dnsOpTmp += val[i];
		if (i == 2)
			dnsOpTmp += " ";
	}
	if (dnsOpcode == "0")
		dnsOpcodeInfo = QStringLiteral("Standard query (0)");
	else if (dnsOpcode == "1")
		dnsOpcodeInfo = QStringLiteral("Reverse query (1)");
	else if (dnsOpcode == "2")
		dnsOpcodeInfo = QStringLiteral("Status request (2)");
	dnsFlagsRoot->addChild({
		new QTreeWidgetItem({". " + dnsOpTmp +
		QStringLiteral(" . . .   . . . .   . . . . = Opcode: ") + dnsOpcodeInfo}) }
	);

	QString dnsflagsTC{ pktList[selectedRow].GetDnsFlagsTC() };
	QString dnsflagsRD{ pktList[selectedRow].GetDnsFlagsRD() };
	dnsFlagsRoot->addChildren({
		new QTreeWidgetItem({ ". . . .   . . " + dnsflagsTC + ".   . . . .   . . . . = Truncated: " +
			(dnsflagsTC == "1" ? "Message is truncated" : "Message is not truncated")}),
		new QTreeWidgetItem({ ". . . .   . . . " + dnsflagsRD + "  . . . .   . . . . = Recursion desired: " +
			(dnsflagsRD == "1" ? "Do query recursively" : "Do query not recursively")})
		});

	QString dnsFlagsZ = pktList[selectedRow].GetDnsFlagsZ();
	dnsFlagsRoot->addChild(
		new QTreeWidgetItem({ ". . . .   . . . .   ." + dnsFlagsZ +
		" . .   . . . . = Z: reserved (" + dnsFlagsZ + ")" }));

	QString dnsFlagsCD = pktList[selectedRow].GetDnsFlagsCD();
	dnsFlagsRoot->addChild(
		new QTreeWidgetItem({ ". . . .   . . . .   . . ." + dnsFlagsCD +
		"  . . . . = Non-authenticated data: " + (dnsFlagsCD == "0" ? "Unacceptable" : "Acceptable") }));

	if (dnsFlagsQR == "1")
	{
		QString dnsFlagsAA{ pktList[selectedRow].GetDnsFlagsAA() };
		dnsFlagsRoot->insertChild(2,
			new QTreeWidgetItem({ ". . . .   . " + dnsFlagsAA
				+ ". .   . . . .   . . . . = Authoritative: "
				+ (dnsFlagsAA == "1" ? "Server is an authority for domain" :
				"Server is not an authority for domain") }));

		QString dnsFlagsRA = pktList[selectedRow].GetDnsFlagsRA();
		dnsFlagsRoot->insertChild(5,
			new QTreeWidgetItem({ ". . . .   . . . .  " + dnsFlagsRA + " . . .   . . . . = Recursion available: " +
			(dnsFlagsRA == "1" ? "Server can do recursive queries" : "Server can not do recursive queries") }));

		QString dnsFlagsAD = pktList[selectedRow].GetDnsFlagsAD();
		dnsFlagsRoot->insertChild(7,
			new QTreeWidgetItem({ ". . . .   . . . .   . ." + dnsFlagsAD +
			" .  . . . . = Answer authenticated: " +
				(dnsFlagsAD == "0" ? "Answer/authority portion was not authenticated by the server"
					: "Answer/authority portion was authenticated by the server") }));

		QString dnsRcode{ pktList[selectedRow].GetDnsFlagsRcode() };
		QString dnsRcodeInfo{};
		if (dnsRcode == "0") dnsRcodeInfo = "No error (0)";
		else if (dnsRcode == "1") dnsRcodeInfo = "Format error (1)";
		else if (dnsRcode == "2") dnsRcodeInfo = "Server failure (2)";
		else if (dnsRcode == "3") dnsRcodeInfo = "Name Error (3)";
		else if (dnsRcode == "4") dnsRcodeInfo = "Not Implemented (4)";
		else if (dnsRcode == "5") dnsRcodeInfo = "Refused (5)";
		int code = dnsRcode.toUtf8().toInt();
		QString bCode{ ToBin(dnsRcode.toUtf8().toInt(), 4) };
		while (bCode.size() < 4)
			bCode += "0";
		dnsFlagsRoot->insertChild(9,
			new QTreeWidgetItem({ ". . . .   . . . .   . . . . " + bCode + "= Reply code: " + dnsRcodeInfo }));
	}

	int dnsOffset{};
	if (dnsQuestionRRs == "1")
	{
		QTreeWidgetItem *dnsQueriesRoot{ new QTreeWidgetItem({ QStringLiteral("Queries") }) };
		dnsRoot->addChild(dnsQueriesRoot);

		QString dnsQueriesName{};
		u_short dnsQueriesTypeNumber{};
		u_short dnsQueriesClassNumber{};

		pktList[selectedRow].GetDnsQueriesDomain(dnsQueriesName,
			dnsQueriesTypeNumber, dnsQueriesClassNumber);
		QString dnsQueriesType{ pktList[selectedRow].GetDnsDomainType(dnsQueriesTypeNumber) };
		QString dnsQueriesClass{ pktList[selectedRow].GetDnsDomainClass(dnsQueriesClassNumber) };

		QTreeWidgetItem *dnsQueriesInfoRoot{ new QTreeWidgetItem({dnsQueriesName +
			QStringLiteral(" type: ") + dnsQueriesType + QStringLiteral(", class: ") + dnsQueriesClass }) };
		dnsQueriesRoot->addChild(dnsQueriesInfoRoot);
		dnsQueriesInfoRoot->addChildren({
			new QTreeWidgetItem({QStringLiteral("Name: ") + dnsQueriesName}),
			new QTreeWidgetItem({QStringLiteral("[Name Length: ") +
				QString::number(dnsQueriesName.size()) + "]" }),
			new QTreeWidgetItem({QStringLiteral("Type: ") + dnsQueriesType + " (" +
				QString::number(dnsQueriesTypeNumber) + ")"}),
			new QTreeWidgetItem({QStringLiteral("Class: ") + dnsQueriesClass +
				QStringLiteral(" (0x000") + QString::number(dnsQueriesClassNumber) + ")"})
			});
		dnsOffset += (2 + dnsQueriesName.size() + 2 + 2);		// 第一个 2 为Questions字段，后面两个2 为上面的type，class
	}
	if (int dnsAnswerNumber{ dnsAnswerRRs.toUtf8().toInt() }; dnsAnswerNumber > 0)
	{
		QTreeWidgetItem *dnsAnswerRoot{ new QTreeWidgetItem({"Answers"}) };
		dnsRoot->addChild(dnsAnswerRoot);

		for (int i{}; i < dnsAnswerNumber; ++i)
		{
			QString dnsAnswerName1;
			u_short dnsAnswerTypeNumber;
			u_short dnsAnswerClassNumber;
			u_int dnsAnswerTTL;
			u_short dnsAnswerLength;
			QString dnsAnswerName2;

			int dnsTmpOffset{ pktList[selectedRow].GetDnsAnswersDomain(
				dnsOffset, dnsAnswerName1,dnsAnswerTypeNumber,
				dnsAnswerClassNumber,  dnsAnswerTTL, dnsAnswerLength, dnsAnswerName2) };
			dnsOffset += dnsTmpOffset;
			QString dnsAnswerType{ pktList[selectedRow].GetDnsDomainType(dnsAnswerTypeNumber) };
			QString dnsAnswerClass{ pktList[selectedRow].GetDnsDomainClass(dnsAnswerClassNumber) };
			QString dnsAnswerTypeInfo{};
			if (dnsAnswerTypeNumber == 1)
				dnsAnswerTypeInfo = "Addr";
			else if (dnsAnswerTypeNumber == 5)
				dnsAnswerTypeInfo = "Cname";
			else if (dnsAnswerTypeNumber == 28)
				dnsAnswerTypeInfo = "AAAA Address";

			QTreeWidgetItem *dnsAnswerInfoRoot{ new QTreeWidgetItem({
			dnsAnswerName1 + QStringLiteral(": type ") + dnsAnswerType +
				QStringLiteral(", class ") + dnsAnswerClass + ", " +
				dnsAnswerTypeInfo + " " + dnsAnswerName2
			}) };
			dnsAnswerRoot->addChild(dnsAnswerInfoRoot);
			dnsAnswerInfoRoot->addChildren({
				new QTreeWidgetItem({QStringLiteral("Name: ") + dnsAnswerName1}),
				new QTreeWidgetItem({QStringLiteral("Type: ") + dnsAnswerType + " (" +
				QString::number(dnsAnswerTypeNumber) + ")"}),
				new QTreeWidgetItem({QStringLiteral("Class: ") + dnsAnswerClass + " (0x000" +
					QString::number(dnsAnswerClassNumber) + ")"}),
				new QTreeWidgetItem({QStringLiteral("Time to live: ") + QString::number(dnsAnswerTTL) +
					" (" + QString::number(dnsAnswerTTL) + " seconds)"}),
				new QTreeWidgetItem({QStringLiteral("Data length: ") + QString::number(dnsAnswerLength)}),
				new QTreeWidgetItem({dnsAnswerTypeInfo + ": " + dnsAnswerName2}),
				});
		}
	}
}

void PacketInfo::GetIcmpTreeInfo(const int &selectedRow, const int &ipDataLength)
{
	QTreeWidgetItem *icmpRoot{ new QTreeWidgetItem({
		QStringLiteral("Internet Control Message Protocol")}) };
	ui->treeWidgetPktInfo->addTopLevelItem(icmpRoot);
	icmpRoot->addChildren({
		new QTreeWidgetItem({QStringLiteral("type: ") + pktList[selectedRow].GetIcmpType() +
		" (" + ui->tableWidgetPacketList->item(selectedRow, 6)->text() + ")"}),
		new QTreeWidgetItem({QStringLiteral("code: ") +
			pktList[selectedRow].GetIcmpCode()}),
		new QTreeWidgetItem({QStringLiteral("Checksum: 0x") +
			pktList[selectedRow].GetIcmpChecksum()}),
		new QTreeWidgetItem({QStringLiteral("Identifier: ") +
			pktList[selectedRow].GetIcmpIdentification()}),
		new QTreeWidgetItem({QStringLiteral("Sequence Number: ") +
			pktList[selectedRow].GetIcmpSequence()}),
		});

	if (int icmpDataLength{ ipDataLength - 8 }; icmpDataLength > 0)
	{
		QTreeWidgetItem *icmpDataRoot{ new QTreeWidgetItem({QStringLiteral("Data (") +
			QString::number(icmpDataLength) + QStringLiteral(") bytes")}) };
		QString icmpData{  };
		icmpDataRoot->addChild(new QTreeWidgetItem({
			pktList[selectedRow].GetIcmpData(icmpDataLength) }));
	}
}

void PacketInfo::GetEthPadding(const int &selectedRow, QTreeWidgetItem *ethRoot, int &paddingNum)
{
	QString padding{};
	paddingNum = kMinFrameLength - pktList[selectedRow].GetLength().toUtf8().toInt();
	if (paddingNum > 0)
	{
		for (int i{}; i != paddingNum; ++i)
		{
			padding += "00";
		}
		ethRoot->addChild(new QTreeWidgetItem({ "Padding: " + padding }));

	}
}

void PacketInfo::GetDataInfo(const int &selectedRow, const int &paddingNum)
{
	const int kColumnNum{ 21 };
	ui->tableWidgetDataInfo->clear();
	ui->tableWidgetDataInfo->setColumnCount(kColumnNum);
	ui->tableWidgetDataInfo->setRowCount(1);
	ui->tableWidgetDataInfo->horizontalHeader()->setVisible(false);
	ui->tableWidgetDataInfo->setGridStyle(Qt::NoPen);
	ui->tableWidgetDataInfo->setVerticalHeaderItem(0, new QTableWidgetItem("0000"));
	for (int i{}; i != kColumnNum; ++i)
		ui->tableWidgetDataInfo->setColumnWidth(i, 10);

	int dataLength{ pktList[selectedRow].GetLength().toUtf8().toInt() };
	u_char *pktData{ (u_char *)(pktList[selectedRow].m_pktData) };

	int row{};
	int col{};
	int j{};
	auto showData = [&] {
		ui->tableWidgetDataInfo->setItem(row, kColumnNum / 2, new QTableWidgetItem(" "));
		ui->tableWidgetDataInfo->setItem(row, col + kColumnNum / 2 + 1,
			new QTableWidgetItem((std::isprint(*pktData) ? QString(*pktData) : QStringLiteral("·"))));
		++col;
		};

	auto screenHandler = [&](int i) {
		if (col % kColumnNum == kColumnNum / 2 - 1 && i != dataLength - 1
			&& i != paddingNum + j - 1)
		{
			++row;
			col = 0;
			ui->tableWidgetDataInfo->setRowCount(row + 1);
			QString tmpRowHeader{ QString::number(row, 16) + QStringLiteral("0") };
			QString rowHeader{};
			for (int k{ tmpRowHeader.size() }; k != 4; ++k)
				rowHeader += QStringLiteral("0");
			rowHeader += tmpRowHeader;
			ui->tableWidgetDataInfo->setVerticalHeaderItem(row,
				new QTableWidgetItem(rowHeader));
		}
		};

	while (j != dataLength)
	{
		ui->tableWidgetDataInfo->setItem(row, col, new QTableWidgetItem(ToHex(pktData, 1)));
		showData();
		screenHandler(j);
		++pktData;
		++j;
	}

	if (kMinFrameLength > pktList[selectedRow].GetLength().toUtf8().toInt())
	{
		screenHandler(j);
		for (int k{ j }; k != paddingNum + j; ++k)
		{
			ui->tableWidgetDataInfo->setItem(row, col, new QTableWidgetItem("00"));
			showData();
			screenHandler(k);
		}
	}
}