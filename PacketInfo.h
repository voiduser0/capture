#pragma once

#include <Array>
#include <QList>
#include <QHash>
#include <QTime>
#include <QTimer>
#include <QVector>
#include <QAction>
#include <QCloseEvent>
#include <QSqlError>
#include <QSqlQuery>
#include <QSqlRecord>
#include <QSqlDatabase>
#include <QSharedPointer>
#include <QtCharts/QPieSlice>
#include <QtCharts/QPieSeries>
#include <QtCharts/QChartView>
#include <QtWidgets/QMainWindow>

#include "pcap.h"
#include "ArpSpoof.h"
#include "GlobalFcn.h"
#include "DataPacket.h"
#include "ui_PacketInfo.h"
#include "PacketHandle.h"
#include "CreateFakePacket.h"
#include "ReadOnlyDelegate.h"

QT_BEGIN_NAMESPACE
namespace Ui { class PacketInfoClass; };
QT_END_NAMESPACE

class PacketInfo : public QMainWindow
{
	Q_OBJECT

	friend QString ToBin(const int val, const int n);
	using SPPieSeries = QSharedPointer<QtCharts::QPieSeries>;

private:
	Ui::PacketInfoClass *ui;

	pcap_if_t *m_allDevices{};
	pcap_if_t *m_device{};
	pcap_t *m_adhandle{};       // 一个指向已打开的网络捕获设备或数据源的句柄
	pcap_dumper_t *m_dumper{};
	char m_errBuf[PCAP_ERRBUF_SIZE];

	QSqlDatabase m_database{};
	QTimer *m_updateChartTime;
	QAction *m_actSearch;
	QList<DataPacket> pktList;
	int m_rowNumber{};
	bool m_isStart{};
	bool m_isTimeStart{};
	bool m_isDumper{};

	PacketHandle *m_pktHandle{};
	ArpSpoof *m_spoof;
	CreateFakePacket *m_cfpkt{};
	SPPieSeries m_pktSeries;
	QtCharts::QChart *m_chart;
	QtCharts::QChartView *m_chartView;
	QMainWindow *m_pieChartWindow;

	ReadOnlyDelegate *m_ReadOnlyDelegate{};
	QHash<QString, int> m_pktNum;

public:
	PacketInfo(QWidget *parent = nullptr);
	~PacketInfo();
	
protected:
	void closeEvent(QCloseEvent *e);

private:
	void InitScreen();
	void InitDatabase();
	void InitTableScreen();
	void InitTreeScreen();
	void InitLEditScreen();
	void InitPieChartScreen();
	void ShowNetwordDevice();
	bool OpenSelectedDevice();
	void ClearList();
	void ClearContents();
	void SetActionState();
	void ResetActionState();
	void ClearDB();
	void SaveFile();

	//void InsertEthInfo(const DataPacket &pkt, const int &eid);
	//void InsertArpInfo(const DataPacket &pkt, const int &id);
	//void InsertIpInfo(const DataPacket &pkt, const int &id, int &ipDataLength);

	QTreeWidgetItem *GetEthTreeInfo(const int &selectedRow);
	void GetArpTreeInfo(const int &selectedRow);
	void GetIpTreeInfo(const int &selectedRow, int &ipDataLength);
	void GetTcpTreeInfo(const int &selectedRow, const int &ipTotalData);
	void GetUdpTreeInfo(const int &selectedRow);
	void GetDnsTreeInfo(const int &selectedRow);
	void GetIcmpTreeInfo(const int &selectedRow, const int &ipDataLength);
	void GetEthPadding(const int &selectedRow, QTreeWidgetItem *ethRoot, int &paddingNum);
	void GetDataInfo(const int &selectedRow, const int &paddingNum);

signals:
	void startShowChart(const QHash<QString, int> &m_pktNum);
	void RecvPktOk(const bool &ok);
	void SendNicName(const QString &nicName);

private slots:
	void on_comboBoxSelectDevices_currentIndexChanged(int index);
	void on_tableWidgetPacketList_cellClicked(int row, int column);
	void on_actOpen_triggered();
	void on_actSave_triggered();
	void on_actStart_triggered();
	void on_actStop_triggered();
	void on_actRestart_triggered();
	void on_actUp_triggered();
	void on_actDown_triggered();
	void on_actTop_triggered();
	void on_actBottom_triggered();
	void on_actChart_triggered();
	void on_actCreate_triggered();
	void on_lineEditFilter_textChanged();
	void on_lineEditFilter_returnPressed();

	void ActToStart(PacketHandle *pktHandle);
	void RecvData(const DataPacket &pkt);
	void RecvPkt(QByteArray &pktData, bool &ok);
	void ShowPieChart();
};
