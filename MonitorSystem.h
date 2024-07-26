#pragma once

#include <QList>
#include <QTimer>
#include <QWidget>
#include <Windows.h>
#include <tlhelp32.h>
#include <Iphlpapi.h>
//#include <winsock2.h>
#include <thread>
#include <chrono>

#pragma comment(lib, "Iphlpapi.lib")

#include "ui_MonitorSystem.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MonitorSystemClass; };
QT_END_NAMESPACE

struct ProcessNetworkInfo {
	DWORD processId;
	std::vector<MIB_TCPROW_OWNER_PID> tcpConnections;
};

class MonitorSystem : public QWidget
{
	Q_OBJECT

public:
	MonitorSystem(QWidget *parent = nullptr);
	~MonitorSystem();

private:
	Ui::MonitorSystemClass *ui;

	QTimer  *m_timer{};
	PROCESSENTRY32 m_process;
	QList<PROCESSENTRY32> m_processList;

private slots:
	void  GetProcessNetworkInfo();

	void on_processComboBox_currentIndexChanged(int index);
	void on_startMonitorBtn_clicked();
	void on_stopMonitorBtn_clicked();
	void on_clearMonitorBtn_clicked();
};
