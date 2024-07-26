#include "MonitorSystem.h"

#include <iostream>
#include <qDebug>

using namespace::std;

MonitorSystem::MonitorSystem(QWidget *parent)
	: QWidget(parent)
	, ui(new Ui::MonitorSystemClass())
{
	ui->setupUi(this);
	setFixedSize(1000, 800);
	ui->startMonitorBtn->setEnabled(true);
	ui->stopMonitorBtn->setEnabled(false);
	m_timer = new QTimer(this);
	ui->processInfoTextEdit->setReadOnly(true);
	connect(m_timer, &QTimer::timeout, this, &MonitorSystem::GetProcessNetworkInfo);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot != INVALID_HANDLE_VALUE)
	{
		m_process.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(snapshot, &m_process))
		{
			do
			{
				m_processList.push_back(m_process);
				QString processName = QString::fromWCharArray(m_process.szExeFile);
				DWORD processId = m_process.th32ProcessID;
				ui->processComboBox->addItem(QString("%1 (%2)").arg(processName).arg(processId));
			} while (Process32Next(snapshot, &m_process));
		}
		m_process = m_processList[0];
		CloseHandle(snapshot);
	}
}

MonitorSystem::~MonitorSystem()
{
	delete ui;
}

void MonitorSystem::on_processComboBox_currentIndexChanged(int index)
{
	int i{};
	while (i != index)
	{
		++i;
	}
	m_process = m_processList[i];
}

void MonitorSystem::GetProcessNetworkInfo()
{
	MIB_TCPTABLE_OWNER_PID *pTcpTable = nullptr;
	DWORD dwSize = 0;

	// 获取所需的缓冲区大小
	if (GetExtendedTcpTable(pTcpTable, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0)
		== ERROR_INSUFFICIENT_BUFFER)
	{
		pTcpTable = (MIB_TCPTABLE_OWNER_PID *)new BYTE[dwSize];

		// 获取 TCP 连接信息
		if (GetExtendedTcpTable(pTcpTable, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0) == NO_ERROR)
		{
			for (DWORD i = 0; i < pTcpTable->dwNumEntries; ++i)
			{
				if (pTcpTable->table[i].dwOwningPid == m_process.th32ProcessID)
				{
					ui->processInfoTextEdit->append({"TCP " + QByteArray(inet_ntoa(*(in_addr *)&pTcpTable->table[i].dwLocalAddr))
						+ QString(":") + QString::number(ntohs(static_cast<u_short>(pTcpTable->table[i].dwLocalPort))) + QString(" -> ") 
						+ QByteArray(inet_ntoa(*(in_addr *)&pTcpTable->table[i].dwRemoteAddr)) + QString(":")
						+ QString::number(ntohs(static_cast<u_short>(pTcpTable->table[i].dwRemotePort)))});
				}
			}
		}
		delete[] pTcpTable;
	}

	MIB_UDPTABLE_OWNER_PID *pUdpTable = nullptr;
	dwSize = 0;
	if (GetExtendedUdpTable(pUdpTable, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0) 
		== ERROR_INSUFFICIENT_BUFFER) 
	{
		pUdpTable = (MIB_UDPTABLE_OWNER_PID *)new BYTE[dwSize];
		// 获取 UDP 连接信息
		if (GetExtendedUdpTable(pUdpTable, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) 
		{
			for (DWORD i = 0; i < pUdpTable->dwNumEntries; i++) 
			{
				if (pUdpTable->table[i].dwOwningPid == m_process.th32ProcessID) 
				{
					ui->processInfoTextEdit->append({ "UDP " + QByteArray(inet_ntoa(*(in_addr *)&pUdpTable->table[i].dwLocalAddr))
					+ QString(":") + QString::number(ntohs(static_cast<u_short>(pUdpTable->table[i].dwLocalPort))) + QString(" -> ")});
				}
			}
		}
		delete[] pUdpTable;
	}
}

void MonitorSystem::on_startMonitorBtn_clicked()
{
	m_timer->start(100);
	ui->startMonitorBtn->setEnabled(false);
	ui->stopMonitorBtn->setEnabled(true);
}

void MonitorSystem::on_stopMonitorBtn_clicked()
{
	m_timer->stop();
	ui->startMonitorBtn->setEnabled(true);
	ui->stopMonitorBtn->setEnabled(false);
}

void MonitorSystem::on_clearMonitorBtn_clicked()
{
	ui->processInfoTextEdit->clear();
}
