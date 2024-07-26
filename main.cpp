#include "PacketInfo.h"
#include <QtWidgets/QApplication>

int main(int argc, char *argv[])
{
	QApplication a(argc, argv);
	PacketInfo w;
	w.show();
	return a.exec();
}
