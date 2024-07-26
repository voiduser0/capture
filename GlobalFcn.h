#pragma once
#include <QString>

inline QString ToHex(const unsigned char *chs, const int size = 1)
{
	QString res{};
	for (int i{}; i < size; ++i) {
		char higher = chs[i] >> 4;
		higher >= 0x0A ? higher += (0x61 - 0x0A) : higher += 0x30;

		char lower = chs[i] & 0x0F;
		lower >= 0x0A ? lower += (0x61 - 0x0A) : lower += 0x30;

		res.append(higher);
		res.append(lower);
	}
	return res;
}

inline QString ToBin(const int val, const int n)
{
	QString res{};
	for (int i{ n - 1 }, j{}; i >= 0; --i)
	{
		res += (((val >> i) % 2 == 0 ? "0" : "1"));
		if (i % 4 == 0)
			res += " ";
	}
	return res;
}