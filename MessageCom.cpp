/*
  MessageCom.cpp
  
  MessageCom is a library to facilitate communication between devices.
  MessageCom is useful for many platforms, including for Arduino.
  MessageCom uses MD5 "ArduinoMD5" links:
    https://github.com/tzikis/ArduinoMD5/
    https://github.com/scottmac/arduino

  MessageCom ist eine bibliothek, um die Kommunikation zwischen Geräten zu erleichtern.
  MessageCom ist für viele plattformen nützlich, unter anderem für Arduino.
  MessageCom nutzt MD5 "ArduinoMD5" links:
    https://github.com/tzikis/ArduinoMD5/
    https://github.com/scottmac/arduino

  @version 0.1
  @date 1 Apr 2013

  @author master[at]link-igor[dot]de Igor Milutinovic
  @author hellokitty_iva[at]gmx[dot]de Iva Milutinovic

  @link https://github.com/sigger/MessageCom

  Copyright 2013 Igor Milutinovic, Iva Milutinovic. All rights reserved.

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include "Arduino.h"
#include "MessageCom.h"

// private:
int MessageCom::strtoi(String tmp) {
	char buf[(tmp.length()+1)];
	for(int i=0; i<tmp.length(); i++) {
		buf[i] = tmp[i];
	}
	buf[tmp.length()] = '\0';
	return atoi(buf);
}
String MessageCom::hashData() {
	char* buf = (char*) malloc(sizeof(char)*(data.length()+1));
	for(int i=0; i<data.length(); i++) {
		buf[i] = data[i];
	}
	buf[data.length()] = '\0';
	
	// make checksum
	unsigned char* hash=MD5::make_hash(buf);
	// generate the digest (hex encoding) of our hash
	char *md5str = MD5::make_digest(hash, 32);
	
	String cs = "";
	for(int i=0; i<32; i++) {
		cs += md5str[i];
	}
	return cs;
}

// public
MessageCom::MessageCom(int size) {
	_size = size;
	_version = 1;
	_id = 1;
	authDelimiter = "?";
	wrapDelimiter = "#";
	dataDelimiter = "%";
	delimiter = "|";
	partDelimiter = "_";
	partDataDelimiter = "^";
}
MessageCom::MessageCom(int size, int version, int id) {
	_size = size;
	_version = version;
	_id = id;
	authDelimiter = "?";
	wrapDelimiter = "#";
	dataDelimiter = "%";
	delimiter = "|";
	partDelimiter = "_";
	partDataDelimiter = "^";
}

// helper-methods
// 
// getter
String MessageCom::getIndexedStringOf(int index, String str, String delim) {
	int start = 0;
	int stop = 0;
	
	String tmp[index+1];
	
	for(int i=0; i<=index ;i++) {
		if((stop = str.indexOf(delim, start)) < 0) {
			tmp[i] = str.substring(start, str.length());
			break;
		}
		// create substring...
		tmp[i] = str.substring(start, stop);
		start = stop+1;
	}
	
	return tmp[index];
}
int MessageCom::getIndexedIntOf(int index, String str, String delim) {
	String tmp = getIndexedStringOf(index, str, delim);
	
	return strtoi(tmp);
}


// command status relevant methods / Befehlsstatus relevante Methoden
//
// getter
int MessageCom::getCmdVersion() {
	return getIndexedIntOf(0, cmdStatus, delimiter);
}
int MessageCom::getCmdId() {
	return getIndexedIntOf(1, cmdStatus, delimiter);
}
int MessageCom::getCmdSucceed() {
	return getIndexedIntOf(2, cmdStatus, delimiter);
}
int MessageCom::getCmdFailed() {
	return getIndexedIntOf(3, cmdStatus, delimiter);
}
int MessageCom::getCmdAck() {
	return getIndexedIntOf(4, cmdStatus, delimiter);
}
int MessageCom::getCmdTask() {
	return getIndexedIntOf(5, cmdStatus, delimiter);
}

// setter
void MessageCom::createCmdStr(int succeed, int failed, int ack, int task) {
	cmdStatus = "";
	cmdStatus += _version+delimiter+_id+delimiter+succeed+delimiter+failed+delimiter+ack+delimiter+task;
}





// datapackage relevant methods / Datenpaket relevante Methoden
//
// getter
// a good place to create context / ein guter ort um kontext zu schaffen
// example:
// expected: "123" and "abc" in this order. Looks like: ...#123|abc%...
// "123" as Integer and "abc" as String
// you are able to extract and cast it using methods below
// getIndexed _TYPE_ Of() treats the "data" as an array
int MessageCom::getDataContextExampleInt() {
	return getIndexedIntOf(0, data, delimiter);
}
String MessageCom::getDataContextExampleString() {
	return getIndexedStringOf(1, data, delimiter);
}





// check
int MessageCom::packageAvailable() {
	// checks whether a package exists/is available (size or length)> 0
	return dataPackage.length();
}
// check MD5
int MessageCom::checkDataConsistence() {
	String cs = hashData();
	if(checksum.equals(cs))
		return 1;
	else
		return 0;
}


// wrap command status and data package into a string including the wrapDelimiter /
// Befehlsstatus und Datenpaket zu einem String zusammenfassen inklusive des wrapDelimiters
void MessageCom::wrapPackage() {
	msg = "";
	msg += cmdStatus+wrapDelimiter+dataPackage;
}
void MessageCom::unwrapPackage() {
	int start = 0;
	int stop = 0;
	
	if((stop = msg.indexOf(wrapDelimiter, start)) >= 0) {
		// create substrings...
		cmdStatus = msg.substring(start, stop);
		start = stop+1;
		dataPackage = msg.substring(start, msg.length());
	}
	
	// if exists
	if (packageAvailable()) {
		start = 0;
		stop = 0;
		
		if((stop = dataPackage.indexOf(dataDelimiter, start)) >= 0) {
			// create substrings...
			data = dataPackage.substring(start, stop);
			start = stop+1;
			checksum = dataPackage.substring(start, dataPackage.length());
		}
	}
}
void MessageCom::unwrapPartPackage() {
	// e.g. make from: 3|0|1^?1|1|0|0|0|1#1000|4000|3000|-1|1001|4002|3001|2008|1000|
	// the following:
	// 3|0|1^
	// _totalParts = 3;
	// _curPart = 0;
	// _task = 1;
	// msg = ?1|1|0|0|0|1#1000|4000|3000|-1|1001|4002|3001|2008|1000|
	
	_totalParts = getIndexedIntOf(0, msg, delimiter);
	_curPart = getIndexedIntOf(1, msg, delimiter);
	_task = getIndexedIntOf(2, msg, delimiter);
	
	String curMsgPart = getIndexedStringOf(1, msg, partDataDelimiter);
	msg = curMsgPart;
}


// authentification / Authentifizierung
void MessageCom::mkMsgAuth() {
	// make authenticated message => "authDelimiter" at the beginning and end of the message
	// Nachricht Authentifizierbar machen  => "authDelimiter" am Anfang und Ende der Nachricht
	String tmp = "";
	tmp += authDelimiter+msg+authDelimiter;
	msg = tmp;
}
int MessageCom::authMsg(String buffer, String delim="") {
	if(delim.equals(""))
		delim = authDelimiter;
	// check if message is authentic
	// prüfe ob Nachricht Authentisch ist
	int firstChar = buffer.indexOf(delim);
	// int nextChar = buffer.lastIndexOf(delim);
	int nextChar = buffer.indexOf(delim, (firstChar+1));
	
	
	if(firstChar >= 0 && nextChar > firstChar) {
		String tmp = buffer.substring((firstChar+1), nextChar);
		if(!tmp.equals("")) {
			msg = tmp;
			return 1;
		}
	}
	return 0;
}
int MessageCom::authPartMsg(String buffer) {
	return authMsg(buffer, partDelimiter);
}


// RX, TX methods
int MessageCom::readMsg(char* buf) {
	String buffer;
	for(int i=0; i<_size; i++) {
		buffer += buf[i];
	}
	return readMsg(buffer);
}
int MessageCom::readMsg(String buffer) {
	msg = "";
	cmdStatus = "";
	dataPackage = "";
	data = "";
	checksum = "";
	_totalParts = -1;
	_curPart = -1;
	_task = -1;
	
	if(authMsg(buffer)) { // whole message / Ganze Nachricht
		unwrapPackage();
		if(getCmdVersion() == _version &&  getCmdId() == _id) {
			if (packageAvailable()) {
				if(checkDataConsistence()){
					return 0;
				} else {
					return -1;
				}
			}
		}
		return 0;
	} else if(authPartMsg(buffer)) { // part of a message / Teil einer Nachricht
		unwrapPartPackage();
		if(_totalParts == 1) { // part of a message is a whole message / Teil einer Nachricht ist die Ganze Nachricht
			if(authMsg(msg)) { // whole message / Ganze Nachricht
				unwrapPackage();
				if(getCmdVersion() == _version &&  getCmdId() == _id) {
					if (packageAvailable()) {
						if(checkDataConsistence()){
							return 0;
						} else {
							return -1;
						}
					}
				}
			}
		}	else {
			return _totalParts;
		}
	}
	return -1;
}
void MessageCom::writeMsg() {
	// Nachricht packen
	wrapPackage();
	// make authenticated message / Nachricht Authentifizierbar machen
	mkMsgAuth();
}


// ----------------------------------------
// ----------------------------------------
// ----------------------------------------


String MessageCom::makeAck(int task) {
	createCmdStr(0, 0, 1, task);
	dataPackage = dataDelimiter;
	writeMsg();
	
	return msg;
}
String MessageCom::makeSucceed(int task) {
	createCmdStr(1, 0, 0, task);
	dataPackage = dataDelimiter;
	writeMsg();
	
	return msg;
}
String MessageCom::makeFailed(int task) {
	createCmdStr(0, 1, 0, task);
	dataPackage = dataDelimiter;
	writeMsg();
	
	return msg;
}
String MessageCom::makeDataSucceed(int task, String value) {
	createCmdStr(1, 0, 0, task);
	data = value;
	checksum = hashData();
	// wrap data package / Datenpaket schnüren
	dataPackage = "";
	dataPackage += data+dataDelimiter+checksum;
	writeMsg();
	
	return msg;
}
String MessageCom::makeDataFailed(int task, String value) {
	createCmdStr(0, 1, 0, task);
	data = value;
	checksum = hashData();
	// wrap data package / Datenpaket schnüren
	dataPackage = "";
	dataPackage += data+dataDelimiter+checksum;
	writeMsg();
	
	return msg;
}













/*
 * This is an OpenSSL-compatible implementation of the RSA Data Security,
 * Inc. MD5 Message-Digest Algorithm (RFC 1321).
 *
 * Written by Solar Designer <solar at openwall.com> in 2001, and placed
 * in the public domain.  There's absolutely no warranty.
 *
 * This differs from Colin Plumb's older public domain implementation in
 * that no 32-bit integer data type is required, there's no compile-time
 * endianness configuration, and the function prototypes match OpenSSL's.
 * The primary goals are portability and ease of use.
 *
 * This implementation is meant to be fast, but not as fast as possible.
 * Some known optimizations are not included to reduce source code size
 * and avoid compile-time configuration.
 */

/*
 * Updated by Scott MacVicar for arduino
 * <scott@macvicar.net>
 */

MD5::MD5() {
	//nothing
	return;
}

char* MD5::make_digest(const unsigned char *digest, int len) /* {{{ */ {
	char * md5str = (char*) malloc(sizeof(char)*(len*2+1));
	static const char hexits[17] = "0123456789abcdef";
	int i;

	for (i = 0; i < len; i++) {
		md5str[i * 2]       = hexits[digest[i] >> 4];
		md5str[(i * 2) + 1] = hexits[digest[i] &  0x0F];
	}
	md5str[len * 2] = '\0';
	return md5str;
}

/*
 * The basic MD5 functions.
 *
 * F and G are optimized compared to their RFC 1321 definitions for
 * architectures that lack an AND-NOT instruction, just like in Colin Plumb's
 * implementation.
 */
#define F(x, y, z)			((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z)			((y) ^ ((z) & ((x) ^ (y))))
#define H(x, y, z)			((x) ^ (y) ^ (z))
#define I(x, y, z)			((y) ^ ((x) | ~(z)))

/*
 * The MD5 transformation for all four rounds.
 */
#define STEP(f, a, b, c, d, x, t, s) \
	(a) += f((b), (c), (d)) + (x) + (t); \
	(a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s)))); \
	(a) += (b);

/*
 * SET reads 4 input bytes in little-endian byte order and stores them
 * in a properly aligned word in host byte order.
 *
 * The check for little-endian architectures that tolerate unaligned
 * memory accesses is just an optimization.  Nothing will break if it
 * doesn't work.
 */
#if defined(__i386__) || defined(__x86_64__) || defined(__vax__)
# define SET(n) \
	(*(MD5_u32plus *)&ptr[(n) * 4])
# define GET(n) \
	SET(n)
#else
# define SET(n) \
	(ctx->block[(n)] = \
	(MD5_u32plus)ptr[(n) * 4] | \
	((MD5_u32plus)ptr[(n) * 4 + 1] << 8) | \
	((MD5_u32plus)ptr[(n) * 4 + 2] << 16) | \
	((MD5_u32plus)ptr[(n) * 4 + 3] << 24))
# define GET(n) \
	(ctx->block[(n)])
#endif

/*
 * This processes one or more 64-byte data blocks, but does NOT update
 * the bit counters.  There are no alignment requirements.
 */
const void *MD5::body(void *ctxBuf, const void *data, size_t size) {
	MD5_CTX *ctx = (MD5_CTX*)ctxBuf;
	const unsigned char *ptr;
	MD5_u32plus a, b, c, d;
	MD5_u32plus saved_a, saved_b, saved_c, saved_d;

	ptr = (unsigned char*)data;

	a = ctx->a;
	b = ctx->b;
	c = ctx->c;
	d = ctx->d;

	do {
		saved_a = a;
		saved_b = b;
		saved_c = c;
		saved_d = d;

/* Round 1 */
		STEP(F, a, b, c, d, SET(0), 0xd76aa478, 7)
		STEP(F, d, a, b, c, SET(1), 0xe8c7b756, 12)
		STEP(F, c, d, a, b, SET(2), 0x242070db, 17)
		STEP(F, b, c, d, a, SET(3), 0xc1bdceee, 22)
		STEP(F, a, b, c, d, SET(4), 0xf57c0faf, 7)
		STEP(F, d, a, b, c, SET(5), 0x4787c62a, 12)
		STEP(F, c, d, a, b, SET(6), 0xa8304613, 17)
		STEP(F, b, c, d, a, SET(7), 0xfd469501, 22)
		STEP(F, a, b, c, d, SET(8), 0x698098d8, 7)
		STEP(F, d, a, b, c, SET(9), 0x8b44f7af, 12)
		STEP(F, c, d, a, b, SET(10), 0xffff5bb1, 17)
		STEP(F, b, c, d, a, SET(11), 0x895cd7be, 22)
		STEP(F, a, b, c, d, SET(12), 0x6b901122, 7)
		STEP(F, d, a, b, c, SET(13), 0xfd987193, 12)
		STEP(F, c, d, a, b, SET(14), 0xa679438e, 17)
		STEP(F, b, c, d, a, SET(15), 0x49b40821, 22)

/* Round 2 */
		STEP(G, a, b, c, d, GET(1), 0xf61e2562, 5)
		STEP(G, d, a, b, c, GET(6), 0xc040b340, 9)
		STEP(G, c, d, a, b, GET(11), 0x265e5a51, 14)
		STEP(G, b, c, d, a, GET(0), 0xe9b6c7aa, 20)
		STEP(G, a, b, c, d, GET(5), 0xd62f105d, 5)
		STEP(G, d, a, b, c, GET(10), 0x02441453, 9)
		STEP(G, c, d, a, b, GET(15), 0xd8a1e681, 14)
		STEP(G, b, c, d, a, GET(4), 0xe7d3fbc8, 20)
		STEP(G, a, b, c, d, GET(9), 0x21e1cde6, 5)
		STEP(G, d, a, b, c, GET(14), 0xc33707d6, 9)
		STEP(G, c, d, a, b, GET(3), 0xf4d50d87, 14)
		STEP(G, b, c, d, a, GET(8), 0x455a14ed, 20)
		STEP(G, a, b, c, d, GET(13), 0xa9e3e905, 5)
		STEP(G, d, a, b, c, GET(2), 0xfcefa3f8, 9)
		STEP(G, c, d, a, b, GET(7), 0x676f02d9, 14)
		STEP(G, b, c, d, a, GET(12), 0x8d2a4c8a, 20)

/* Round 3 */
		STEP(H, a, b, c, d, GET(5), 0xfffa3942, 4)
		STEP(H, d, a, b, c, GET(8), 0x8771f681, 11)
		STEP(H, c, d, a, b, GET(11), 0x6d9d6122, 16)
		STEP(H, b, c, d, a, GET(14), 0xfde5380c, 23)
		STEP(H, a, b, c, d, GET(1), 0xa4beea44, 4)
		STEP(H, d, a, b, c, GET(4), 0x4bdecfa9, 11)
		STEP(H, c, d, a, b, GET(7), 0xf6bb4b60, 16)
		STEP(H, b, c, d, a, GET(10), 0xbebfbc70, 23)
		STEP(H, a, b, c, d, GET(13), 0x289b7ec6, 4)
		STEP(H, d, a, b, c, GET(0), 0xeaa127fa, 11)
		STEP(H, c, d, a, b, GET(3), 0xd4ef3085, 16)
		STEP(H, b, c, d, a, GET(6), 0x04881d05, 23)
		STEP(H, a, b, c, d, GET(9), 0xd9d4d039, 4)
		STEP(H, d, a, b, c, GET(12), 0xe6db99e5, 11)
		STEP(H, c, d, a, b, GET(15), 0x1fa27cf8, 16)
		STEP(H, b, c, d, a, GET(2), 0xc4ac5665, 23)

/* Round 4 */
		STEP(I, a, b, c, d, GET(0), 0xf4292244, 6)
		STEP(I, d, a, b, c, GET(7), 0x432aff97, 10)
		STEP(I, c, d, a, b, GET(14), 0xab9423a7, 15)
		STEP(I, b, c, d, a, GET(5), 0xfc93a039, 21)
		STEP(I, a, b, c, d, GET(12), 0x655b59c3, 6)
		STEP(I, d, a, b, c, GET(3), 0x8f0ccc92, 10)
		STEP(I, c, d, a, b, GET(10), 0xffeff47d, 15)
		STEP(I, b, c, d, a, GET(1), 0x85845dd1, 21)
		STEP(I, a, b, c, d, GET(8), 0x6fa87e4f, 6)
		STEP(I, d, a, b, c, GET(15), 0xfe2ce6e0, 10)
		STEP(I, c, d, a, b, GET(6), 0xa3014314, 15)
		STEP(I, b, c, d, a, GET(13), 0x4e0811a1, 21)
		STEP(I, a, b, c, d, GET(4), 0xf7537e82, 6)
		STEP(I, d, a, b, c, GET(11), 0xbd3af235, 10)
		STEP(I, c, d, a, b, GET(2), 0x2ad7d2bb, 15)
		STEP(I, b, c, d, a, GET(9), 0xeb86d391, 21)

		a += saved_a;
		b += saved_b;
		c += saved_c;
		d += saved_d;

		ptr += 64;
	} while (size -= 64);

	ctx->a = a;
	ctx->b = b;
	ctx->c = c;
	ctx->d = d;

	return ptr;
}

void MD5::MD5Init(void *ctxBuf) {
	MD5_CTX *ctx = (MD5_CTX*)ctxBuf;
	ctx->a = 0x67452301;
	ctx->b = 0xefcdab89;
	ctx->c = 0x98badcfe;
	ctx->d = 0x10325476;

	ctx->lo = 0;
	ctx->hi = 0;
}

void MD5::MD5Update(void *ctxBuf, const void *data, size_t size) {
	MD5_CTX *ctx = (MD5_CTX*)ctxBuf;
	MD5_u32plus saved_lo;
	MD5_u32plus used, free;

	saved_lo = ctx->lo;
	if ((ctx->lo = (saved_lo + size) & 0x1fffffff) < saved_lo) {
		ctx->hi++;
	}
	ctx->hi += size >> 29;

	used = saved_lo & 0x3f;

	if (used) {
		free = 64 - used;

		if (size < free) {
			memcpy(&ctx->buffer[used], data, size);
			return;
		}

		memcpy(&ctx->buffer[used], data, free);
		data = (unsigned char *)data + free;
		size -= free;
		body(ctx, ctx->buffer, 64);
	}

	if (size >= 64) {
		data = body(ctx, data, size & ~(size_t)0x3f);
		size &= 0x3f;
	}

	memcpy(ctx->buffer, data, size);
}

void MD5::MD5Final(unsigned char *result, void *ctxBuf) {
	MD5_CTX *ctx = (MD5_CTX*)ctxBuf;
	MD5_u32plus used, free;

	used = ctx->lo & 0x3f;

	ctx->buffer[used++] = 0x80;

	free = 64 - used;

	if (free < 8) {
		memset(&ctx->buffer[used], 0, free);
		body(ctx, ctx->buffer, 64);
		used = 0;
		free = 64;
	}

	memset(&ctx->buffer[used], 0, free - 8);

	ctx->lo <<= 3;
	ctx->buffer[56] = ctx->lo;
	ctx->buffer[57] = ctx->lo >> 8;
	ctx->buffer[58] = ctx->lo >> 16;
	ctx->buffer[59] = ctx->lo >> 24;
	ctx->buffer[60] = ctx->hi;
	ctx->buffer[61] = ctx->hi >> 8;
	ctx->buffer[62] = ctx->hi >> 16;
	ctx->buffer[63] = ctx->hi >> 24;

	body(ctx, ctx->buffer, 64);

	result[0] = ctx->a;
	result[1] = ctx->a >> 8;
	result[2] = ctx->a >> 16;
	result[3] = ctx->a >> 24;
	result[4] = ctx->b;
	result[5] = ctx->b >> 8;
	result[6] = ctx->b >> 16;
	result[7] = ctx->b >> 24;
	result[8] = ctx->c;
	result[9] = ctx->c >> 8;
	result[10] = ctx->c >> 16;
	result[11] = ctx->c >> 24;
	result[12] = ctx->d;
	result[13] = ctx->d >> 8;
	result[14] = ctx->d >> 16;
	result[15] = ctx->d >> 24;

	memset(ctx, 0, sizeof(*ctx));
}
unsigned char* MD5::make_hash(char *arg) {
	MD5_CTX context;
	unsigned char digest[16];
	MD5Init(&context);
	MD5Update(&context, arg, strlen(arg));
	MD5Final(digest, &context);
	return digest;
}
