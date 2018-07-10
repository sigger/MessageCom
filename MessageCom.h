/*
  MessageCom.h
  
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

#ifndef MessageCom_h
#define MessageCom_h

#include "Arduino.h"

class MessageCom {
	private:
		int strtoi(String);
		String hashData();
	public:
		int _size;
		int _version;
		int _id;
		
		int _totalParts;
		int _curPart;
		int _task;

		String authDelimiter;
		String wrapDelimiter;
		String dataDelimiter;
		String delimiter;
		String partDelimiter;
		String partDataDelimiter;
		
		String msg; // contains command_status and data_packet / enthält Befehlsstatus und Datenpaket
		String cmdStatus; // contains commands / enthält Befehle
		String dataPackage;	// contains data and its checksum / enthält Daten und die checksum
		String data;
		String checksum;
		
		
		MessageCom(int);
		MessageCom(int, int, int);
		
		
		// helper-methods
		// 
		// getter
		String getIndexedStringOf(int, String, String);
		int getIndexedIntOf(int, String, String);
		
		
		// command status relevant methods / Befehlsstatus relevante Methoden
		//
		// getter
		int getCmdVersion();
		int getCmdId();
		int getCmdSucceed();
		int getCmdFailed();
		int getCmdAck();
		int getCmdTask();
		
		// setter
		void createCmdStr(int, int, int, int);
		
		
		// datapackage relevant methods / Datenpaket relevante Methoden
		//
		// getter
		// a good place to create context! / ein guter ort um kontext zu schaffen!
		int getDataContextExampleInt();
		String getDataContextExampleString();
		
		// check
		int packageAvailable();
		// check MD5
		int checkDataConsistence();
		
		// setter
		void wrapPackage();
		void unwrapPackage();
		void unwrapPartPackage();
		
		
		// authentification / Authentifizierung
		void mkMsgAuth();
		int authMsg(String, String);
		int authPartMsg(String);
		
		
		// RX, TX methods
		int readMsg(char*);
		int readMsg(String);
		void writeMsg();
		
		// ----------------------------------------
		// ----------------------------------------
		// ----------------------------------------
		
		String makeAck(int);
		String makeSucceed(int);
		String makeFailed(int);
		String makeDataSucceed(int, String); // same as makeSucceed including data 
		String makeDataFailed(int, String); // same as makeFailed including data
};

#endif



#ifndef MD5_h
#define MD5_h

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

#include <string.h>

typedef unsigned long MD5_u32plus;

typedef struct {
	MD5_u32plus lo, hi;
	MD5_u32plus a, b, c, d;
	unsigned char buffer[64];
	MD5_u32plus block[16];
} MD5_CTX;

class MD5 {
	public:
		MD5();
		static unsigned char* make_hash(char *arg);
		static char* make_digest(const unsigned char *digest, int len);
	 	static const void *body(void *ctxBuf, const void *data, size_t size);
		static void MD5Init(void *ctxBuf);
		static void MD5Final(unsigned char *result, void *ctxBuf);
		static void MD5Update(void *ctxBuf, const void *data, size_t size);
};

#endif
