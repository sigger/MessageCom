/*
  MessageCom Library - example

  A demonstartion of the MessageCom Library.

  @date 1 Apr 2013

  @author master[at]link-igor[dot]de Igor Milutinovic
  @author hellokitty_iva[at]gmx[dot]de Iva Milutinovic

  @link https://github.com/sigger/MessageCom

  Copyright 2013 Igor Milutinovic, Iva Milutinovic. All rights reserved.

  This example code is in the public domain.

  Example Message:
  ?1|1|0|0|0|99#123|abc%6f2ed7c3cfa1b2b35abefd87ea754e6d?

  Structure of a Message:

  ? - authDelimiter
======
  // command status
  // example: 1|1|0|0|0|99
  // description: a|b|c|d|e|f - all Integer
  a - version
    | - delimiter
  b - id
    | - delimiter
  c - succeed flag
    | - delimiter
  d - failed flag
    | - delimiter
  e - acknowledgement flag
    | - delimiter
  f - task number
======
  # - wrapDelimiter
======
  // data package part 1 - contains the desired data
  // if there is no data leave the "data package part 1" empty.
  // example: 123|abc
  123 - data
    | - delimiter
  abc - data
======
  % - dataDelimiter // always required, regardless of whether "data package part 1" is present or not
======
  // data package part 2 - contains the checksum of the desired data (MD5)
  // example: 6f2ed7c3cfa1b2b35abefd87ea754e6d := md5("123|abc")
  md5 of "data package part 1"
======
  ? - authDelimiter

*/

// include the library code:
#include <MessageCom.h>

// size of a message
#define SIZE 66

// initialize the library with size (default version and id)
MessageCom message(SIZE);

// initialize buffer for the message
char buffer[SIZE];

void setup() {
  // begin communication via Serial(USB)
  Serial.begin(115200);

  // clear buffer
  for(int i=0; i<SIZE; i++)
    buffer[i] = NULL;
}

void loop() {
  if(Serial.available() > 0) {
    // received message into buffer
    for(int i=0; i<SIZE; i++) {
      buffer[i] = Serial.read();
      // maybe a delay of 1 to 5 ms per read
      delay(2);
    }

    // try to interpret the from the buffer
    if(message.readMsg(buffer) == 0) {
      // the message is authentic and complete

      // print what you've received
      Serial.println("");
      Serial.println("YEAH! I received an authentic message!");
      Serial.println("==========");
      Serial.print("Message: ");
      Serial.println(message.msg);
      Serial.print("Command status: ");
      Serial.println(message.cmdStatus);
      Serial.print("Data Package: ");
      Serial.println(message.dataPackage);
      Serial.print("Data: ");
      Serial.println(message.data);
      Serial.print("Checksum: ");
      Serial.println(message.checksum);
      Serial.print("Task: ");
      Serial.println(message.getCmdTask());
      Serial.println("------");

      Serial.println("Extracted Data: ");

      Serial.println("Index 0 as Interger: ");
      Serial.println(message.getDataContextExampleInt());
      // or non-contextual
      // Serial.println(message.getIndexedIntOf(0, message.data, message.delimiter));

      Serial.println("Index 1 as String: ");
      Serial.println(message.getDataContextExampleString());
      // or non-contextual
      // Serial.println(message.getIndexedStringOf(1, message.data, message.delimiter));

      Serial.println("==========");
      Serial.println("");

      // extract the "task" from the message.
      int task = message.getCmdTask();

      // make an acknowledgement with the extracted "task"
      String ack = message.makeAck(task);
      // send the acknowledgement
      Serial.println(ack);

      // accomplish your task... do your work...
      // or in this case: wait 1500 ms or 1.5 sec...
      for(int i=0; i<100; i++) {
        delay(15);
      }

      // make a success message with data and with the extracted "task"
      String ok = message.makeDataSucceed(task, "meow");
      // --- or ---
      // make a success message without data but with the extracted "task"
      // String ok = message.makeSucceed(task);

      // and send it
      Serial.println(ok);

      // clear buffer for the next message
      for(int i=0; i<SIZE; i++)
        buffer[i] = NULL;
    }
  }
}
