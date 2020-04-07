//——————————————————————————————————————————————————————————————————————————————
//  ACAN2517 Demo in loopback mode, using hardware SPI1, with an external interrupt
//——————————————————————————————————————————————————————————————————————————————

#include <ACAN2517.h>

//——————————————————————————————————————————————————————————————————————————————
//  MCP2517 connections: adapt theses settings to your design
//  As hardware SPI is used, you should select pins that support SPI functions.
//  This sketch is designed for a Teensy 3.5, using SPI1
//  But standard Teensy 3.5 SPI1 pins are not used
//    SCK input of MCP2517 is connected to pin #32
//    SDI input of MCP2517 is connected to pin #0
//    SDO output of MCP2517 is connected to pin #1
//  CS input of MCP2517 should be connected to a digital output port
//  INT output of MCP2517 should be connected to a digital input port, with interrupt capability
//——————————————————————————————————————————————————————————————————————————————

static const byte MCP2517_SCK = 13 ; // SCK input of MCP2517
static const byte MCP2517_SDI =  11 ; // SDI input of MCP2517
static const byte MCP2517_SDO =  12 ; // SDO output of MCP2517

static const byte MCP2517_CS  = 15 ; // CS input of MCP2517
static const byte MCP2517_INT = 38 ; // INT output of MCP2517

static unsigned gSendDate = 0 ;
static unsigned gSentCount = 0 ;
static unsigned gReceivedCount = 0 ;

#define CAN_switch 2
#define silent2 40

//——————————————————————————————————————————————————————————————————————————————
//  MCP2517 Driver object
//——————————————————————————————————————————————————————————————————————————————

ACAN2517 can (MCP2517_CS, SPI, MCP2517_INT) ;

//——————————————————————————————————————————————————————————————————————————————
//   SETUP
//——————————————————————————————————————————————————————————————————————————————

void setup () {
  pinMode(CAN_switch,OUTPUT);
  pinMode(silent2,OUTPUT);
  digitalWrite(CAN_switch, HIGH);
  digitalWrite(silent2,LOW);
//--- Switch on builtin led
  pinMode (LED_BUILTIN, OUTPUT) ;
  digitalWrite (LED_BUILTIN, LOW) ;
//--- Start serial
  Serial.begin (38400) ;
//--- Wait for serial (blink led at 10 Hz during waiting)
  while (!Serial) {
    delay (50) ;
    digitalWrite (LED_BUILTIN, !digitalRead (LED_BUILTIN)) ;
  }
//--- Define alternate pins for SPI1 (see https://www.pjrc.com/teensy/td_libs_SPI.html)
  Serial.print ("Using pin #") ;
  Serial.print (MCP2517_SDI) ;
  Serial.print (" for MOSI: ") ;
  Serial.println (SPI.pinIsMOSI (MCP2517_SDI) ? "yes" : "NO!!!") ;
  Serial.print ("Using pin #") ;
  Serial.print (MCP2517_SDO) ;
  Serial.print (" for MISO: ") ;
  Serial.println (SPI.pinIsMISO (MCP2517_SDO) ? "yes" : "NO!!!") ;
  Serial.print ("Using pin #") ;
  Serial.print (MCP2517_SCK) ;
  Serial.print (" for SCK: ") ;
  Serial.println (SPI.pinIsSCK (MCP2517_SCK) ? "yes" : "NO!!!") ;
  SPI.setMOSI (MCP2517_SDI) ;
  SPI.setMISO (MCP2517_SDO) ;
  SPI.setSCK (MCP2517_SCK) ;
//----------------------------------- Begin SPI
  SPI.begin () ;
//--- Configure ACAN2517
  Serial.print ("sizeof (ACAN2517Settings): ") ;
  Serial.print (sizeof (ACAN2517Settings)) ;
  Serial.println (" bytes") ;
  Serial.println ("Configure ACAN2517") ;
  ACAN2517Settings settings (ACAN2517Settings::OSC_20MHz, 250 * 1000) ; // CAN bit rate 250 kb/s
  settings.mRequestedMode = ACAN2517Settings::InternalLoopBack ; // Select loopback mode
  const uint32_t errorCode = can.begin (settings, [] { can.isr () ; }) ;
  if (errorCode == 0) {
    Serial.print ("Bit Rate prescaler: ") ;
    Serial.println (settings.mBitRatePrescaler) ;
    Serial.print ("Phase segment 1: ") ;
    Serial.println (settings.mPhaseSegment1) ;
    Serial.print ("Phase segment 2: ") ;
    Serial.println (settings.mPhaseSegment2) ;
    Serial.print ("SJW:") ;
    Serial.println (settings.mSJW) ;
    Serial.print ("Actual bit rate: ") ;
    Serial.print (settings.actualBitRate ()) ;
    Serial.println (" bit/s") ;
    Serial.print ("Exact bit rate ? ") ;
    Serial.println (settings.exactBitRate () ? "yes" : "no") ;
    Serial.print ("Sample point: ") ;
    Serial.print (settings.samplePointFromBitStart ()) ;
    Serial.println ("%") ;
  }else{
    Serial.print ("Configuration error 0x") ;
    Serial.println (errorCode, HEX) ;
  }
}

//----------------------------------------------------------------------------------------------------------------------

static uint32_t gBlinkLedDate = 0 ;
static uint32_t gReceivedFrameCount = 0 ;
static uint32_t gSentFrameCount = 0 ;

//——————————————————————————————————————————————————————————————————————————————

void loop() {
  CANMessage message, frame;
  if (gBlinkLedDate < millis ()) {
    gBlinkLedDate += 1000 ;
    digitalWrite (LED_BUILTIN, !digitalRead (LED_BUILTIN)) ;
    message.id = 0x000;
    message.len = 8;
    message.data[0] = 0x00;
    message.data[1] = 0x10;
    message.data[2] = 0x20;
    message.data[3] = 0x30;
    message.data[4] = 0x40;
    message.data[5] = 0x50;
    message.data[6] = 0x60;
    message.data[7] = 0x70;
    const bool ok = can.tryToSend (message) ;
    if (ok) {
      gSentFrameCount += 1 ;
      Serial.print ("Sent Count: ") ;
      Serial.println (gSentFrameCount) ;
    }else{
      Serial.println ("Send failure") ;
    }

  }
  if (can.receive (frame)) {
    gReceivedCount += 1 ;
    Serial.print ("Received Count: ") ;
    Serial.println (gReceivedCount) ;
  }
}

//——————————————————————————————————————————————————————————————————————————————
