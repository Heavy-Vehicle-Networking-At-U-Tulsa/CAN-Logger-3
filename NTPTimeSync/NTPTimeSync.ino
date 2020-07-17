/*
 * UDP NTP Time Synchronization
 * 
 * This code is designed to connect to connect the CAN Logger 3 to a newtork
 * using WPA/WPA2 encryption. It will send a UDP request to an NTP server and,
 * upon receiving one, will update the Teensy Real Time Clock (RTC) to match
 * the received timestamp from the NTP server, in Coordinated Universal Time
 * (UTC). It was adapted from the code at:
 * https://www.arduino.cc/en/Tutorial/UdpNTPClient
 * 
 * This code has been written to use the ATWINC1510-MR210PB WiFi module running
 * firmware version 19.6.1
 * 
 * References:
 * https://www.arduino.cc/en/Guide/ArduinoWiFiShield101#toc5
 * https://www.arduino.cc/en/Tutorial/UdpNTPClient
 * https://www.geekstips.com/arduino-time-sync-ntp-server-esp8266-udp/
 * https://labs.apnic.net/?p=462
 * 
 * Written by:
 * Christopher Lute
 * Colorado State University
 * Contact chris.lute@colostate.edu
 * 
 * Revision date: 16 July 2020
 * Revision Notes:
 *  - 16 July 2020: initial release
 */

#include <SPI.h>
#include <WiFi101.h>
#include <WiFiUdp.h>
#include <TimeLib.h>

// Define pin assignments for CAN Logger 3
#define WiFi_EN 24
#define WiFi_RST 25
#define WiFi_CS 31
#define WiFi_IRQ 23

#include "arduino_secrets.h" 
//please enter your sensitive data in the Secret tab/arduino_secrets.h
char ssid[] = SECRET_SSID;                   // Network SSID (name)
char pass[] = SECRET_PASS;                   // Network password

// Define constants
int status = WL_IDLE_STATUS;                 // Initialize WiFi status to "idle"
unsigned int localPort = 2390;               // UDP port 
//IPAddress timeServerIP(129, 6, 15, 28);
IPAddress timeServerIP;                      // Initialize IP address for NTP server
const char* ntpServerName = "time.nist.gov"; // Obtain time from time.nist.gov server
const int NTP_PACKET_SIZE = 48;              // NTP time stamp is the first 48 bytes of the message
byte packetBuffer[NTP_PACKET_SIZE];          // Buffer to hold packets
char timeString[100];
unsigned long epochTime = 2208988800;        // Seconds from 1 Jan 1900 to 1 Jan 1970 
time_t prevDisplay = 0;                      // Previous time displayed by the clock

// Initialize a WiFi UDP port
WiFiUDP Udp;

// Define constants for NTP client requests
int leapIndicator = 3;                       // Indicates clock is unsynchronized
int versionNumber = 4;                       // Using NTP version 4
int mode = 3;                                // Indicates UDP client 

// Send an NTP request to the time server at the given address
void sendNTPrequest(IPAddress& address)
{
  // Initialize all bytes in the buffer to 0
  memset(packetBuffer, 0, NTP_PACKET_SIZE);
  // Initialize values needed to form NTP request
  packetBuffer[0] = (leapIndicator + versionNumber + mode); // LI, Version, Mode

  Udp.beginPacket(address, 123); // NTP requests are to port 123
  Udp.write(packetBuffer, NTP_PACKET_SIZE);
  Udp.endPacket();
}

// Utility for digital clock display: prints preceding colon and leading 0
void printDigits(int digits){
  Serial.print(":");
  if(digits < 10)
    Serial.print('0');
  Serial.print(digits);
}

// Displays time configured as digital clock display
void digitalClockDisplay(time_t thisTime){
  Serial.print(hour(thisTime));
  printDigits(minute(thisTime));
  printDigits(second(thisTime));
  Serial.print(" ");
  Serial.print(day(thisTime));
  Serial.print(" ");
  Serial.print(month(thisTime));
  Serial.print(" ");
  Serial.println(year(thisTime)); 
}

time_t getTeensy3Time(){
  return Teensy3Clock.get();
}

// Tries to get timestamp using NTP and sets Teensy Real Time Clock (RTC) to NTP time. If no response from NTP server uses Teensy RTC
time_t getTimestamp(){
  time_t timeStamp;
  // Gets IP address from NTP server pool and sends request to server
  WiFi.hostByName(ntpServerName, timeServerIP);  
  sendNTPrequest(timeServerIP);
  
  if (Udp.parsePacket()){
    Udp.read(packetBuffer, NTP_PACKET_SIZE);

    // First four bytes are integer seconds and next four are fractional
    unsigned long integerSeconds = packetBuffer[40] << 24 | packetBuffer[41] << 16 | packetBuffer[42] << 8 | packetBuffer[43];
    // Only using the integer portion for now
    unsigned long fractionalSeconds = packetBuffer[44] << 24 | packetBuffer[45] << 16 | packetBuffer[46] << 8 | packetBuffer[47];
    timeStamp = integerSeconds - epochTime; 
    Teensy3Clock.set(timeStamp);
    setTime(timeStamp);
  }
  else {
    Serial.println("No response from server, using onboard RTC");
    timeStamp = getTeensy3Time();
  }
  return timeStamp;
}
void setup() {
  //Initialize serial and wait for port to open:
  Serial.begin(9600);
  while (!Serial){
    ; // wait for serial port to connect. Needed for native USB port only
  }

  // Set pins for CAN Logger 3
  WiFi.setPins(WiFi_CS,WiFi_IRQ,WiFi_RST);
  pinMode(WiFi_EN, OUTPUT);
  digitalWrite(WiFi_EN,HIGH);

  // Checks to verify WiFi shield is present
  if (WiFi.status() == WL_NO_SHIELD){
    Serial.println("WiFi shield not present");
  }

  // Verify installed firmware version. This code was developed using firmware version 19.6.1
  String fv = WiFi.firmwareVersion();
  if (fv == "19.6.1") {
    Serial.println("Firmware check: PASSED\n");
  }
  else {
    Serial.println("Please revise firmware to 19.6.1");
    Serial.print("Currently installed firmware: ");
    Serial.println(fv);
  }
    
  // Attempt to connect to WiFi network:
  while ( status != WL_CONNECTED){
    status = WiFi.begin(ssid, pass);
    Serial.print("Attempting to connect to WPA SSID: ");
    Serial.println(ssid); 
    delay(3000);
  }

  // Print connection status
  Serial.print("Connected to network: ");
  Serial.println(WiFi.SSID());
  Serial.println("Starting UDP");
  Udp.begin(localPort);
  Serial.print("Local port: ");
  Serial.println(localPort);

  // Sync to local clock to NTP
  setSyncProvider(getTimestamp);
  if (timeStatus()!= timeSet) {
    Serial.println("Unable to sync with the RTC");
  }
  else {
    Serial.println("RTC has set the system time");
  }
  setSyncInterval(1);
}

void loop(){
  if (timeStatus() != timeNotSet) {
    // Looks to see if now() has updated, updates prevDisplay to now() and displays new time
    if (now() != prevDisplay) {
      prevDisplay = now();
      digitalClockDisplay(prevDisplay);  
    }
  }
}
