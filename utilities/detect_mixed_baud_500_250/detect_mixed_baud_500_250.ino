#include <FlexCAN.h>                                   
#define CAN_ERR_FLAG 0x20000000

#define RX_TIMEOUT 250
#define LED_TIMEOUT 10000

CAN_message_t rxmsg0;
CAN_message_t rxmsg1;

uint32_t RXCount0 = 0;
uint32_t RXCount1 = 0;

//Define LED
#define GREEN_LED_PIN 6
#define RED_LED_PIN 14
#define YELLOW_LED_PIN 5
#define BLUE_LED_PIN 39 //Can Logger 3

//Set LEDs
boolean GREEN_LED_state; 
boolean RED_LED_state;
boolean YELLOW_LED_state;
boolean BLUE_LED_state;

//Define CAN TXRX Transmission Silent pins for CAN Logger 2
//#define SILENT_0 39
//#define SILENT_1 38
//#define SILENT_2 37

//Define CAN TXRX Transmission Silent pins for CAN Logger 3
#define SILENT_0 40
#define SILENT_1 41
#define SILENT_2 42

elapsedMillis can0_error_timer;
elapsedMillis can1_error_timer;
elapsedMillis can0_rx_timer;
elapsedMillis can1_rx_timer;

//A generic CAN Frame print function for the Serial terminal
void printFrame(CAN_message_t rxmsg, uint8_t channel, uint32_t RXCount)
{
  char CANdataDisplay[50];
  sprintf(CANdataDisplay, "%d %12lu %12lu %08X %d %d", channel, RXCount, micros(), rxmsg.id, rxmsg.ext, rxmsg.len);
  Serial.print(CANdataDisplay);
  for (uint8_t i = 0; i < rxmsg.len; i++) {
    char CANBytes[4];
    sprintf(CANBytes, " %02X", rxmsg.buf[i]);
    Serial.print(CANBytes);
  }
  Serial.println();
}

void setup()
{
  // Disable transmission for the CAN TXRX
  pinMode(SILENT_0,OUTPUT);
  pinMode(SILENT_1,OUTPUT);
  pinMode(SILENT_2,OUTPUT);
  digitalWrite(SILENT_0,HIGH);
  digitalWrite(SILENT_1,HIGH);
  digitalWrite(SILENT_2,HIGH);

  pinMode(GREEN_LED_PIN,OUTPUT);
  pinMode(RED_LED_PIN,OUTPUT);
  pinMode(YELLOW_LED_PIN,OUTPUT);
  pinMode(BLUE_LED_PIN,OUTPUT);
  
  Can0.begin(500000);
  Can1.begin(666666);
  Can0.setReportErrors(true);
  Can1.setReportErrors(true);
}

void loop()
{
  if (Can0.available()) {
    Can0.read(rxmsg0);
    //Toggle the LED
    if (rxmsg0.id & CAN_ERR_FLAG){
      // Error frame
      RED_LED_state = !RED_LED_state;
      digitalWrite(RED_LED_PIN,RED_LED_state);
      can0_error_timer = 0;
    }
    else {
      printFrame(rxmsg0,0,RXCount0++);
      GREEN_LED_state = !GREEN_LED_state;
      digitalWrite(GREEN_LED_PIN,GREEN_LED_state);
      can0_rx_timer = 0;
    }
  }
  if (Can1.available()) {
    Can1.read(rxmsg1);
    //Toggle the LED
    if (rxmsg1.id & CAN_ERR_FLAG){
      // Error frame
      YELLOW_LED_state = !YELLOW_LED_state;
      digitalWrite(YELLOW_LED_PIN,YELLOW_LED_state);
      can1_error_timer = 0;
    }
    else {
      printFrame(rxmsg1,1,RXCount1++);
      BLUE_LED_state = !BLUE_LED_state;
      digitalWrite(BLUE_LED_PIN,BLUE_LED_state);
      can1_rx_timer = 0;
    }
  }

  if (can0_rx_timer >= RX_TIMEOUT){
    GREEN_LED_state = HIGH;
    digitalWrite(GREEN_LED_PIN,GREEN_LED_state);  
  }
  if (can1_rx_timer >= RX_TIMEOUT){
    BLUE_LED_state = LOW;
    digitalWrite(BLUE_LED_PIN,BLUE_LED_state);  
  }
  
  if (can0_error_timer >= LED_TIMEOUT){
    RED_LED_state = LOW;
    digitalWrite(RED_LED_PIN,RED_LED_state);  
  }
  if (can1_error_timer >= LED_TIMEOUT){
    YELLOW_LED_state = LOW;
    digitalWrite(YELLOW_LED_PIN,YELLOW_LED_state);  
  }
}
