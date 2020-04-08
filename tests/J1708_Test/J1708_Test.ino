#define CAN_switch 2
elapsedMillis timer;
uint8_t message[4] ={0x00,0x00,0x00,0x00};
unsigned char sBuffer[100];

void setup () {
  pinMode(CAN_switch,OUTPUT);
  digitalWrite(CAN_switch, LOW);
  Serial2.begin(9600);
  
}
void loop() {
   
   int nBytes = Serial2.available();
   if(nBytes > 0)
   {
       int nCount = Serial2.readBytes(sBuffer, nBytes);
       for(int nIndex = 0; nIndex < nCount; nIndex++)
       {
           Serial.print(sBuffer[nIndex], HEX);
           Serial.print(" ");
       }
       Serial.println("");
   } 

   if (timer>1000) {
    Serial2.write(message,4);
    timer = 0;
    message[0] +=1;
    message[1] +=1;
    message[2] +=1;
    message[3] +=1;
   }

}

//——————————————————————————————————————————————————————————————————————————————
