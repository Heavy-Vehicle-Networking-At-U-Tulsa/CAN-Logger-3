
#define CAN_switch 2

void setup () {
  pinMode(CAN_switch,OUTPUT);
  digitalWrite(CAN_switch, LOW);
  Serial2.begin(9600);
  
}


void loop() {
  unsigned char sBuffer[100];

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

}

//——————————————————————————————————————————————————————————————————————————————
