#define rx_pin 4
#define tx_pin 3
elapsedMicros counter;

void setup() {
  // put your setup code here, to run once:
Serial.begin(9600);
pinMode(rx_pin,INPUT);
pinMode(tx_pin,OUTPUT);

}

void loop() {
  // put your main code here, to run repeatedly:
  
  if(digitalRead(rx_pin) == 0) {
   counter = 0;
   while (counter< 17) digitalWrite(tx_pin,LOW);
   digitalWrite(tx_pin,HIGH);
   delay(100);
  }

}
