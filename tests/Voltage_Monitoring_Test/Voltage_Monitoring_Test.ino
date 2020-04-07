//Define source pins
#define RAW_sense 21
#define A6_sense 20
int RAW_measure = A22;
int A7_measure = A21;

#define green_LED 14

void setup() {
  // put your setup code here, to run once:
   pinMode(RAW_sense, INPUT_PULLUP);
   pinMode(A6_sense, INPUT_PULLUP);
   pinMode(green_LED,OUTPUT);
}

void loop() {
  // put your main code here, to run repeatedly:
  Serial.print("RAW sense:");
  Serial.println(digitalRead(RAW_sense));
  Serial.print("RAW measure:");
  Serial.println(analogRead(RAW_measure));
  
  Serial.print("A6 sense:");
  Serial.println(digitalRead(A6_sense));
  Serial.print("A7 measure:");
  Serial.println(analogRead(A7_measure));
  Serial.println("------------------------");
  digitalWrite(green_LED,HIGH);
  delay(1000);
  digitalWrite(green_LED,LOW);
  delay(100);
  
  
}
