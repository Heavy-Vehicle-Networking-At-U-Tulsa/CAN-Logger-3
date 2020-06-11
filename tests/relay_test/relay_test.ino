//Define LED
#define red_led 14
#define blue_led 39


//Define Button
#define button 28
bool button_state;


//Define relay
#define relay_switch 2

void setup() {
 // put your setup code here, to run once:

 
 //Start serial with red LED on
Serial.begin(9600);
 delay(2);
 pinMode (red_led, OUTPUT);
 pinMode (blue_led, OUTPUT);
 digitalWrite (red_led, HIGH);
 pinMode(button,INPUT_PULLUP);
 pinMode(relay_switch, INPUT_PULLUP);
 delay(1000);
}
void loop() {
 // put your main code here, to run repeatedly:
  button_state = !digitalRead(button);
  digitalWrite(blue_led,LOW);
  digitalWrite(relay_switch,LOW);
  if (button_state == true){
    digitalWrite(blue_led,HIGH);
    digitalWrite(relay_switch,HIGH);
  }
}
