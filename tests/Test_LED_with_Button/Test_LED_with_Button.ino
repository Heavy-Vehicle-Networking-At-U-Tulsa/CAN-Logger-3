//Define LED pins based on schematic
#define GREEN_LED_PIN 6
#define RED_LED_PIN 14
#define YELLOW_LED_PIN 5
#define BLUE_LED_PIN 39

//Define button pin, the button is soldered on SW21
#define button1 28
#define button2 53
//Create a on/off boolean for the button
bool buttonState1;
bool buttonState2;

void setup() {
  // put your setup code here, to run once:
  //Define LED pin mode
  pinMode(GREEN_LED_PIN,OUTPUT);
  pinMode(YELLOW_LED_PIN,OUTPUT);
  pinMode(RED_LED_PIN,OUTPUT);
  pinMode(BLUE_LED_PIN,OUTPUT);
  //Pull button high
  pinMode(button1,INPUT_PULLUP);
  pinMode(button2,INPUT_PULLUP);
}

void loop() {
  // put your main code here, to run repeatedly:
  //If button is pushed, the pin will pull low
  buttonState1= digitalRead(button1); 
  buttonState2= digitalRead(button2); 
  digitalWrite(GREEN_LED_PIN,buttonState1);
  digitalWrite(YELLOW_LED_PIN,buttonState1);
  digitalWrite(RED_LED_PIN,buttonState2);
  digitalWrite(BLUE_LED_PIN,buttonState2);
  
}
