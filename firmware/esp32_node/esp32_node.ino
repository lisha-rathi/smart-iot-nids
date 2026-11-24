// ESP32 IoT sensor node: DHT + PIR + relay (fan) + buzzer + LED, reporting over MQTT.
// Tested in the Wokwi simulator. For the real board, change the settings marked below.
//
// Pins: DHT data GPIO4, PIR out GPIO27, relay IN GPIO26, buzzer GPIO25, LED GPIO2
// Arduino libraries: DHT sensor library, Adafruit Unified Sensor, PubSubClient

#include <WiFi.h>
#include <PubSubClient.h>
#include "DHT.h"

// ---------- settings: change these for the real board ----------
const char* WIFI_SSID    = "YOUR_WIFI_NAME";       // real board: laptop hotspot name
const char* WIFI_PASS    = "YOUR_WIFI_PASSWORD";                  // real board: hotspot password
const int   WIFI_CHANNEL = 0;                 // Wokwi only. Real board: 0
const char* MQTT_HOST    = "192.168.137.1"; // real board: laptop's IP on the hotspot
const int   MQTT_PORT    = 1883;
const char* TOPIC_PREFIX = "iotnids-demo-4821"; // public broker is shared, keep this unique
const char* NODE_ID      = "node1";
// ----------------------------------------------------------------

#define DHTPIN     4
#define DHTTYPE    DHT11   // Wokwi only has DHT22. Use DHT11 on the real board.
#define PIR_PIN    27
#define RELAY_PIN  26
#define BUZZER_PIN 25
#define LED_PIN    2

#define RELAY_ON   HIGH    // many real relay modules are active-LOW: swap if inverted
#define RELAY_OFF  LOW

const float FAN_ON_TEMP  = 30.0;
const float FAN_OFF_TEMP = 28.0;

DHT dht(DHTPIN, DHTTYPE);
WiFiClient espClient;
PubSubClient mqtt(espClient);

String tTelemetry, tCmd, tStatus;
bool fanOn = false;
bool alertOn = false;
unsigned long lastRead = 0;
unsigned long lastMqttTry = 0;

void onMessage(char* topic, byte* payload, unsigned int len) {
  String msg;
  for (unsigned int i = 0; i < len; i++) msg += (char)payload[i];
  msg.trim();
  Serial.println("cmd received: " + msg);
  if (msg == "ALERT_ON")  alertOn = true;
  if (msg == "ALERT_OFF") alertOn = false;
}

// runs every loop, never blocks the fan logic
void networkTick() {
  if (WiFi.status() != WL_CONNECTED) return;   // auto-reconnect is on

  if (!mqtt.connected()) {
    if (millis() - lastMqttTry < 5000) return;
    lastMqttTry = millis();
    String cid = String("esp32-") + TOPIC_PREFIX + "-" + NODE_ID;
    // last-will: broker publishes "offline" if the ESP32 drops
    if (mqtt.connect(cid.c_str(), NULL, NULL, tStatus.c_str(), 1, true, "offline")) {
      mqtt.publish(tStatus.c_str(), "online", true);
      mqtt.subscribe(tCmd.c_str());
      Serial.println("MQTT connected");
    } else {
      Serial.printf("MQTT failed, rc=%d\n", mqtt.state());
    }
    return;
  }
  mqtt.loop();
}

void setup() {
  Serial.begin(115200);
  pinMode(PIR_PIN, INPUT);
  pinMode(RELAY_PIN, OUTPUT);
  pinMode(BUZZER_PIN, OUTPUT);
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(RELAY_PIN, RELAY_OFF);
  dht.begin();

  tTelemetry = String(TOPIC_PREFIX) + "/" + NODE_ID + "/telemetry";
  tCmd       = String(TOPIC_PREFIX) + "/" + NODE_ID + "/cmd";
  tStatus    = String(TOPIC_PREFIX) + "/" + NODE_ID + "/status";

  WiFi.mode(WIFI_STA);
  WiFi.setAutoReconnect(true);
  WiFi.begin(WIFI_SSID, WIFI_PASS, WIFI_CHANNEL);
  Serial.print("Connecting to WiFi");

  mqtt.setServer(MQTT_HOST, MQTT_PORT);
  mqtt.setCallback(onMessage);
}

void loop() {
  networkTick();

  // Serial test commands still work: 'a' = alert on, 'n' = alert off
  if (Serial.available()) {
    char c = Serial.read();
    if (c == 'a') alertOn = true;
    if (c == 'n') alertOn = false;
  }

  if (alertOn) {
    tone(BUZZER_PIN, 1000);
    digitalWrite(LED_PIN, HIGH);
  } else {
    noTone(BUZZER_PIN);
    digitalWrite(LED_PIN, LOW);
  }

  if (millis() - lastRead >= 2000) {
    lastRead = millis();
    float t = dht.readTemperature();
    float h = dht.readHumidity();
    int motion = digitalRead(PIR_PIN);

    if (isnan(t) || isnan(h)) {
      Serial.println("DHT read failed");
      return;
    }

    // fan logic runs on the ESP32 itself, so it works even if the network is down
    if (!fanOn && t >= FAN_ON_TEMP) fanOn = true;
    if (fanOn && t <= FAN_OFF_TEMP) fanOn = false;
    digitalWrite(RELAY_PIN, fanOn ? RELAY_ON : RELAY_OFF);

    char buf[128];
    snprintf(buf, sizeof(buf),
             "{\"temp\":%.1f,\"hum\":%.1f,\"motion\":%d,\"fan\":%d,\"alert\":%d}",
             t, h, motion, fanOn ? 1 : 0, alertOn ? 1 : 0);

    if (mqtt.connected()) mqtt.publish(tTelemetry.c_str(), buf);
    Serial.printf("%s  wifi=%s mqtt=%s\n", buf,
                  WiFi.status() == WL_CONNECTED ? "ok" : "down",
                  mqtt.connected() ? "ok" : "down");
  }
  delay(10);
}
