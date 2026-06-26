# src/subscriber_teste.py
import paho.mqtt.client as mqtt

BROKER_IP = "10.0.0.1"
PORT = 1883
TOPIC = "iot/sensor/#"

def on_connect(client, userdata, flags, rc):
    print(f"Conectado ao Broker com código de resultado: {rc}")
    client.subscribe(TOPIC)
    print(f"Inscrito com sucesso no tópico: {TOPIC}")

def on_message(client, userdata, msg):
    print(f"📥 Mensagem Recebida via Broker -> Tópico: {msg.topic} | Conteúdo: {msg.payload.decode()}")

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message

print(f"Conectando ao broker em {BROKER_IP} para escuta...")
client.connect(BROKER_IP, PORT, 60)

try:
    client.loop_forever()
except KeyboardInterrupt:
    print("\nEncerrando escuta.")
    client.disconnect()
