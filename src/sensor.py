# src/sensor_teste.py
import time
import paho.mqtt.client as mqtt

BROKER_IP = "10.0.0.1"
PORT = 1883
TOPIC = "v1/sensor/temperatura"

client = mqtt.Client()

print(# Conectando ao Broker no Gateway
f"Conectando ao broker em {BROKER_IP}:{PORT}...")
try:
    client.connect(BROKER_IP, PORT, 60)
except Exception as e:
    print(f"Erro ao conectar: {e}")
    exit(1)

print("Conectado com sucesso! Iniciando envio de métricas...")

contador = 0
try:
    while True:
        mensagem = f"{{'temperatura': 25.4, 'contador': {contador}}}"
        client.publish(TOPIC, mensagem)
        print(f"Enviado: {mensagem} para o tópico [{TOPIC}]")
        contador += 1
        time.sleep(2)
except KeyboardInterrupt:
    print("\nEncerrando o sensor de teste.")
    client.disconnect()
