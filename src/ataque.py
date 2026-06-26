import paho.mqtt.client as mqtt
import time

# Tenta publicar sem um CONNECT prévio
client = mqtt.Client()
# Não chamamos client.connect() da forma convencional ou pulamos o fluxo
print("[!] Tentando PUBLISH sem CONNECT (Violação do Autômato)")
client.connect("10.0.0.1", 1883)
client.publish("iot/sensor/temperatura", "DADOS_MALICIOSOS")
