import requests
from math import cos, sqrt, radians
from datetime import datetime
import os
from dotenv import load_dotenv
import re

# Cargar las variables de entorno desde el archivo .env
load_dotenv()
API_KEY = os.getenv('API_KEY')

# --- Función para procesar la respuesta en texto plano ---
def parse_plaintext_response(response_text):
    # Divide la respuesta en líneas y elimina los espacios innecesarios
    lines = [line.strip() for line in response_text.split("\n") if line.strip()]

    # Crea un diccionario para almacenar los valores extraídos
    ip_info = {}

    # Recorre las líneas y extrae los valores de cada línea que contienen "key:value"
    for line in lines:
        if ":" in line:
            key, value = line.split(":", 1)  # Divide en el primer ":"
            key = key.strip().lower()        # Convierte la clave a minúsculas
            value = value.strip()            # Elimina espacios en el valor
            ip_info[key] = value             # Añade al diccionario
    
    # Verifica si el estado es "ok"
    if ip_info.get("status") == "ok":
        return {
            "ip": ip_info.get('ip'),
            "city": ip_info.get('city'),
            "latitude": float(ip_info.get('latitude')),
            "longitude": float(ip_info.get('longitude')),
        }
    else:
        print(f"Error: Estado no 'ok' en la respuesta {response_text}")
        return None

# --- Función para obtener información de IP usando la API ---
def get_ip_info(ip):
    url = f"https://api.whatismyip.com/ip-address-lookup.php?key={API_KEY}&input={ip}"
    print(f"Obteniendo información para la IP: {ip}")
    response = requests.get(url)

    # Comprobamos si la respuesta es válida antes de continuar
    if response.status_code != 200:
        print(f"Error: La API devolvió un código de estado {response.status_code} para la IP {ip}")
        return None

    # Trabajamos con la respuesta en texto plano
    response_text = response.text

    # Llamamos a la función para procesar la respuesta en texto plano
    ip_info = parse_plaintext_response(response_text)
    if ip_info:
        return ip_info
    else:
        print(f"Error: No se pudo obtener información para la IP {ip}")
        return None

# --- Función para calcular la distancia utilizando la fórmula aproximada ---
def approximate_distance(lat1, lon1, lat2, lon2, city1, city2):
    # Calculamos la diferencia de latitud y longitud
    delta_lat = lat2 - lat1
    delta_lon = lon2 - lon1
    
    # Latitud media en radianes
    lat_media = radians((lat1 + lat2) / 2)
    print(f"Ciudad de Origen: {city1} ({lat1}, {lon1})")
    print(f"Ciudad de Destino: {city2} ({lat2}, {lon2})")
    # Fórmula de distancia aproximada (km)
    d = sqrt((delta_lat * 111.32) ** 2 + (delta_lon * 111.32 * cos(lat_media)) ** 2)
    return d  # Retorna la distancia en km

# --- Función para calcular la diferencia de tiempo en horas ---
def calculate_time_difference(time1, time2):
    time_format = "%Y/%m/%d %H:%M:%S"
    t1 = datetime.strptime(time1, time_format)
    t2 = datetime.strptime(time2, time_format)
    
    time_diff = abs((t1 - t2).total_seconds() / 3600)  # Diferencia en horas
    return time_diff

# --- Función para determinar si el viaje es imposible ---
def is_impossible_travel(distancia, tiempo, threshold=120):
    if tiempo == 0:
        print("Error: El tiempo entre los dos eventos es cero")
        return True

    velocidad = distancia / tiempo  # Calcula la velocidad en km/h

    print(f"Velocidad calculada: {velocidad:.2f} km/h")

    # Si la velocidad es mayor al umbral, consideramos que el viaje es imposible
    if velocidad > threshold:
        print(f"Alerta: El viaje es imposible. Velocidad ({velocidad:.2f} km/h) excede el umbral de {threshold} km/h.")
        return True
    else:
        print(f"El viaje es posible. Velocidad calculada: {velocidad:.2f} km/h")
        return False

# --- Función para procesar la alarma y verificar velocidad ---
def process_alarm(log):
    # Regex para extraer las IPs y fechas del log
    ip_regex = r"IP de origen: (\d+\.\d+\.\d+\.\d+)"  # IP address pattern
    date_regex = r"Fecha/hora: (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})"
    
    ips = re.findall(ip_regex, log)
    dates = re.findall(date_regex, log)

    if len(ips) != 2:
        print("Error: No se pudieron encontrar dos IPs en el log")
        return
    if len(dates) != 2:
        print("Error: No se pudieron encontrar dos fechas en el log")
        return

    # Obtener información de ambas IPs
    ip_info_1 = get_ip_info(ips[0])
    ip_info_2 = get_ip_info(ips[1])

    if ip_info_1 is None or ip_info_2 is None:
        print("Error: No se pudo obtener información para una o ambas IPs")
        return
    # Obtener ciudades de origen de ambas IPs
    city1 = ip_info_1['city']
    city2 = ip_info_2['city']
    # Obtener las latitudes y longitudes de ambas IPs
    lat1, lon1 = ip_info_1['latitude'], ip_info_1['longitude']
    lat2, lon2 = ip_info_2['latitude'], ip_info_2['longitude']

    # Calcular la distancia entre las dos IPs usando la fórmula aproximada
    distancia = approximate_distance(lat1, lon1, lat2, lon2, city1, city2)
    print(f"La distancia entre las dos IPs es de aproximadamente {distancia:.2f} km")

    # Calcular la diferencia de tiempo en horas
    tiempo = calculate_time_difference(dates[0], dates[1])
    print(f"Diferencia de tiempo entre los dos eventos: {tiempo:.2f} horas")

    # Determinar si el viaje es imposible según la velocidad media
    is_impossible_travel(distancia, tiempo, threshold=120)

# --- Ejemplo de log para probar ---
log = """
Workapp - Login desde 2 IPs diferentes    
Fecha/hora: 2024/10/15 08:07:08 Usuario: sosaro IP de origen: 181.94.208.201 
Geolocalizacion de origen: Asuncion, Asuncion, Paraguay, 1119 Reputacion de IP (Cisco Talos): https://talosintelligence.com/reputation_center/lookup?search=181.94.208.201 ---  
Fecha/hora: 2024/10/15 13:22:33 Usuario: sosaro IP de origen: 181.91.87.152 
Geolocalizacion de origen: Formosa, Formosa, Argentina, P3600 JIE Reputacion de IP (Cisco Talos): https://talosintelligence.com/reputation_center/lookup?search=181.91.87.152 ---
"""
log2 = """
Workapp - Login desde 2 IPs diferentes    
Fecha/hora: 2024/10/15 12:36:10 Usuario: u996467 IP de origen: 190.104.176.241 
Geolocalizacion de origen: San Estanislao, San Pedro, Paraguay, 8210 Reputacion de IP (Cisco Talos): https://talosintelligence.com/reputation_center/lookup?search=190.104.176.241 ---  
Fecha/hora: 2024/10/15 09:06:04 Usuario: u996467 IP de origen: 181.94.250.37 
Geolocalizacion de origen: Asuncion, Asuncion, Paraguay, 1119 Reputacion de IP (Cisco Talos): https://talosintelligence.com/reputation_center/lookup?search=181.94.250.37 ---
"""
log3 = """s
Workapp - Login desde 2 IPs diferentes    
Fecha/hora: 2024/10/15 12:21:32 Usuario: u997390 IP de origen: 190.104.177.62 
Geolocalizacion de origen: Encarnacion, Itapua, Paraguay, 6000 Reputacion de IP (Cisco Talos): https://talosintelligence.com/reputation_center/lookup?search=190.104.177.62 ---  
Fecha/hora: 2024/10/15 11:55:44 Usuario: u997390 IP de origen: 181.94.231.35 
Geolocalizacion de origen: Asuncion, Asuncion, Paraguay, 1119 Reputacion de IP (Cisco Talos): https://talosintelligence.com/reputation_center/lookup?search=181.94.231.35 ---
"""

result = process_alarm(log2)
