import requests
from math import cos, sqrt, radians
from datetime import datetime
import os
from dotenv import load_dotenv
import re

# Cargar las variables de entorno desde el archivo .env
load_dotenv()
API_KEY = os.getenv('API_WMIP_KEY')
API_URL = os.getenv('API_WMIP_URL')

# --- Función para procesar la respuesta en texto plano ---
def parse_plaintext_response(response_text):
    lines = [line.strip() for line in response_text.split("\n") if line.strip()]
    ip_info = {}

    for line in lines:
        if ":" in line:
            key, value = line.split(":", 1)
            key = key.strip().lower()
            value = value.strip()
            ip_info[key] = value

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

# --- Función para obtener información de IP usando API_WMIP ---
def get_ip_info(ip):
    url = f"{API_URL}={API_KEY}&input={ip}"
    response = requests.get(url)

    if response.status_code != 200:
        print(f"Error: La API devolvió un código de estado {response.status_code} para la IP {ip}")
        return None

    return parse_plaintext_response(response.text)

# --- Función para calcular la distancia ---
def approximate_distance(lat1, lon1, lat2, lon2):
    delta_lat = lat2 - lat1
    delta_lon = lon2 - lon1
    lat_media = radians((lat1 + lat2) / 2)
    d = sqrt((delta_lat * 111.32) ** 2 + (delta_lon * 111.32 * cos(lat_media)) ** 2)
    return d

# --- Función para calcular la diferencia de tiempo en horas ---
def calculate_time_difference(time1, time2):
    time_format = "%Y/%m/%d %H:%M:%S"
    t1 = datetime.strptime(time1, time_format)
    t2 = datetime.strptime(time2, time_format)
    return abs((t1 - t2).total_seconds() / 3600)

# --- Función para determinar si el viaje es imposible ---
def is_impossible_travel(distancia, tiempo, threshold=120):
    if tiempo == 0:
        return True

    velocidad = distancia / tiempo
    return velocidad > threshold

# --- Función para procesar la alarma y verificar ubicación ---
def process_alarm(log):
    ip_regex = r"IP de origen: (\d+\.\d+\.\d+\.\d+)"
    date_regex = r"Fecha/hora: (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})"
    city_regex = r"Geolocalizacion de origen: ([\w\sáéíóúÁÉÍÓÚñÑ]+),"

    ips = re.findall(ip_regex, log)
    dates = re.findall(date_regex, log)
    cities = re.findall(city_regex, log)

    if len(ips) != 2:
        return "Error: No se pudieron encontrar dos IPs en el log"
    if len(dates) != 2:
        return "Error: No se pudieron encontrar dos fechas en el log"
    if len(cities) != 2:
        return "Error: No se pudieron encontrar dos ciudades en el log"

    ip_info_1 = get_ip_info(ips[0])
    ip_info_2 = get_ip_info(ips[1])

    if not ip_info_1 or not ip_info_2:
        return "Error: No se pudo obtener información para una o ambas IPs"

    expected_city_1 = cities[0]
    expected_city_2 = cities[1]
    actual_city_1 = ip_info_1['city']
    actual_city_2 = ip_info_2['city']

    lat1, lon1 = ip_info_1['latitude'], ip_info_1['longitude']
    lat2, lon2 = ip_info_2['latitude'], ip_info_2['longitude']
    distancia = approximate_distance(lat1, lon1, lat2, lon2)
    tiempo = calculate_time_difference(dates[0], dates[1])

    ciudades_diferentes = (actual_city_1 != expected_city_1) or (actual_city_2 != expected_city_2)
    viaje_imposible = is_impossible_travel(distancia, tiempo)

    if viaje_imposible and ciudades_diferentes:
        return (f"Alerta: Viaje imposible detectado y discrepancias de ciudad encontradas.\n"
                f"Distancia: {distancia:.2f} km, Tiempo: {tiempo:.2f} horas.\n"
                f"Ciudades detectadas: {actual_city_1} y {actual_city_2}, "
                f"esperadas: {expected_city_1} y {expected_city_2}.")
    elif viaje_imposible:
        return (f"Favor verificar manualmente: Se detectó un viaje imposible.\n"
                f"Distancia: {distancia:.2f} km, Tiempo: {tiempo:.2f} horas.")
    elif ciudades_diferentes:
        return (f"Discrepancia: Usuario detectado en {actual_city_1} y {actual_city_2}, "
                f"esperadas: {expected_city_1} y {expected_city_2}. Localidades cercanas, pero verifique manualmente.")
    else:
        return (f"Localidades cercanas: El viaje es posible según los datos proporcionados.\n"
                f"Distancia: {distancia:.2f} km, Tiempo: {tiempo:.2f} horas.")

# --- Ejemplo de log para probar ---
log = """
Notificacion SIEM - Workapp - Login desde 2 IPs diferentes    
    Fecha/hora: 2024/12/06 15:37:32 Usuario: u997839 IP de origen: 181.94.250.37 Geolocalizacion de origen: Asuncion, Asuncion, Paraguay, 1119 
    Fecha/hora: 2024/12/06 16:43:39 Usuario: u997839 IP de origen: 181.91.87.76 Geolocalizacion de origen: Formosa, Formosa, Argentina, P3600 JIE
"""

# Ejecutar la función de prueba
result = process_alarm(log)
print(result)
