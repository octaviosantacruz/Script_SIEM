import requests
from math import cos, sqrt, radians
from datetime import datetime
import os
from dotenv import load_dotenv
import re

# Cargar las variables de entorno desde el archivo .env
load_dotenv()
IP2LOCATION_API_KEY = os.getenv('API_IP2L_KEY')
IP2LOCATION_URL = os.getenv('API_IP2L_URL')

# --- Función para procesar la respuesta de IP2Location ---
def get_ip2location_info(ip):
    url = f"{IP2LOCATION_URL}?key={IP2LOCATION_API_KEY}&ip={ip}&format=json"
    response = requests.get(url)

    if response.status_code != 200:
        print(f"Error: La API IP2Location devolvió un código de estado {response.status_code} para la IP {ip}")
        return None

    data = response.json()

    if "ip" in data:
        return {
            "ip": data.get('ip'),
            "city": data.get('city_name'),
            "latitude": float(data.get('latitude')),
            "longitude": float(data.get('longitude')),
        }
    else:
        print(f"Error: No se pudo obtener información de IP2Location para la IP {ip}")
        return None

# --- Función para calcular la diferencia de tiempo ---
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

    if velocidad > threshold:
        return True
    return False

# --- Función para calcular la distancia aproximada ---
def approximate_distance(lat1, lon1, lat2, lon2):
    delta_lat = lat2 - lat1
    delta_lon = lon2 - lon1
    lat_media = radians((lat1 + lat2) / 2)

    d = sqrt((delta_lat * 111.32) ** 2 + (delta_lon * 111.32 * cos(lat_media)) ** 2)
    return d

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

    ip2_info_1 = get_ip2location_info(ips[0])
    ip2_info_2 = get_ip2location_info(ips[1])

    if not ip2_info_1 or not ip2_info_2:
        return "Error: No se pudo obtener información para una o ambas IPs"

    expected_city_1 = cities[0]
    expected_city_2 = cities[1]
    actual_city_1 = ip2_info_1['city']
    actual_city_2 = ip2_info_2['city']

    lat1, lon1 = ip2_info_1['latitude'], ip2_info_1['longitude']
    lat2, lon2 = ip2_info_2['latitude'], ip2_info_2['longitude']
    distancia = approximate_distance(lat1, lon1, lat2, lon2)
    tiempo = calculate_time_difference(dates[0], dates[1])

    ciudades_diferentes = (actual_city_1 != expected_city_1) or (actual_city_2 != expected_city_2)
    viaje_imposible = is_impossible_travel(distancia, tiempo)

    # Evaluar las condiciones y generar el mensaje de resultado
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
Workapp - Login desde 2 IPs diferentes    Fecha/hora: 2024/11/22 09:16:35 Usuario: moroside IP de origen: 186.16.26.38 Geolocalizacion de origen: San Lorenzo, Central, Paraguay, 110221 Reputacion de IP (Cisco Talos): https://talosintelligence.com/reputation_center/lookup?search=186.16.26.38 ---  Fecha/hora: 2024/11/22 08:00:38 Usuario: moroside IP de origen: 181.91.85.67 Geolocalizacion de origen: Formosa, Formosa, Argentina, P3600 JIE Reputacion de IP (Cisco Talos): https://talosintelligence.com/reputation_center/lookup?search=181.91.85.67 ---
"""

# Ejecutar la función de prueba
resultado = process_alarm(log)
print(resultado)
