import requests
from math import cos, sqrt, radians
from datetime import datetime
import os
from dotenv import load_dotenv
import re
import sys

# Configurar la codificación UTF-8
sys.stdout.reconfigure(encoding='utf-8')

# Cargar las variables de entorno desde el archivo .env
load_dotenv()
IP2LOCATION_API_KEY = os.getenv('API_IP2L_KEY')
IP2LOCATION_URL = os.getenv('API_IP2L_URL')

# Función para procesar la respuesta de IP2Location
def get_ip2location_info(ip):
    try:
        # Definir la URL completa para hacer la solicitud GET
        url = f"{IP2LOCATION_URL}?ip={ip}&key={IP2LOCATION_API_KEY}"

        # Realizar la solicitud GET a la API
        response = requests.get(url)

        # Verificar si la respuesta fue exitosa (código 200)
        if response.status_code == 200:
            data = response.json()  # Parsear la respuesta JSON

            # Extraer información relevante
            location_info = {
                "country": data.get("country_name", "N/A"),
                "region": data.get("region_name", "N/A"),
                "city": data.get("city_name", "N/A"),
                "latitude": data.get("latitude", "N/A"),
                "longitude": data.get("longitude", "N/A"),
                "isp": data.get("isp", "N/A")
            }
            return location_info

        else:
            print(f"Error al obtener la información de IP2Location. Código de estado: {response.status_code}")
            return None

    except requests.exceptions.RequestException as e:
        print(f"Error al realizar la solicitud a la API: {e}")
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

# --- Función principal para procesar alertas ---
def process_alarm(log):
    # Identificar el tipo de alerta
    if "Login desde 2 IPs diferentes" in log:
        return process_multiple_ip_login(log)
    elif "VPN fuera de ARG o PY" in log:
        return process_vpn_outside_permitted_countries(log)
    elif "Login fuera de ARG y PY" in log:
        return process_login_outside_permitted_countries(log)
    else:
        return "Error: Tipo de alerta no identificado en el log."

# --- Función para procesar login desde dos IPs diferentes ---
def process_multiple_ip_login(log):
    ip_regex = r"IP de origen: (\d+\.\d+\.\d+\.\d+)"
    date_regex = r"Fecha/hora: (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})"

    ips = re.findall(ip_regex, log)
    dates = re.findall(date_regex, log)

    if len(ips) != 2 or len(dates) != 2:
        return "Error: No se pudieron encontrar dos IPs o dos fechas en el log"

    ip_info_1 = get_ip2location_info(ips[0])
    ip_info_2 = get_ip2location_info(ips[1])

    if not ip_info_1 or not ip_info_2:
        return "Error: No se pudo obtener información para una o ambas IPs"

    lat1, lon1 = ip_info_1['latitude'], ip_info_1['longitude']
    lat2, lon2 = ip_info_2['latitude'], ip_info_2['longitude']
    distancia = approximate_distance(lat1, lon1, lat2, lon2)
    tiempo = calculate_time_difference(dates[0], dates[1])

    if is_impossible_travel(distancia, tiempo):
        return f"Alerta: Viaje imposible detectado entre las IPs {ips[0]} y {ips[1]}. Distancia: {distancia:.2f} km, Tiempo: {tiempo:.2f} horas."
    else:
        return f"Login desde dos IPs diferentes detectado. Viaje posible. Distancia: {distancia:.2f} km, Tiempo: {tiempo:.2f} horas."

# --- Función para extraer país del log ---
def extract_country_from_log(log):
    country_regex = r"Geolocalizacion de origen: [\w\sáéíóúÁÉÍÓÚñÑ]+, [\w\sáéíóúÁÉÍÓÚñÑ]+, (\w+)"
    match = re.search(country_regex, log)

    if match:
        return match.group(1)
    return None

# --- Función para procesar VPN fuera de ARG o PY ---
def process_vpn_outside_permitted_countries(log):
    ip_regex = r"IP de origen: (\d+\.\d+\.\d+\.\d+)"
    ip_match = re.search(ip_regex, log)

    if not ip_match:
        return "Error: No se pudo encontrar la IP en el log"

    ip = ip_match.group(1)
    ip_info = get_ip2location_info(ip)

    if not ip_info:
        return "Error: No se pudo obtener información de la IP"

    detected_country = ip_info['country']
    log_country = extract_country_from_log(log)

    if not log_country:
        return "Error: No se pudo extraer el país del log"

    if detected_country == log_country:
        return f"Se verifica que el usuario reside en {detected_country}."
    else:
        return f"Alerta: Inconsistencia detectada. El log indica {log_country}, pero la IP pertenece a {detected_country}. IP: {ip}."

# --- Función para procesar login fuera de ARG y PY ---
def process_login_outside_permitted_countries(log):
    return process_vpn_outside_permitted_countries(log)

if __name__ == "__main__":
    # --- Ejemplo de logs para probar ---
    logs = [
        """Workapp - Login desde 2 IPs diferentes    Fecha/hora: 2024/12/09 16:03:16 Usuario: v2391077 IP de origen: 181.91.85.251 Geolocalizacion de origen: Formosa, Formosa, Argentina, P3600 JIE Reputacion de IP (Cisco Talos): https://talosintelligence.com/reputation_center/lookup?search=181.91.85.251 ---  Fecha/hora: 2024/12/09 11:08:02 Usuario: v2391077 IP de origen: 190.104.176.203 Geolocalizacion de origen: San Estanislao, San Pedro, Paraguay, 8210 Reputacion de IP (Cisco Talos): https://talosintelligence.com/reputation_center/lookup?search=190.104.176.203 ---""",
        
        """Notificacion SIEM - VPN fuera de ARG o PY.
        Fecha/hora: 2024/12/06 12:39:09 Usuario: e47483962 IP de origen: 190.135.226.84 Geolocalizacion de origen: Minas, Lavalleja, Uruguay""",
        
        """Notificacion SIEM - Workapp - Login fuera de ARG y PY
        Fecha/hora: 2024/12/06 15:37:51 Usuario: e47483962 IP de origen: 190.135.226.84 Geolocalizacion de origen: Minas, Lavalleja, Uruguay"""
    ]

    # Ejecutar las funciones de prueba con los logs de ejemplo
    for log in logs:
        resultado = process_alarm(log)
        print(resultado)
        print("---")
