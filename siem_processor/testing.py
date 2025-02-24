import requests
from math import cos, sqrt, radians
from datetime import datetime
import re
import sys

# Configurar la codificación UTF-8
sys.stdout.reconfigure(encoding='utf-8')

# Función para obtener información de una IP desde la API de NordVPN
def get_ip_info_from_nordvpn(ip):
    try:
        url = f"https://web-api.nordvpn.com/v1/ips/lookup/{ip}"
        response = requests.get(url)

        if response.status_code == 200:
            data = response.json()

            # Extraer información relevante
            location_info = {
                "ip": data.get("ip", "N/A"),
                "country": data.get("country", "N/A"),
                "country_code": data.get("country_code", "N/A"),
                "region": data.get("region", "N/A"),
                "city": data.get("city", "N/A"),
                "state_code": data.get("state_code", "N/A"),
                "zip_code": data.get("zip_code", "Unknown"),
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
                "isp": data.get("isp", "N/A"),
                "asn": data.get("isp_asn", "N/A"),
                "host_domain": data["host"]["domain"] if data.get("host") else "N/A",
                "vpn_detected": data.get("hosted", False),
                "gdpr": data.get("gdpr", False),
            }
            return location_info

        else:
            print(f"Error en API NordVPN. Código de estado: {response.status_code}")
            return None

    except requests.exceptions.RequestException as e:
        print(f"Error en la solicitud a NordVPN API: {e}")
        return None

# --- Función para calcular la diferencia de tiempo ---
def calculate_time_difference(time1, time2):
    time_format = "%Y/%m/%d %H:%M:%S"
    t1 = datetime.strptime(time1, time_format)
    t2 = datetime.strptime(time2, time_format)
    return abs((t1 - t2).total_seconds() / 3600)  # Diferencia en horas

# --- Función para determinar si el viaje es imposible ---
def is_impossible_travel(distancia, tiempo, threshold=120):
    if tiempo == 0:
        print("Error: El tiempo entre los dos eventos es cero")
        return True

    velocidad = distancia / tiempo  # Calcula la velocidad en km/h
    return velocidad > threshold

# --- Función para calcular distancia entre coordenadas ---
def approximate_distance(lat1, lon1, lat2, lon2):
    delta_lat = lat2 - lat1
    delta_lon = lon2 - lon1
    lat_media = radians((lat1 + lat2) / 2)

    return sqrt((delta_lat * 111.32) ** 2 + (delta_lon * 111.32 * cos(lat_media)) ** 2)

# --- Función principal para procesar alertas ---
def process_alarm(log):
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
        return "Error: No se encontraron dos IPs o fechas en el log"

    ip_info_1 = get_ip_info_from_nordvpn(ips[0])
    ip_info_2 = get_ip_info_from_nordvpn(ips[1])

    if not ip_info_1 or not ip_info_2:
        return "Error: No se pudo obtener información para una o ambas IPs"

    lat1, lon1 = ip_info_1['latitude'], ip_info_1['longitude']
    lat2, lon2 = ip_info_2['latitude'], ip_info_2['longitude']

    if None in (lat1, lon1, lat2, lon2):
        return "Error: Las coordenadas de una o ambas IPs son inválidas"

    distancia = approximate_distance(lat1, lon1, lat2, lon2)
    tiempo = calculate_time_difference(dates[0], dates[1])

    mensaje = f"🔍 **Análisis de Login desde 2 IPs diferentes:**\n"
    mensaje += f"- 🌍 **IP 1** ({ips[0]}): {ip_info_1['city']}, {ip_info_1['region']}, {ip_info_1['country']}\n"
    mensaje += f"- 🌍 **IP 2** ({ips[1]}): {ip_info_2['city']}, {ip_info_2['region']}, {ip_info_2['country']}\n"
    mensaje += f"- 🚀 **Distancia:** {distancia:.2f} km\n"
    mensaje += f"- ⏳ **Tiempo:** {tiempo:.2f} horas\n"

    if is_impossible_travel(distancia, tiempo):
        mensaje += "⚠️ **ALERTA:** Viaje imposible detectado."
    else:
        mensaje += "✅ Viaje posible."

    return mensaje

# --- Función para procesar VPN fuera de ARG o PY ---
def process_vpn_outside_permitted_countries(log):
    ip_regex = r"IP de origen: (\d+\.\d+\.\d+\.\d+)"
    ip_match = re.search(ip_regex, log)

    if not ip_match:
        return "Error: No se pudo encontrar la IP en el log"

    ip = ip_match.group(1)
    ip_info = get_ip_info_from_nordvpn(ip)

    if not ip_info:
        return "Error: No se pudo obtener información de la IP"

    mensaje = f"🔍 **Análisis de VPN:**\n"
    mensaje += f"- 🌍 **IP:** {ip} ({ip_info['country']} - {ip_info['country_code']})\n"
    mensaje += f"- 🏙️ **Ubicación:** {ip_info['city']}, {ip_info['region']}\n"
    mensaje += f"- 🏢 **ISP:** {ip_info['isp']} ({ip_info['asn']})\n"
    mensaje += f"- 🌐 **Dominio:** {ip_info['host_domain']}\n"
    mensaje += f"- 🔐 **VPN Detectada:** {'Sí' if ip_info['vpn_detected'] else 'No'}\n"
    mensaje += f"- 📜 **Cumple GDPR:** {'Sí' if ip_info['gdpr'] else 'No'}\n"

    return mensaje

# --- Función para procesar login fuera de ARG y PY ---
def process_login_outside_permitted_countries(log):
    return process_vpn_outside_permitted_countries(log)

if __name__ == "__main__":
    logs = [
        """Workapp - Login desde 2 IPs diferentes    Fecha/hora: 2025/02/21 11:09:10 Usuario: u994755 IP de origen: 181.121.197.192 Geolocalizacion de origen: Yaguarete Cua, Cordillera, Paraguay, 3230 Reputacion de IP (Cisco Talos): https://talosintelligence.com/reputation_center/lookup?search=181.121.197.192 ---  Fecha/hora: 2025/02/21 16:01:56 Usuario: u994755 IP de origen: 181.121.48.111 Geolocalizacion de origen: San Lorenzo, Central, Paraguay, 110221 Reputacion de IP (Cisco Talos): https://talosintelligence.com/reputation_center/lookup?search=181.121.48.111 ---""",
    ]

    for log in logs:
        resultado = process_alarm(log)
        print(resultado)
        print("---")
