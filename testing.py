import re
import sys



def get_windows_login_observation(body):
    # Patrones para extraer usuario, IP del equipo (destino) y hostname
    patterns = [
        # Patrón para logs en inglés
        r'User: (.*?)\s*Session ID:.*?Destination Network Address: (\d+\.\d+\.\d+\.\d+).*?(\w+[-_]\w+)',
        
        # Patrón para logs en español
        r'Usuario: (.*?)\s*Identificador de sesi.n:.*?Direcci.n de red de destino: (\d+\.\d+\.\d+\.\d+).*?(\w+[-_]\w+)'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, body, re.DOTALL | re.UNICODE)
        if match:
            original_user = match.group(1).strip()  # Usuario original
            dest_ip = match.group(2).strip()  # IP de destino
            
            # Extraer hostname si está disponible, de lo contrario usar IP de destino
            try:
                hostname = match.group(3).strip()
            except:
                hostname = dest_ip

            # Limpiar usuario solo para mostrar, sin modificar el log original
            user = original_user.split('\\')[-1].split('@')[-1]

            # Formato de salida requerido
            return f"Usuario: {user} Host: {hostname} Ip: {dest_ip}"
    
    # Si no coincide con ninguno de los patrones
    return "No se pudo extraer información del inicio de sesión"

# Ejemplo de uso
body = """
Alarm: Windows - Login  Se ha detectado un inicio de sesión en el equipo  10.150.34.43||Application||224723||Microsoft-Windows-Winlogon||22||100||1733921507||3||asusisv-xd01.personal.com.py||||||1||Servicios de Escritorio remoto: notificaci¾n de inicio de shell recibida:  Usuario: TPPY\u991555_admin Identificador de sesi¾n: 97 Direcci¾n de red de destino: 10.150.100.12||  Summary: Field match alarm triggered on ASUSISV-XD01
"""

print(get_windows_login_observation(body))