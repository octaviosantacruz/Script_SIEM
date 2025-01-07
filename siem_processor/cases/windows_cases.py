"""
windows_cases.py | The script contains a function to handle Windows-specific cases in SIEM alarms.
"""
import re

def handle_windows_cases(alarma, cuerpo, df_bd):
    if "Login" in alarma:
        observacion = get_windows_login_observation(cuerpo)
        is_bold = bool(observacion)
    else:
        observacion = "Unhandled Windows case"
        is_bold = False
    return observacion, is_bold

def get_windows_login_observation(body):
    patterns = [
        r'Alarm: Windows - Login.*?(\d+\.\d+\.\d+\.\d+).*?User: (.*?) Session ID:.*?Source Network Address: (\d+\.\d+\.\d+\.\d+)',
        r'Alarm: Windows - Login.*?(\d+\.\d+\.\d+\.\d+).*?Usuario: (.*?) Identificador de sesión:.*?Dirección de red de origen: (\d+\.\d+\.\d+\.\d+)',
    ]
    for pattern in patterns:
        match = re.search(pattern, body, re.DOTALL)
        if match:
            ip = match.group(1).strip()
            user = match.group(2).strip()
            source_ip = match.group(3).strip()
            return f"Equipo: {ip}, User: {user}, Dirección de origen: {source_ip}"
    return "No se pudo extraer información del inicio de sesión"
