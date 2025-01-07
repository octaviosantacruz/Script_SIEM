import re

def handle_linux_cases(alarma, cuerpo, df_bd):
    if "Login sin usuario" in alarma:
        observacion = get_linux_login_observation(cuerpo)
    elif "Sudo su detectado" in alarma:
        observacion = get_sudo_su_observation(cuerpo)
    else:
        observacion = "Unhandled Linux case"
    is_bold = True if observacion else False
    return observacion, is_bold

def get_linux_login_observation(body):
    pattern = r'Usuario: (.*?) Equipo: (.*?) Ip: (\d+\.\d+\.\d+\.\d+)'
    match = re.search(pattern, body, re.DOTALL)
    if match:
        user = match.group(1).strip()
        equipo = match.group(2).strip()
        ip = match.group(3).strip()
        return f"Usuario: {user} Equipo: {equipo} IP: {ip}"
    return "No se pudo extraer información del login en Linux"

def get_sudo_su_observation(body):
    pattern = r'usuario: (.*?) Cambio a: root Host: (.*?) Ip: (\d+\.\d+\.\d+\.\d+)'
    match = re.search(pattern, body, re.DOTALL)
    if match:
        user = match.group(1).strip()
        host = match.group(2).strip()
        ip = match.group(3).strip()
        return f"Usuario: {user} Host: {host} Ip: {ip}"
    return "No se pudo extraer información del sudo su"
