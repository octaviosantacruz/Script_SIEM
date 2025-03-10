import re

def handle_windows_login(alarma, cuerpo):
    """
    Maneja alarmas de inicio de sesión en Windows.

    Args:
        alarma (str): El tipo de alarma.
        cuerpo (str): El cuerpo del log.

    Returns:
        tuple: Observación (str) y si el texto debe estar en negrita (bool).
    """
    observacion = "Caso no clasificado - Añadir manualmente"  # Valor por defecto
    is_bold = False

    if alarma == "Notificacion SIEM - Se ha detectado un inicio de sesión":
        observacion = get_windows_login_observation(cuerpo)
        if observacion == "No se pudo extraer información del inicio de sesión":
            observacion = get_variant_windows_login_observation(cuerpo)
        is_bold = True if observacion != "No se pudo extraer información del inicio de sesión variante" else False

    elif alarma == "Notificacion SIEM - Se ha detectado un inicio de sesión en los DC":
        observacion = get_windows_dc_login_observation(cuerpo)
        is_bold = True if observacion != "No se pudo extraer información del inicio de sesión en los DC" else False

    elif alarma == "Notificacion SIEM - Se ha detectado un inicio de sesión sin opr o admin":
        observacion = get_windows_user_login_observation(cuerpo)
        is_bold = True if observacion != "No se pudo extraer información del inicio de sesión sin opr o admin" else False

    return observacion, is_bold


def get_variant_windows_login_observation(cuerpo):
    """
    Extrae la información de los logs de Windows Login en un formato variante.

    Args:
        cuerpo (str): El cuerpo del log.

    Returns:
        str: Observación extraída o un mensaje de error.
    """
    pattern = r'Desde IP:\s*(?P<ip_origen>(?:\d+\.\d+\.\d+\.\d+|::)?)\s*Hacia Ip:\s*(?P<ip_destino>\d+\.\d+\.\d+\.\d+)\s*Usuario:\s*(?P<user>\S+)\s*Host:\s*(?P<host>\S+)'

    match = re.search(pattern, cuerpo, re.DOTALL | re.IGNORECASE)
    if match:
        ip_origen = match.group("ip_origen").strip()
        ip_destino = match.group("ip_destino").strip()
        user = match.group("user").strip()
        host = match.group("host").strip()

        # Si la IP de origen es "::" o está vacía, la omitimos
        if ip_origen == "::" or not ip_origen:
            return f"Login Citrix -- IP Origen: {ip_destino}, Usuario: {user}, Host: {host}"
        else:
            return f"Login Citrix -- IP Origen: {ip_origen}, IP Destino: {ip_destino}, Usuario: {user}, Host: {host}"

    return "No se pudo extraer información del inicio de sesión variante"


def get_windows_login_observation(cuerpo):
    """
    Extrae la información de los logs de Windows Login.

    Args:
        cuerpo (str): El cuerpo del log.

    Returns:
        str: Observación extraída o un mensaje de error.
    """
    patterns = [
        r'Alarm: Windows - Login.*?(\d+\.\d+\.\d+\.\d+).*?User: (.*?) Session ID:.*?Source Network Address: (\d+\.\d+\.\d+\.\d+)',
        r'Alarm: Windows - Login.*?(\d+\.\d+\.\d+\.\d+).*?Usuario: (.*?) Identificador de sesión:.*?Dirección de red de origen: (\d+\.\d+\.\d+\.\d+)',
    ]

    for pattern in patterns:
        match = re.search(pattern, cuerpo, re.DOTALL)
        if match:
            ip = match.group(1).strip()
            user = match.group(2).strip()
            source_ip = match.group(3).strip()
            return f"Equipo: {ip}, User: {user}, Dirección de origen: {source_ip}"

    return "No se pudo extraer información del inicio de sesión"

def get_windows_dc_login_observation(cuerpo):
    """
    Extrae información de los logs "Se ha detectado un inicio de sesión en los DC".

    Args:
        cuerpo (str): El cuerpo del log.

    Returns:
        str: Observación extraída o un mensaje de error.
    """
    pattern = r'Desde IP: (\d+\.\d+\.\d+\.\d+) Hacia Ip: (\d+\.\d+\.\d+\.\d+) Usuario: (.*?) Host: (.*?)$'
    match = re.search(pattern, cuerpo, re.DOTALL)

    if match:
        ip_origen = match.group(1).strip()
        ip_destino = match.group(2).strip()
        user = match.group(3).strip()
        host = match.group(4).strip()
        return f"Inicio de sesión en DC - IP Origen: {ip_origen}, IP Destino: {ip_destino}, Usuario: {user}, Host: {host}"

    return "No se pudo extraer información del inicio de sesión en los DC"


def get_windows_user_login_observation(cuerpo):
    """
    Extrae información de los logs "Se ha detectado un inicio de sesión sin opr o admin".

    Args:
        cuerpo (str): El cuerpo del log.

    Returns:
        str: Observación extraída o un mensaje de error.
    """
    pattern = r'Desde IP: (\d+\.\d+\.\d+\.\d+) Hacia Ip: (\d+\.\d+\.\d+\.\d+) Usuario: (.*?) Host: (.*?)$'
    match = re.search(pattern, cuerpo, re.DOTALL)

    if match:
        ip_origen = match.group(1).strip()
        ip_destino = match.group(2).strip()
        user = match.group(3).strip()
        host = match.group(4).strip()
        return f"Inicio de sesión sin opr/admin - IP Origen: {ip_origen}, IP Destino: {ip_destino}, Usuario: {user}, Host: {host}"

    return "No se pudo extraer información del inicio de sesión sin opr o admin"
