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
    if alarma == "Notificacion SIEM - Se ha detectado un inicio de sesión":
        observacion = get_windows_login_observation(cuerpo)
        is_bold = True if observacion else False
        return observacion, is_bold

    return "Caso no clasificado - Añadir manualmente", False


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
