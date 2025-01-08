import re

def handle_linux_login(alarma, cuerpo):
    """
    Maneja alarmas de inicio de sesión en Linux.

    Args:
        alarma (str): El tipo de alarma.
        cuerpo (str): El cuerpo del log.

    Returns:
        tuple: Observación (str) y si el texto debe estar en negrita (bool).
    """
    if alarma == "Notificacion SIEM - Login fuera de puentes":
        observacion = get_login_fuera_de_puentes_observation(cuerpo)
        is_bold = True if observacion else False
        return observacion, is_bold

    if alarma == "Notificacion SIEM - Sudo su detectado":
        observacion = get_sudo_su_observation(cuerpo)
        is_bold = True if observacion else False
        return observacion, is_bold
    
    if alarma == "Notificacion SIEM - Login sin usuario OPR o PS en Linux":
        observacion = get_login_sin_usuario_opr_o_ps_observation(cuerpo)
        is_bold = True if observacion else False
        return observacion, is_bold

    return "Caso no clasificado - Añadir manualmente", False


def get_login_fuera_de_puentes_observation(cuerpo):
    """
    Extrae información de los logs "Login fuera de puentes".

    Args:
        cuerpo (str): El cuerpo del log.

    Returns:
        str: Observación extraída o un mensaje de error.
    """
    # Ajustamos el patrón para capturar el host de destino correctamente
    pattern = r'Login fuera de puentes.*?Usuario de origen: (.*?) IP de Origen: (\d+\.\d+\.\d+\.\d+).*?Host de Destino: (.*?) IPAM:'
    match = re.search(pattern, cuerpo, re.DOTALL)

    if match:
        user = match.group(1).strip()
        ip_origen = match.group(2).strip()
        host_destino = match.group(3).strip()
        return f"Usuario: {user}, IP de Origen: {ip_origen}, Host de Destino: {host_destino}"

    return "No se pudo extraer información del login fuera de puentes"


def get_sudo_su_observation(cuerpo):
    """
    Extrae información de los logs "Sudo su detectado".

    Args:
        cuerpo (str): El cuerpo del log.

    Returns:
        str: Observación extraída o un mensaje de error.
    """
    pattern = r'usuario: (.*?) Cambio a: root Host: (.*?) Ip: (\d+\.\d+\.\d+\.\d+)'
    match = re.search(pattern, cuerpo, re.DOTALL)

    if match:
        user = match.group(1).strip()
        host = match.group(2).strip()
        ip = match.group(3).strip()
        return f"Usuario: {user}, Host: {host}, IP: {ip}"

    return "No se pudo extraer información del sudo su"

def get_login_sin_usuario_opr_o_ps_observation(cuerpo):
    """
    Extrae información de los logs "Login sin usuario OPR o PS en Linux".

    Args:
        cuerpo (str): El cuerpo del log.

    Returns:
        str: Observación extraída o un mensaje de error.
    """
    # Patrón para extraer Usuario, Equipo y IP
    pattern = r'Se ha detectado un login en los sistemas linux.*?Usuario: (.*?) Equipo: (.*?) Ip: (\d+\.\d+\.\d+\.\d+)'
    match = re.search(pattern, cuerpo, re.DOTALL)

    if match:
        user = match.group(1).strip()
        equipo = match.group(2).strip()
        ip = match.group(3).strip()
        return f"Usuario: {user}, Equipo: {equipo}, IP: {ip}"

    return "No se pudo extraer información del login sin usuario OPR o PS en Linux"
