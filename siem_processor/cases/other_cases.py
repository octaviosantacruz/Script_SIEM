# Handle ABM Alarmas and Salto Laterales de DBA
import re
from siem_processor.utils.styles import apply_styles as styles
def handle_abm_cases(alarma, cuerpo):
    """
    Maneja los casos de ABM (Usuarios y Grupos de Active Directory).

    Args:
        alarma (str): El tipo de alarma.
        cuerpo (str): El cuerpo del log.

    Returns:
        tuple: Observación (str) y si el texto debe estar en negrita (bool).
    """
    if alarma == "Notificacion SIEM - ABM-Grupo-AD-Agregado":
        observacion = get_abm_grupo_ad_agregado_observation(cuerpo)
        return observacion, True

    if alarma == "Notificacion SIEM - ABM-Usuario-AD-Creado":
        observacion = get_abm_usuario_ad_creado_observation(cuerpo)
        return observacion, True

    if alarma == "Notificacion SIEM - ABM-Restablecimiento-Credenciales":
        observacion = get_abm_restablecimiento_credenciales_observation(cuerpo)
        return observacion, True
    
    if alarma == "Notificacion SIEM - Notificacion SIEM - Pase a produccion detectado":
        observacion = get_pase_a_produccion_observation(cuerpo)
        return observacion, True

    return "Caso ABM no clasificado - Añadir manualmente", False


def handle_salto_lateral_dba(alarma, cuerpo):
    """
    Maneja los casos de saltos laterales para usuarios DBA.

    Args:
        alarma (str): El tipo de alarma.
        cuerpo (str): El cuerpo del log.

    Returns:
        tuple: Observación (str) y si el texto debe estar en negrita (bool).
    """
    if alarma in [
        "Notificacion SIEM - Posible salto lateral 12+",
        "Notificacion SIEM - Posible salto lateral 6+"
    ]:
        observacion = get_salto_lateral_observation(cuerpo)
        is_bold = "Salto Lateral de Usuario DBA" in observacion
        return observacion, is_bold

    return "Caso de salto lateral no clasificado - Añadir manualmente", False


def handle_pases_produccion(alarma, cuerpo):
    """
    Maneja los casos relacionados con pases a producción.

    Args:
        alarma (str): El tipo de alarma.
        cuerpo (str): El cuerpo del log.

    Returns:
        tuple: Observación (str) y si el texto debe estar en negrita (bool).
    """
    if alarma == "Notificacion SIEM - Notificacion SIEM - Pase a produccion detectado":
        observacion = get_pase_a_produccion_observation(cuerpo)
        return observacion, True

    return "Caso de pase a producción no clasificado - Añadir manualmente", False


def get_abm_grupo_ad_agregado_observation(cuerpo):
    """
    Extrae información de los logs "ABM-Grupo-AD-Agregado".

    Args:
        cuerpo (str): El cuerpo del log.

    Returns:
        str: Observación extraída.
    """
    pattern = r'Usuario de origen: (.*?) Usuario de destino: (.*?) Grupo \(si corresponde\): (.*?) IP de origen: (\d+\.\d+\.\d+\.\d+)'
    match = re.search(pattern, cuerpo, re.DOTALL)

    if match:
        user_origen = match.group(1).strip()
        user_destino = match.group(2).strip()
        grupo = match.group(3).strip() or "No especificado"
        ip_origen = match.group(4).strip()
        return f"Usuario de origen: {user_origen}, Usuario de destino: {user_destino}, Grupo: {grupo}, IP de origen: {ip_origen}"

    return "No se pudo extraer información del log ABM-Grupo-AD-Agregado"


def get_abm_usuario_ad_creado_observation(cuerpo):
    """
    Extrae información de los logs "ABM-Usuario-AD-Creado".

    Args:
        cuerpo (str): El cuerpo del log.

    Returns:
        str: Observación extraída.
    """
    pattern = r'Usuario de origen: (.*?) Usuario de destino: (.*?) IP de origen: (\d+\.\d+\.\d+\.\d+)'
    match = re.search(pattern, cuerpo, re.DOTALL)

    if match:
        user_origen = match.group(1).strip()
        user_destino = match.group(2).strip()
        ip_origen = match.group(3).strip()
        return f"Usuario de origen: {user_origen}, Usuario de destino: {user_destino}, IP de origen: {ip_origen}"

    return "No se pudo extraer información del log ABM-Usuario-AD-Creado"


def get_abm_restablecimiento_credenciales_observation(cuerpo):
    """
    Extrae información de los logs "ABM-Restablecimiento-Credenciales".

    Args:
        cuerpo (str): El cuerpo del log.

    Returns:
        str: Observación extraída.
    """
    pattern = r'Usuario de origen: (.*?) Usuario de destino: (.*?) Grupo \(si corresponde\): (.*?) IP de origen: (\d+\.\d+\.\d+\.\d+)'
    match = re.search(pattern, cuerpo, re.DOTALL)

    if match:
        user_origen = match.group(1).strip()
        user_destino = match.group(2).strip()
        grupo = match.group(3).strip() or "No especificado"
        ip_origen = match.group(4).strip()
        return f"Usuario de origen: {user_origen}, Usuario de destino: {user_destino}, Grupo: {grupo}, IP de origen: {ip_origen}"

    return "No se pudo extraer información del log ABM-Restablecimiento-Credenciales"


def get_pase_a_produccion_observation(cuerpo):
    """
    Extrae información de los logs "Pase a Producción".

    Args:
        cuerpo (str): El cuerpo del log.

    Returns:
        str: Observación extraída.
    """
    pattern = r'Host: (.*?) Proceso: (.*?) Usuario: (.*?) Comando: (.*?)'
    match = re.search(pattern, cuerpo, re.DOTALL)

    if match:
        host = match.group(1).strip()
        proceso = match.group(2).strip()
        usuario = match.group(3).strip()
        comando = match.group(4).strip()
        return f"Host: {host}, Proceso: {proceso}, Usuario: {usuario}, Comando: {comando}"

    return "No se pudo extraer información del log Pase a Producción"


def get_salto_lateral_observation(cuerpo):
    """
    Extrae información de los logs de "Salto Lateral" y detecta usuarios DBA específicos.

    Args:
        cuerpo (str): El cuerpo del log.

    Returns:
        str: Observación extraída.
    """
    # Patrón para detectar el usuario de origen
    pattern = r'Usuario de origen: (liuzzid_dbaadm|villajos_dbaadm)'
    match = re.search(pattern, cuerpo, re.DOTALL)

    if match:
        usuario = match.group(1).strip()
        return f"Salto Lateral de Usuario DBA: {usuario}"
    else:
        not_match = "No se detectó un usuario DBA en el log de salto lateral"
        not_match = styles(not_match, bold=True)

    return not_match

