"""
Este script se encarga de hacer consultas en un servicio usando requests para obtener información del usuario en el Active Directory.
"""
import requests
import json
import os
import re
from datetime import datetime
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

# Configuración de la URL
BASE_URL = os.getenv('URL_LINK')
print(f"URL base utilizada: {BASE_URL}")
# Regex para extraer posición y departamento hasta un "/" o "_"
POSITION_DEPARTMENT_REGEX = r"^(?P<position>.+?) - (?P<department>.+?)(?:[/_].*)?$"

# Función para hacer la solicitud y obtener información
def fetch_user_info(user_id, info_type):
    """
    Hace una solicitud al servicio y obtiene la información especificada para el usuario.
    
    Args:
        user_id (str): ID del usuario.
        info_type (str): Tipo de información a obtener (e.g., 'title', 'mobile').

    Returns:
        str: Valor de la información obtenida (o None si falla).
    """
    timestamp = datetime.now().timestamp()
    url = f"{BASE_URL}?user={user_id}&info={info_type}"
    try:
        response = requests.get(url, verify=False, headers={"Cache-Control": "no-cache"})  # Desactivar cach
        response.raise_for_status()  # Lanza excepción si el código no es 200
        
        response.encoding = 'utf-8'
        data = response.json()

        # Log detallado para depuración
        print("Respuesta completa del servidor:", json.dumps(data, indent=4))

        if data.get("sucess") == "200":
            return data.get("info")
        else:
            print(f"Error en la solicitud: {data}")
    except requests.RequestException as e:
        print(f"Error al realizar la solicitud: {e}")
    return None

# Función principal para obtener información y mostrarla en una tabla
def get_user_details(user_id):
    """
    Obtiene los detalles del usuario (puesto, departamento, y móvil) y los imprime en formato de tabla.

    Args:
        user_id (str): ID del usuario.
    """
    # Obtener información del título (puesto y departamento)
    title_info = fetch_user_info(user_id, "title")
    position, department = None, None
    if title_info:
        print(f"Title Info: {title_info}")  # Log para depuración
        match = re.match(POSITION_DEPARTMENT_REGEX, title_info)
        if match:
            position = match.group("position")
            department = match.group("department")
        else:
            print("No se pudo parsear el título correctamente.")

    # Obtener información del móvil
    mobile = fetch_user_info(user_id, "mobile")

    # Imprimir en formato de tabla
    print(f"{'Usuario':<15}{'Puesto':<30}{'Departamento':<80}{'Móvil':<50}")
    print("-" * 180)
    print(f"{user_id:<15}{position or 'N/A':<30}{department or 'N/A':<80}{mobile or 'N/A':<50}")

# Ejecutar el script
if __name__ == "__main__":
    # Reemplazar con un usuario real para pruebas
    user_id = "deus"  
    get_user_details(user_id)
