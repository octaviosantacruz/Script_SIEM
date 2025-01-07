from siem_processor.utils.normalization import normalize_body

def handle_general_case(alarma, cuerpo):
    """
    Maneja casos generales basados en el tipo de alarma.

    Args:
        alarma (str): El tipo de alarma.
        cuerpo (str): El cuerpo del log.

    Returns:
        tuple: Observación (str) y si el texto debe estar en negrita (bool).
    """
    observacion = "Caso no clasificado - Añadir manualmente"
    is_bold = False

    # Implementar lógica específica para alarmas generales si es necesario
    return observacion, is_bold
