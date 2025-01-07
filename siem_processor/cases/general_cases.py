from siem_processor.utils.normalization import normalize_body

def handle_general_cases(alarma, cuerpo, df_bd):
    """
    Maneja casos generales que no son específicos de Windows o Linux.
    
    Args:
        alarma (str): El tipo de alarma.
        cuerpo (str): El cuerpo del mensaje de la alarma.
        df_bd (DataFrame): Base de datos normalizada que contiene logs históricos.

    Returns:
        tuple: Observación (str) y si el texto debe estar en negrita (bool).
    """
    # Normalizar el cuerpo del mensaje
    cuerpo_normalizado = normalize_body(cuerpo)

    # Buscar coincidencias en la base de datos normalizada
    matches = df_bd[df_bd['Cuerpo Normalizado'] == cuerpo_normalizado]

    if len(matches) >= 2:
        # Si hay dos o más coincidencias
        observacion = matches.iloc[0]['Observación']
        is_bold = True
    elif len(matches) == 1:
        # Si hay una coincidencia exacta
        observacion = matches.iloc[0]['Observación']
        is_bold = False
    else:
        # Sin coincidencias
        observacion = "Caso por defecto - Añadir manualmente"
        is_bold = False

    return observacion, is_bold
