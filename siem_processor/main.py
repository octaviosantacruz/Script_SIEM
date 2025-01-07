from siem_processor.cases.windows_login import handle_windows_login
from siem_processor.cases.linux_login import handle_linux_login
from siem_processor.cases.general_cases import handle_general_case

def process_alarm(alarma, cuerpo):
    """
    Procesa una alarma específica en función de su tipo.

    Args:
        alarma (str): El tipo de alarma.
        cuerpo (str): El cuerpo del log.

    Returns:
        tuple: Observación (str) y si el texto debe estar en negrita (bool).
    """
    # Casos específicos de Windows
    if "Windows" in alarma:
        return handle_windows_login(alarma, cuerpo)

    # Casos específicos de Linux
    if "Linux" in alarma or "puentes" in alarma or "sudo su" in alarma:
        return handle_linux_login(alarma, cuerpo)

    # Casos generales
    return handle_general_case(alarma, cuerpo)
