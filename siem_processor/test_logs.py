"""
testing.py | Script para probar y verificar logs individuales de alarmas SIEM.
"""

import argparse
from siem_processor.cases.windows_login import handle_windows_login
from siem_processor.cases.linux_login import handle_linux_login
from siem_processor.cases.other_cases import (
    handle_abm_cases,
    handle_salto_lateral_dba,
    handle_pases_produccion,
    handle_cambio_gpo
)
from siem_processor.modules.IP2Location import process_alarm

# --- Función para probar logs individuales ---
def test_single_log(alarma, cuerpo):
    """
    Prueba un log individual y devuelve el resultado procesado.

    Args:
        alarma (str): Tipo de alarma.
        cuerpo (str): Cuerpo del log.

    Returns:
        str: Observación procesada.
    """
    print(f"\nProcesando log individual: Alarma='{alarma}', Cuerpo='{cuerpo}'")
    # Procesar según el tipo de alarma
    if alarma in [
        "Notificacion SIEM - Se ha detectado un inicio de sesión",
        "Notificacion SIEM - Se ha detectado un inicio de sesión en los DC",
        "Notificacion SIEM - Se ha detectado un inicio de sesión sin opr o admin"
    ]:
        print("Procesando inicio de sesión en Windows...")
        observacion, _ = handle_windows_login(alarma, cuerpo)
        return observacion

    elif alarma in [
        "Notificacion SIEM - Login fuera de puentes",
        "Notificacion SIEM - Notificacion SIEM - Login sin usuario OPR o PS en Linux",
        "Notificacion SIEM - Sudo su detectado",
        "Notificacion SIEM - Notificacion - SIEM cambios audit"
    ]:
        observacion, _ = handle_linux_login(alarma, cuerpo)
        return observacion

    elif alarma in [
        "Notificacion SIEM - ABM-Usuario-AD-Creado",
        "Notificacion SIEM - ABM-Restablecimiento-Credenciales",
        "Notificacion SIEM - ABM-Grupo-AD-Agregado",
        "Notificacion SIEM - ABM-Grupo-AD-Removido",
    ]:
        observacion, _ = handle_abm_cases(alarma, cuerpo)
        return observacion

    elif alarma in [
        "Notificacion SIEM - Posible salto lateral 12+",
        "Notificacion SIEM - Posible salto lateral 6+"
    ]:
        observacion, _ = handle_salto_lateral_dba(alarma, cuerpo)
        return observacion

    elif alarma in [
        "Notificacion SIEM - VPN - Login desde 2 IPs diferentes",
        "Notificacion SIEM - Workapp - Login desde 2 IPs diferentes",
        "Notificacion SIEM - Workapp - Login fuera de ARG y PY",
        "Notificacion SIEM - VPN fuera de ARG o PY."
    ]:
        observacion = process_alarm(cuerpo)
        return observacion

    elif alarma in [
        "Notificacion SIEM - Notificacion SIEM - Pase a produccion detectado"
    ]:
        observacion, _ = handle_pases_produccion(alarma, cuerpo)
        return observacion
    elif alarma in [
        "Notificacion SIEM - SIEM - Cambio de politicas GPO"
    ]:
        observacion, _ = handle_cambio_gpo(alarma, cuerpo)
        return observacion

    return "Caso no clasificado - Verificar manualmente"

# --- Punto de entrada principal ---
if __name__ == "__main__":
    # Variables de ejemplo para pruebas rápidas
    test_alarma = """
    Notificacion SIEM - SIEM - Cambio de politicas GPO
    """.strip()

    test_cuerpo = """
    Alarm: DCS-cambio-en-politica  Se ha detectado un cambio de las políticas GPO  Usuario: u991555_admin  DC: ASUSISV-MSDC2  Hora: 2025/01/16 16:47:02
    """.strip()


    parser = argparse.ArgumentParser(description="Probar y verificar logs individuales de alarmas SIEM.")
    parser.add_argument(
        "--alarma", default=test_alarma,
        help="El tipo de alarma (por ejemplo, 'Notificacion SIEM - Se ha detectado un inicio de sesión')."
    )
    parser.add_argument(
        "--cuerpo", default=test_cuerpo,
        help="El cuerpo del log a procesar."
    )
    args = parser.parse_args()
    print(f"Antes de procesar: Alarma='{args.alarma}', Cuerpo='{args.cuerpo}'")
    # Procesar el log individual
    resultado = test_single_log(args.alarma, args.cuerpo)
    print("\nResultado del procesamiento:")
    print(resultado)
