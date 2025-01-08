"""
normalizedb.py: Script for nrormalizing 
"""
import pandas as pd
import re

def normalize_body(body):
    patterns = [
        (r'^.*?(?=Usuario de origen)', 'Usuario de origen'),  # Patrón 1
        (r'^.*?(?=Usuario:)', 'Usuario:'),  # Patrón 2
        (r'^.*?(?=Se han detectado)', 'Se han detectado'),  # Patrón 3
        (r'Alarm: Windows - Login.*?(\d+\.\d+\.\d+\.\d+).*?\|\|3\|\|(.*?\.py).*?User: (.*?) Session ID:', 'Alarm: Windows - Login')  # Patrón 4 mejorado
    ]
    
    for pattern, start_phrase in patterns:
        if start_phrase in body:
            if start_phrase == 'Alarm: Windows - Login':
                # Manejo especial para el patrón de alarma de Windows
                match = re.search(pattern, body, re.DOTALL)
                if match:
                    ip = match.group(1).strip()
                    host = match.group(2).strip()
                    user = match.group(3).strip()
                    return f"Alarm: Windows - Login  Se ha detectado un inicio de sesión en el equipo  {ip} Host: {host} User: {user}"
            else:
                normalized = re.sub(pattern, '', body, flags=re.DOTALL)
                return normalized.strip()
    
    # Si ningún patrón coincide, devolver el cuerpo original
    return body.strip()

def normalize_database(input_file, output_file):
    # Leer el archivo Excel
    df = pd.read_excel(input_file, sheet_name='BD_Logs')
    
    # Aplicar la normalización a la columna 'Cuerpo'
    df['Cuerpo'] = df['Cuerpo'].apply(normalize_body)
    
    # Guardar el resultado en un nuevo archivo Excel
    with pd.ExcelWriter(output_file) as writer:
        df.to_excel(writer, sheet_name='BD_Logs_Normalized', index=False)
    
    print(f"Base de datos normalizada guardada en {output_file}")

# Uso del script
input_file = "BD_Logs.xlsx"
output_file = "BD_Logs_Normalized.xlsx"
normalize_database(input_file, output_file)