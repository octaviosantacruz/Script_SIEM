"""
normalization.py| The script contains a function to normalize the database of SIEM alarms.
"""
import pandas as pd
import re

def normalize_database(input_file):
    df = pd.read_excel(input_file, sheet_name='BD_Logs')
    df['Cuerpo Normalizado'] = df['Cuerpo'].apply(normalize_body)
    return df

def normalize_body(body):
    patterns = [
        (r'^.*?(?=Usuario de origen)', 'Usuario de origen'),
        (r'^.*?(?=Usuario:)', 'Usuario:'),
        (r'^.*?(?=Se han detectado)', 'Se han detectado'),
    ]
    for pattern, start_phrase in patterns:
        if start_phrase in body:
            normalized = re.sub(pattern, '', body, flags=re.DOTALL)
            return normalized.strip()
    return body.strip()
