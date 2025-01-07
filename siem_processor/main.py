import argparse
from openpyxl import load_workbook
from datetime import datetime
from siem_processor.utils.normalization import normalize_database
from siem_processor.utils.styles import apply_styles, is_critical_alarm
from siem_processor.cases.windows_cases import handle_windows_cases
from siem_processor.cases.linux_cases import handle_linux_cases
from siem_processor.cases.general_cases import handle_general_cases
import pandas as pd

def process_alarms(input_file, bd_file):
    # Normalize the database
    df_bd = normalize_database(bd_file)

    # Read the input Excel file
    df_input = pd.read_excel(input_file, sheet_name='7-11')
    workbook = load_workbook(input_file)
    sheet_input = workbook['7-11']

    for index, row in df_input.iterrows():
        alarma = row['Alarma']
        cuerpo = row['Cuerpo']

        # Handle cases based on the type of alarm
        if "Windows" in alarma:
            observacion, is_bold = handle_windows_cases(alarma, cuerpo, df_bd)
        elif "Linux" in alarma:
            observacion, is_bold = handle_linux_cases(alarma, cuerpo, df_bd)
        else:
            observacion, is_bold = handle_general_cases(alarma, cuerpo, df_bd)

        # Update observations in the Excel sheet
        sheet_input.cell(row=index + 2, column=2, value=observacion)
        sheet_input.cell(row=index + 2, column=3, value=cuerpo)

        # Apply styles for critical and bold alarms
        is_critical = is_critical_alarm(alarma)
        apply_styles(sheet_input, index, is_critical, is_bold)

    # Save the processed file
    today = datetime.now().strftime("%d-%m")
    output_file = f"{today}_SIEM_DIA.xlsx"
    workbook.save(output_file)
    print(f"Processing complete. Result saved in {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process SIEM alarms.")
    parser.add_argument("input_file", help="Path to the input Excel file (e.g., '7-11.xlsx').")
    parser.add_argument("bd_file", help="Path to the database Excel file (e.g., 'BD_Logs.xlsx').")
    args = parser.parse_args()

    process_alarms(args.input_file, args.bd_file)