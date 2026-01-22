import csv

def contar_validos(ruta_csv):
    contador_true = 0
    contador_false = 0
    contador_error = 0
    contador_invalid = 0
    with open(ruta_csv, mode='r', newline='', encoding='cp1252') as archivo:
        lector = csv.DictReader(archivo)
        for fila in lector:
            valid_value = fila["Secure"].strip().lower()

            if valid_value == "true":
                contador_true += 1
            elif valid_value == "false":
                contador_false += 1
                """elif valid_value == "error": ## "Invalid (Kind, Version)"
                    contador_error += 1
                elif 'invalid' in valid_value:
                    if 'kind' in valid_value and 'version' in valid_value:
                        contador_invalid += 1"""
    return contador_true, contador_false #, contador_error, contador_invalid
# Ejemplo de uso:
suma_total_files = 0
ruta_archivo = '../evaluation/validation_results_valid_jsons03.csv'  # Cambia esto por el nombre de tu archivo config_validation_results03_3_json10_FirstConfig
cantidad_true, contador_false= contar_validos(ruta_archivo) ## , contador_error, contador_invalid 
suma_total_files = cantidad_true + contador_false #+ contador_error 
print(f"Cantidad de filas con valid=True: {cantidad_true}")
print(f"Cantidad de filas con valid=False: {contador_false}")
#print(f"Cantidad de filas con valid=Error: {contador_error}")
print(f"Cantidad archivos en total: {suma_total_files}")
#print(f"Cantidad de filas con Valid=Invalid...: {contador_invalid}")
