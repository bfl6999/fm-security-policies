import csv
import os
import shutil

# Ruta del CSV
csv_path = "../../../fm-json-kubernetes/evaluation/k8sJsontoUvl_results_final.csv"

# Carpeta donde están los JSON originales
source_folder = "../../../scriptJsonToUvl/generateConfigs/outputs_json_mappeds11"
# c:\Users\CAOSD\projects\scriptJsonToUvl\generateConfigs
# Carpeta donde guardarás solo los JSON válidos
destination_folder = "../../../valid_jsons"

# Crear carpeta destino si no existe
os.makedirs(destination_folder, exist_ok=True)

valid_filenames = []

# Leer el csv (sin pandas para mayor velocidad en archivos muy grandes)
with open(csv_path, newline='', encoding='utf-8') as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
      if row["Valid"].strip() == "True":    # filtrar solo True
          valid_filenames.append(row["Filename"].strip())

print(f"Total archivos marcados como True: {len(valid_filenames)}")

copiados = 0

# Recorrer y copiar los archivos válidos
for fname in valid_filenames:
  src = os.path.join(source_folder, fname)
  dst = os.path.join(destination_folder, fname)

  if os.path.exists(src):
      shutil.copy2(src, dst)   # copia manteniendo metadata
      copiados += 1
  else:
      print(f"⚠ Archivo no encontrado: {src}")

print(f"Archivos copiados correctamente: {copiados}")
print("Proceso completado.")
