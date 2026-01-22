import os
import shutil
import csv
import re
import sys

# --- IMPORTACIÓN DE TU TRADUCTOR ---
# Asegúrate de que python encuentre el archivo extract_kyverno_checks.py
sys.path.append(os.path.abspath("../")) 
from tools_extraction.kyverno.extract_kyverno_checks import extract_constraints_from_policy

# --- CONFIGURACIÓN ---
REPO_PATH = r"C:\Users\CAOSD\projects\policies"  # Ruta absoluta a las políticas
DEST_DIR = "../resources/dataset_final_validated"
OUTPUT_CSV = "reporte_validacion_semantica.csv"
VALID_FEATURES_CSV = "../resources/mapping_csv/kubernetes_mapping_properties_features.csv" # Tu CSV maestro

# --- CARGA DEL MODELO DE FEATURES (Tu código) ---
def load_feature_dict_polaris(csv_file):
    """
    Carga todas las features válidas del modelo en un Set para búsqueda rápida O(1).
    """
    valid_features = set()
    print(f"Cargando modelo de features desde: {csv_file}")
    try:
        with open(csv_file, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                # Asumimos que la columna se llama 'Feature' como indicaste
                if "Feature" in row:
                    valid_features.add(row["Feature"].strip())
    except Exception as e:
        print(f"Error cargando CSV de features: {e}")
        exit()
        
    print(f"Modelo cargado: {len(valid_features)} features válidas.")
    return valid_features

# --- UTILIDADES DE VALIDACIÓN ---
def extraer_feature_limpia(expr):
    """
    De una expresión UVL compleja, extrae solo el nombre de la feature.
    Ejemplo: "(Pod.io_k8s_..._hostIPC == true)" -> "io_k8s_..._hostIPC"
    """
    # 1. Limpiar paréntesis y negaciones iniciales
    clean = expr.replace("(", "").replace(")", "").strip()
    if clean.startswith("!"):
        clean = clean[1:].strip()
    
    # 2. Separar por el operador de comparación o lógico
    # Cortamos en el primer espacio, =, >, <, !
    tokens = re.split(r'[ =!><]', clean)
    full_ref = tokens[0] # Ej: Pod.io_k8s_api_core_v1_Pod_spec_hostIPC
    
    # 3. Quitar la referencia del módulo (Pod.) si tu CSV solo tiene el nombre de la feature
    if "." in full_ref:
        return full_ref.split(".", 1)[1] # Devuelve lo que hay después del punto
    return full_ref

# --- PROCESO PRINCIPAL ---
valid_features_set = load_feature_dict_polaris(VALID_FEATURES_CSV)
stats = {"total": 0, "aceptadas": 0, "descartadas": 0}

if os.path.exists(DEST_DIR): shutil.rmtree(DEST_DIR)
os.makedirs(DEST_DIR)

print("\n--- INICIANDO VALIDACIÓN HÍBRIDA (SINTÁCTICA + SEMÁNTICA) ---")

with open(OUTPUT_CSV, "w", encoding="utf-8") as f_out:
    f_out.write("Archivo;Categoria;Resultado;Razon\n")

    for root, dirs, files in os.walk(REPO_PATH):
        # 1. Poda de directorios (ignorar mpol, gpol, cel, etc.)
        dirs[:] = [d for d in dirs if not (d.startswith(".") or d == "test" or d.endswith("-cel") or d.endswith("-mpol") or d.endswith("-gpol") or d.endswith("-dpol"))]

        for file in files:
            if not (file.endswith(".yaml") or file.endswith(".yml")): continue
            if file in ["kustomization.yaml", "artifacthub-pkg.yml", "values.yaml"]: continue

            filepath = os.path.join(root, file)
            stats["total"] += 1
            
            # --- FASE 1: TRADUCCIÓN (EL PROCESAMIENTO) ---
            try:
                # Esto ejecuta tu lógica de concatenación, prefijos y recursividad
                constraints_dict, _ = extract_constraints_from_policy(filepath)
            except Exception as e:
                # Si crashea el traductor, es que el YAML es muy raro
                f_out.write(f"{file};Unknown;DESCARTADA;Error Traductor: {str(e)}\n")
                stats["descartadas"] += 1
                continue

            if not constraints_dict:
                # Si devuelve vacío, es que no encontró patterns compatibles (o era mutate/generate)
                f_out.write(f"{file};Unknown;DESCARTADA;Sin reglas estáticas detectadas\n")
                stats["descartadas"] += 1
                continue

            # --- FASE 2: VERIFICACIÓN SEMÁNTICA ---
            features_desconocidas = []
            features_detectadas = 0
            
            # Iteramos sobre todas las restricciones generadas
            for policy_name, expr_list in constraints_dict.items():
                for expr in expr_list:
                    # Ojo: una expresión puede ser compuesta "A & B". 
                    # Simplificación: buscamos todas las palabras que parecen features
                    # Regex para capturar strings tipo "io_k8s_..._algo"
                    candidates = re.findall(r'\b(?:[a-zA-Z0-9]+_){2,}[a-zA-Z0-9_]+\b', expr)
                    
                    for feat in candidates:
                        # Si tu CSV tiene prefijos (io_k8s...), verificamos directo
                        if feat not in valid_features_set:
                            # Filtro extra: A veces son valores (ENUMs), no features.
                            # Si empieza por io_k8s es casi seguro una feature.
                            if feat.startswith("io_k8s"): 
                                features_desconocidas.append(feat)
                        else:
                            features_detectadas += 1

            # --- DECISIÓN FINAL ---
            rel_path = os.path.relpath(filepath, REPO_PATH)
            parts = rel_path.split(os.sep)
            categoria = parts[0] if len(parts) > 1 else "root"
            nombre_final = f"{parts[-2]}.yaml" if len(parts) >= 2 else file

            if features_desconocidas:
                # Política genera features que NO existen en el modelo (Alucinación del traductor o feature nueva)
                unique_errors = list(set(features_desconocidas))[:3] # Muestra solo las primeras 3
                f_out.write(f"{rel_path};{categoria};DESCARTADA;Feature fantasma: {unique_errors}\n")
                stats["descartadas"] += 1
            elif features_detectadas == 0:
                 # No detectó features conocidas (raro, quizás validó contra 'null' o strings puros)
                 f_out.write(f"{rel_path};{categoria};DESCARTADA;No se detectaron features K8s validables\n")
                 stats["descartadas"] += 1
            else:
                # ÉXITO: Traducible Y todas las features existen en el modelo
                f_out.write(f"{rel_path};{categoria};ACEPTADA;Semántica Correcta\n")
                stats["aceptadas"] += 1
                
                # Copiar al dataset limpio
                target_dir = os.path.join(DEST_DIR, categoria)
                os.makedirs(target_dir, exist_ok=True)
                shutil.copy2(filepath, os.path.join(target_dir, nombre_final))

print(f"\n--- RESUMEN FINAL ---")
print(f"Total Analizados: {stats['total']}")
print(f"Aceptadas (Estáticas y Semántica OK): {stats['aceptadas']}")
print(f"Descartadas: {stats['descartadas']}")
print(f"Dataset limpio en: {DEST_DIR}")