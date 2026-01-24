from flamapy.metamodels.fm_metamodel.transformations import UVLReader, FlatFM
from flamapy.metamodels.pysat_metamodel.transformations import FmToPysat

from scripts.configurationJSON01 import ConfigurationJSON
from scripts.valid_config02 import valid_config_version_json

import os
import csv
import time
import contextlib, io
from pathlib import Path
from scripts._inference_policy import extract_policy_kinds_from_constraints, infer_policies_from_kind

HERE = Path(__file__).resolve().parent # scripts/
ROOT = HERE.parent # fm-security-rules/
ROOT_PARENT = ROOT.parent # carpeta anterior a la raiz/
FM_PATH = ROOT / "variability_model" / "policies_template" / "policy_structure04.uvl"
VALID_JSONS_DIR = ROOT_PARENT / "valid_jsons" ## valid_jsons jsons_testing

OUTPUT_CSV = ROOT / "evaluation" / "validation_results_valid_jsons04_01.csv" ## Output csv
VALIDATE_ONLY_FIRST_CONFIG = True


# --------------------------------------------------
# FUNCIONES
# --------------------------------------------------

def load_processed_files(csv_file_path):
    """
    Load already processed filenames from a CSV file.
    
    :param csv_file_path (str): Path to the CSV results file.
    
    """
    processed = set()
    if os.path.exists(csv_file_path):
        with open(csv_file_path, mode="r", newline="") as f:
            reader = csv.reader(f)
            next(reader, None)  # Skip header
            for row in reader:
                if row and row[0].endswith(".json"):  # Ensure that it is a valid row of data.
                    processed.add(row[0])
    return processed

def build_suffix_index(sat_features):

    suffix_map = {}

    for sf in sat_features:

        # 1) Guardar el NOMBRE COMPLETO como clave (para coincidencia exacta)
        suffix_map.setdefault(sf, []).append(sf)

        # 2) Sufijo final (última parte)
        idx = sf.rfind("_")
        if idx != -1:
            suffix_final = sf[idx+1:]
            suffix_map.setdefault(suffix_final, []).append(sf)

        # 3) Cardinalidades: extraer lo que sigue a "_n1_"
        marker = "_n1_"
        if marker in sf:
            suffix_card = sf.split(marker, 1)[1]
            suffix_map.setdefault(suffix_card, []).append(sf)

    return suffix_map



def validate_single_json(json_file, fm_model, sat_model, sat_features, constraints_map):
    """Valida un archivo JSON concreto y devuelve métricas para el CSV."""
    policy_false = '' ## Como obtener la politica por la que se vuelve False?, agregar set de politicas aplicadas?
    tool_policy = 'Kyverno' ## Obtener tool de la herramienta de la politica que falla
    severity_of_policy ='medium' ## Severity de la herramienta de la politica que falla
    try:
        print(f"Procesando archivo: {json_file}") 

        start_conf_time = time.time() # Start of mapping conf time
        config_reader = ConfigurationJSON(json_file)
        configurations = config_reader.transform()
        end_conf_time = time.time()
        conf_time = round(end_conf_time - start_conf_time, 5)
        config = configurations[0]

        # detectar políticas aplicables
        auto_policies = infer_policies_from_kind(config.elements, constraints_map)
        print(f"Detectar politicas aplicadas a la configg: {auto_policies}")
        if not auto_policies: ## If para comprobar si la configuracion tiene alguna politica para comprobar del fm; sino skip
            ## Definir funcion para comprobar si hay coincidencia entre kinds de la config y 
            return [os.path.basename(json_file), "Configuracion sin politicas que verificar", "-", "-", "-", "-", "-", "-", "-", "Skip"]
            
        ## Como agregar la politica que incumple + la tool?
        num_confs = len(configurations) ## Num of configs
        num_features = len(configurations[0].elements) if configurations else 0 # Num of featurtes fronm the config
        valid_config_bool = True
        # --- Validación ---
        if VALIDATE_ONLY_FIRST_CONFIG:
            #config = configurations[0]

            start_validation_time = time.time()
            valid, _ = valid_config_version_json(config, fm_model, sat_model, sat_features, auto_policies)
            end_validation_time = time.time()
            valid_config_bool = valid
            #print(f'Configuración 1 (única validada): -> Válida: {valid}')
        else:
            start_validation_time = time.time()
            for conf in configurations:
                valid, _ = valid_config_version_json(conf, fm_model, sat_model, sat_features, auto_policies)
                if not valid: # Checking of each configuration of each file
                    valid_config_bool = False
                    break # If there is only one invalid conf, the entire file is considered invalid
                        
            end_validation_time = time.time()

        validation_time = round(end_validation_time - start_validation_time, 5)
        policy_false = str(auto_policies)
        return [os.path.basename(json_file), valid_config_bool, validation_time, conf_time, policy_false, tool_policy, severity_of_policy, num_features, num_confs,  "Ningun parametro invalido" if valid_config_bool else "Recomendacion: "]
    
    
    except Exception as e:
        print(f"[ERROR] {json_file}: {e}")
        return [os.path.basename(json_file), "Error", "-", "-", "-", "-", "-", "-", "-", str(e)]

def validate_all_configs(flat_model, sat_model, sat_features, processed_files):
  
    """
    Validate all JSON configuration files in a directory.

    Args:
        directory (str): Path to the directory with JSON files.
        fm_model (FeatureModel): The feature model.
        sat_model (PySATModel): SAT-based model.
        writer (csv.writer): CSV writer object to save results.
        processed_files (set): Set of files already processed.

    Returns:
        tuple: Counts of valid, invalid, and error files.
    """
    print(f"SAT features cargadas: {len(sat_features)}")
    print(f"Procesando carpeta de JSONs: {VALID_JSONS_DIR.resolve()}")
    constraint_kinds_map = extract_policy_kinds_from_constraints(FM_PATH)
    #suffix_map = build_suffix_index(sat_features) ## Dict para las coincidencias con los features del flatten

    file_exists = os.path.exists(OUTPUT_CSV) and os.path.getsize(OUTPUT_CSV) > 0
    
    with open(OUTPUT_CSV, mode='a', newline='') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["Filename", "Secure", "TimeVal", "TimeConf","PoliciesApplied", "ToolPolicy", "Severity", "Features", "Configurations", "Description"])

        valid_count = invalid_count = error_count = 0

        for filename in os.listdir(VALID_JSONS_DIR):
            if not filename.endswith(".json"):
                continue
            
            if filename in processed_files:
                print(f"Saltando (ya procesado): {filename}")
                continue
            
            json_path = os.path.join(VALID_JSONS_DIR, filename)
            result = validate_single_json(json_path, flat_model, sat_model, sat_features, constraint_kinds_map)
            writer.writerow(result)
            processed_files.add(filename)
            
            state = str(result[1]).lower()
            if state == "true":
                valid_count += 1
            elif state == "false":
                invalid_count += 1
            else:
                error_count += 1
                
        """writer.writerow([])  # línea en blanco
        writer.writerow(["Resumen", "", "", "", "", "", "", "", "", ""])
        writer.writerow(["Configuraciones sin errores", valid_count])
        writer.writerow(["Configuraciones con errores de Seguridad", invalid_count])
        writer.writerow(["Archivos sin políticas aplicables", error_count])"""
    print("\n=== RESUMEN FINAL ===")
    print(f"Archivos válidos:   {valid_count}")
    print(f"Archivos inválidos: {invalid_count}")
    print(f"Archivos sin politicas aplicables: {error_count}")
    print(f"Resultados guardados en: {OUTPUT_CSV}")


if __name__ == '__main__':

    print(f"Cargando y procesando el modelo")
    start_startup_model = time.time()  # Start of validation time
    fm_model = UVLReader(str(FM_PATH)).transform()
    flat_fm_op = FlatFM(fm_model)
    flat_fm_op.set_maintain_namespaces(False)  # False para quitar el prefijo del import, con True se mantiene.
    flat_fm = flat_fm_op.transform()

    end_startup_model = time.time()  # End of validation time
    validation_time = round(end_startup_model - start_startup_model, 4)
    print(f"Tiempo de start config of FMs   {validation_time}")
    
    print(f"Procesando el Flat FM")
    start_flatfm_proccess = time.time()  # Start of validation time
    ## Silent the outputs logs of the flatten proccess
    silent = io.StringIO()
    with contextlib.redirect_stdout(silent):
        sat_model = FmToPysat(flat_fm).transform()
    sat_features = set(sat_model.variables.keys())
    end_flatfm_proccess = time.time()
    flatfm_time = round(end_flatfm_proccess - start_flatfm_proccess, 4)
    print(f"Tiempo de silenciar FlatFm y guardar SAT_FEATURES   {flatfm_time}")
    #valid_count, invalid_count, error_count = 0, 0, 0
    list_processed_files = load_processed_files(OUTPUT_CSV)
    print(f"Validando JSONs desde: {VALID_JSONS_DIR.resolve()}")
    validate_all_configs(flat_fm, sat_model, sat_features, list_processed_files)
    
    print(f"Tiempo de start config of FMs   {validation_time}")
    print(f"Tiempo de silenciar FlatFm y guardar SAT_FEATURES   {flatfm_time}")