import os
import csv
import time
import contextlib, io
from pathlib import Path

from flamapy.metamodels.fm_metamodel.transformations import UVLReader
from flamapy.metamodels.pysat_metamodel.transformations import FmToPysat

from scripts.configurationJSON01 import ConfigurationJSON
from scripts.valid_config import valid_config_version_json  # versión que acepta sat_features


# --------------------------------------------------
# CONFIGURACIÓN
# --------------------------------------------------

HERE = Path(__file__).resolve().parent         # scripts/
ROOT = HERE.parent                             # fm-security-rules/
ROOT_PARENT = ROOT.parent                      # carpeta projects/

FM_PATH = ROOT / "variability_model" / "policies_template" / "policy_structure03.uvl"

# Tus JSONs están aquí:
VALID_JSONS_DIR = ROOT_PARENT / "valid_jsons"

OUTPUT_CSV = HERE / "validation_results_valid_jsons.csv"

VALIDATE_ONLY_FIRST_CONFIG = True


# --------------------------------------------------
# FUNCIONES
# --------------------------------------------------

def validate_single_json(json_file, fm_model, sat_model, sat_features):
    """Valida un archivo JSON concreto y devuelve métricas para el CSV."""

    try:
        print(f"Validando archivo: {json_file}")

        start_conf_time = time.time()
        config_reader = ConfigurationJSON(json_file)
        configurations = config_reader.transform()
        end_conf_time = time.time()

        conf_time = round(end_conf_time - start_conf_time, 5)
        num_confs = len(configurations)
        num_features = len(configurations[0].elements) if configurations else 0

        # --- Validación ---
        if VALIDATE_ONLY_FIRST_CONFIG:
            config = configurations[0]

            start_validation_time = time.time()
            valid, _ = valid_config_version_json(config, fm_model, sat_model, sat_features)
            end_validation_time = time.time()

        else:
            valid = True
            start_validation_time = time.time()

            for conf in configurations:
                ok, _ = valid_config_version_json(conf, fm_model, sat_model, sat_features)
                if not ok:
                    valid = False
                    break

            end_validation_time = time.time()

        validation_time = round(end_validation_time - start_validation_time, 5)

        return [
            os.path.basename(json_file),
            valid,
            num_features,
            num_confs,
            conf_time,
            validation_time,
            "Archivo válido" if valid else "Archivo inválido"
        ]

    except Exception as e:
        print(f"[ERROR] {json_file}: {e}")
        return [
            os.path.basename(json_file),
            "Error",
            "-",
            "-",
            "-",
            "-",
            str(e)
        ]


def validate_all_valid_jsons():

    print(f"\nCargando modelo UVL: {FM_PATH}\n")
    fm_model = UVLReader(str(FM_PATH)).transform()

    # Silenciar la salida del transformador SAT
    silent = io.StringIO()
    with contextlib.redirect_stdout(silent):
        sat_model = FmToPysat(fm_model).transform()

    # EXTRAEMOS SAT FEATURES UNA SOLA VEZ
    sat_features = set(sat_model.variables.keys())
    print(f"SAT features cargadas: {len(sat_features)}")

    print(f"Procesando carpeta de JSONs: {VALID_JSONS_DIR.resolve()}")

    files = sorted([f for f in os.listdir(VALID_JSONS_DIR) if f.endswith(".json")])

    with open(OUTPUT_CSV, mode='w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Filename", "Valid", "Features", "Configurations", "TimeConf", "TimeVal", "Description"])

        valid_count = invalid_count = error_count = 0

        for filename in files:
            json_path = os.path.join(VALID_JSONS_DIR, filename)
            result = validate_single_json(json_path, fm_model, sat_model, sat_features)
            writer.writerow(result)

            state = str(result[1]).lower()
            if state == "true":
                valid_count += 1
            elif state == "false":
                invalid_count += 1
            else:
                error_count += 1

    print("\n=== RESUMEN FINAL ===")
    print(f"Archivos válidos:   {valid_count}")
    print(f"Archivos inválidos: {invalid_count}")
    print(f"Errores:            {error_count}")
    print(f"Resultados guardados en: {OUTPUT_CSV}")


# --------------------------------------------------
# MAIN
# --------------------------------------------------

if __name__ == '__main__':
    print(f"Validando JSONs desde: {VALID_JSONS_DIR.resolve()}")
    validate_all_valid_jsons()