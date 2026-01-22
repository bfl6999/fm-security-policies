from flamapy.metamodels.fm_metamodel.transformations import UVLReader
from flamapy.metamodels.pysat_metamodel.transformations import FmToPysat
from configurationJSON01 import ConfigurationJSON  # Reader JSON
from valid_config import valid_config_version_json

import time  # Libreria para calcular los tiempos de procesamiento

import os
import csv

FM_PATH = '../../../variability_model/kubernetes_combined_04.uvl'

json_base_directory = '../../../resources/generateConfigs'
json_folders = ['outputs_json_mappeds', 'invalidKindsVersions01' ]

ERROR_LOG_FILE = "error_log_mappeds03_11_3.txt"
csv_ouput_file = "config_validation_results03_3_json11_FirstConfig.csv"

VALIDATE_ONLY_FIRST_CONFIG = True ## Use unit or total validation version

def load_processed_files(csv_file_path):
  """
  Load already processed filenames from a CSV file.

  Args:
      csv_file_path (str): Path to the CSV results file.

  Returns:
      set: Set of filenames already processed.
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


def process_file(filepath, fm_model, sat_model):
  """
  Validate a single JSON configuration file against a feature model.

  Args:
      filepath (str): Path to the configuration JSON file.
      fm_model (FeatureModel): The feature model.
      sat_model (PySATModel): SAT-based representation of the model.

  Returns:
      list: Validation summary including filename, status, feature count, etc.
  """

  try:
    print(f"Procesando archivo: {filepath}")
    
    if 'invalidKindsVersions' in os.path.normpath(filepath):
      ## return process with the error decided and so on...
      return [os.path.basename(filepath), "Invalid (Kind, Version)", "-", "-", "-", "-", "La version y/o kind en el archivo estan fuera del esquema de Kubernetes."]

    start_conf_time = time.time()  # Start of mapping time
    configuration_reader = ConfigurationJSON(filepath)
    configurations = configuration_reader.transform()
    end_conf_time = time.time()  # End of mapping time
    conf_time = round(end_conf_time - start_conf_time, 5)  # Row T conf: Conf mapping time in seconds
    num_confs = len(configurations)  # Row Nº Confs: Number of file configurations
    # If there are configurations, we take the first one to tell its features
    num_features = len(configurations[0].elements) if configurations else 0
    file_valid = True
    
    if VALIDATE_ONLY_FIRST_CONFIG:
        config = configurations[0] ## The first configuration is obtained

        start_validation_time = time.time()  # Start of validation time
        valid, complete_config = valid_config_version_json(config, fm_model, sat_model)
        end_validation_time = time.time()  # End of validation time
        validation_time = round(end_validation_time - start_validation_time, 4)  # Row T val: Validation time in seconds
        file_valid = valid
        print(f'Configuración 1 (única validada): -> Válida: {valid}')
    else: ## Complete validation of configurations
      start_validation_time = time.time()  # Start of validation time
      for i, config in enumerate(configurations): ## Checking of each configuration of each file
        valid, complete_config = valid_config_version_json(config, fm_model, sat_model)
        print(f'Configuración {i+1}:  -> Válida: {valid}') ## {config.elements} 
        if not valid:
          file_valid = False
          break # If there is only one invalid conf, the entire file is considered invalid
      end_validation_time = time.time()  # End of validation time
      validation_time = round(end_validation_time - start_validation_time, 4)  # Row T val: Validation time in seconds
    return [os.path.basename(filepath), file_valid, num_features, num_confs, conf_time, validation_time, "Todas las Configuraciones validas" if file_valid else "Alguna Configuracion invalida"] ##results

  except FileNotFoundError:
    with open(ERROR_LOG_FILE, "a") as error_log:
      error_log.write(f"Archivo no encontrado: {os.path.basename(filepath)}\n")
    return [os.path.basename(filepath), "Error", "-", "-", "-", "-", "Exeption Error archivo no encontrado"] #return [os.path.basename(filepath), "Error"]

  except Exception as e:
    with open(ERROR_LOG_FILE, "a") as error_log:
      error_log.write(f"Error desconocido en archivo {os.path.basename(filepath)}: {str(e)}\n")
    return [os.path.basename(filepath), "Error", "-", "-", "-", "-", "Exeption Error no contemplado"] 

def validate_all_configs(directory, fm_model, sat_model ,writer, processed_files):
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

  valid_count = 0
  invalid_count = 0
  error_count = 0
  for filename in os.listdir(directory):
    if filename in processed_files: 
      continue ## File already in the list of results
    if not filename.endswith(".json"):  # Only process JSON
      continue

    file_path = os.path.normpath(os.path.join(directory, filename))     ## os.path.join(directory, filename)
    result = process_file(file_path, fm_model, sat_model)
    writer.writerow(result)  # Write in the CSV line by line

    valid_field = str(result[1]).strip().lower()
    if valid_field == 'true':
      valid_count += 1
    if valid_field == 'false':
      invalid_count += 1
    else:
      error_count += 1

  return valid_count, invalid_count, error_count

# Generator list processing YAMLs of all valid folders
def iterate_all_paths(json_base_directory, json_folders, fm_model, sat_model):
    for folder in json_folders:
        json_path = os.path.normpath(os.path.join(json_base_directory, folder))
        if os.path.isdir(json_path):
            validate_all_configs(json_path, fm_model, sat_model)
        
if __name__ == '__main__':

  fm_model = UVLReader(FM_PATH).transform()
  sat_model = FmToPysat(fm_model).transform()
  print(f"Cargando y procesando el modelo")
  valid_count, invalid_count, error_count = 0, 0, 0
  list_processed_files = load_processed_files(csv_ouput_file)

  writhe_name_rows = not os.path.exists(csv_ouput_file) or os.stat(csv_ouput_file).st_size == 0

  with open(csv_ouput_file, mode="a", newline="") as file:
    writer = csv.writer(file)
    
    if writhe_name_rows: ## Write header rows if csv not exist before
      writer.writerow(["Filename", "Valid", "Features", "Configurations", "TimeConf", "TimeVal", "DescriptionAgrupation"])

    for folder in json_folders:
      json_path = os.path.normpath(os.path.join(json_base_directory, folder))
      print(f"JSON PATH {json_path}")
      if os.path.isdir(json_path):
        valid_num, invalid_num, error_num =  validate_all_configs(json_path, fm_model, sat_model, writer, list_processed_files)
        valid_count = valid_count + valid_num
        invalid_count = invalid_count + invalid_num
        error_count = error_count + error_num

    writer.writerow(["Total Valid", valid_count])
    writer.writerow(["Total Invalid", invalid_count])
    writer.writerow(["Total Error", error_count])

    print(f"\n Total de archivos válidos: {valid_count}")
    print(f" Total de archivos inválidos: {invalid_count}")
    print(f" Total de archivos inválidos: {error_count}")

    print(f"Resultados guardados en {csv_ouput_file}")