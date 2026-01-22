"""
This script processes classified Kubernetes YAML files and maps their hierarchical structure
to features defined in a UVL model using a CSV-based feature mapping.

It performs:
- Parsing of YAML documents to extract properties and key-value pairs
- Filtering based on valid (apiVersion, kind) from a reference CSV
- Matching YAML structures to UVL feature names
- Outputting transformed JSON files with features replaced

Outputs:
- JSON files with UVL features mapped from YAML structure
- Error logs for malformed or unrecognized YAMLs
"""

import yaml
import csv
import os
import json
import re
from datetime import datetime, timezone, date, time

import gc
import shutil

# Base path where the buckets are sorted by size
yaml_base_directory = '../resources/kyverno_policies_yamls' ## 
csv_kinds_versions = '../resources/mapping_csv/kinds_versions_detected.csv'
# Valids buckets
buckets = ['tiny', 'small', 'medium', 'large', 'huge']


def load_kinds_versions(path_csv):
    """
    Load the list of allowed (apiVersion, kind) combinations from a CSV file.

    Args:
        path_csv (str): Path to the CSV file containing Kubernetes kinds and versions.

    Returns:
        set: A set of tuples containing (apiVersion, kind).
    """

    kinds_versions = set()
    with open(path_csv, mode='r', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            version = row['Version'].strip() ## group = row['Group'].strip()
            kind = row['Kind'].strip()
            kinds_versions.add((version, kind))
    return kinds_versions


def extract_yaml_properties(data, parent_key='', root_info=None, first_add=True):
    """
    Recursively extract YAML properties into flattened hierarchical features.

    Args:
        data (dict or list): Parsed YAML data structure.
        parent_key (str): Parent key prefix for recursion.
        root_info (dict): Dictionary storing top-level `apiVersion` and `kind`.
        first_add (bool): Whether this is the initial recursion.

    Returns:
        tuple: Lists of (simple_props, hierarchical_props, key_value_pairs, root_info).
    """

    simple_props = []
    hierarchical_props = []
    key_value_pairs = []
    
    if root_info is None:
        root_info = {}

    if isinstance(data, dict):
        for key, value in data.items():

            if key is None and value is None: ## Omit the type of cases with declarations "name: [ ? ]"
                raise ValueError(f"Clave o valor inválida detectada: {key}: {value}")
            
            new_key = f"{parent_key}_{key}" if parent_key else key
            # Save key values (apiVersion and kind) to determine the context
            if key in ['apiVersion', 'kind'] and first_add: ## It is only modified if it is the first call
                if key not in root_info:  # Do not overwrite if already defined at the top level.
                    if '/' in value and not '.' in value:
                        value = value.replace('/', '_')
                    elif '.' in value and '/' in value: ## In case the version value contains dots '.' only the second part separated by the sidebar '/' is used to indicate the version within the schemas
                        aux_value = value.split('/') ## As represented in the api_rbac_v1_ schemas, case in the yaml: rbac.authorization.k8s.io/v1
                        value = aux_value[1]
                    elif '.' in value and not '/' in value:
                        ## There is no version definition and only a group or an invalid version is added.
                        raise ValueError(f"apiVersion sin versión explícita: {value}")

                    root_info[key] = value
            simple_props.append(key)

            if isinstance(value, (dict, list)):
                sub_simple, sub_hierarchical, sub_kv_pairs, _ = extract_yaml_properties(value, new_key, root_info, first_add=False)
                simple_props.extend(sub_simple)
                hierarchical_props.extend(sub_hierarchical)
                hierarchical_props.append(new_key)  # Values are added after recursion
                key_value_pairs.extend(sub_kv_pairs)
            else:
                hierarchical_props.append(new_key)
                key_value_pairs.append((new_key, value))  # Save key and value

    elif isinstance(data, list):
        for item in data:
            sub_simple, sub_hierarchical, sub_kv_pairs, _ = extract_yaml_properties(item, parent_key, root_info, first_add=False)
            simple_props.extend(sub_simple)
            hierarchical_props.extend(sub_hierarchical)
            key_value_pairs.extend(sub_kv_pairs)

    # If we have apiVersion and kind, we add a prefix to the feature to improve accuracy.
    if 'apiVersion' in root_info and 'kind' in root_info and first_add:
        prefix = f"{root_info['apiVersion']}_{root_info['kind']}"
        hierarchical_props = [f"{prefix}_{prop}" for prop in hierarchical_props]
        key_value_pairs = [(f"{prefix}_{key}", value) for key, value in key_value_pairs]
    elif 'apiVersion' not in root_info or 'kind' not in root_info and first_add:
        return None, None, None, root_info ## Try to determine files without apiVersion kind in the root. It also detects those that do not declare properties at the beginning.
    return simple_props, hierarchical_props, key_value_pairs, root_info


def process_yaml_file(file_path):
    """
    Process a single YAML file and extract structured features.

    Validates the file's (apiVersion, kind) against allowed values,
    parses features, and stores invalid files in error folders if needed.

    Args:
        file_path (str): Path to the YAML file.

    Yields:
        tuple: Extracted metadata including file path, doc index, parsed data, props, and root info.
    """

    error_log_path = './error_log_mapping_tester_03.txt'
    dict_allowed_kinds_versions = load_kinds_versions(csv_kinds_versions) ## Allowed kinds and versions are loaded

    try:
        with open(file_path, 'r', encoding='utf-8') as yaml_file:
            yaml_documents = list(yaml.safe_load_all(yaml_file))
        if not yaml_documents:
            return None  # File empty or not valid

        for index, yaml_data in enumerate(yaml_documents):
            if yaml_data is None:
                continue
            try:
                root_info = {}  # Reset root_info for each document
                simple_props, hierarchical_props, key_value_pairs, root_info = extract_yaml_properties(yaml_data)

                ## Checks if the files to be mapped have a valid version and kinds in the context of the model.
                apiVersion =  root_info.get('apiVersion')
                kind = root_info.get('kind')

                if "_" in apiVersion:
                    split_version = apiVersion.split("_")[1]
                    apiVersion = split_version
                if (apiVersion, kind) not in dict_allowed_kinds_versions:
                    print(f"Archivo no valido por version y kind")
                    # Saving a copy of the YAML in JSON format
                    dest_json_dir = os.path.join(yaml_base_directory, 'invalidKindsVersions01')
                    os.makedirs(dest_json_dir, exist_ok=True)
                    json_name = os.path.basename(file_path).replace('.yaml', '.json')
                    json_path = os.path.join(dest_json_dir, json_name)
                    with open(json_path, 'w', encoding='utf-8') as f_json:
                        json.dump(yaml_data, f_json, indent=2)

                    # Moving the original YAML to another folder
                    dest_yaml_dir = os.path.join(yaml_base_directory, 'invalidKindsVersionsFormatYaml01')
                    os.makedirs(dest_yaml_dir, exist_ok=True)
                    dest_path_file = os.path.join(dest_yaml_dir, os.path.basename(file_path))
                    shutil.move(file_path, dest_path_file)

                    # Log
                    with open(error_log_path, 'a', encoding='utf-8') as error_log:
                        error_log.write(f"[KIND NO VÁLIDO] Falta apiVersion/kind raíz en {file_path} (doc {index})\n")
                    break
                    
                yield (file_path, index, yaml_data, simple_props, hierarchical_props, key_value_pairs, root_info)
                    # yaml_data_list.append((filename, index, yaml_data, simple_props, hierarchical_props, key_value_pairs, root_info))

            except ValueError as ve:
                with open(error_log_path, 'a', encoding='utf-8') as error_log:
                    error_log.write(f"[OMITIDO] {ve} en {file_path}\n")
                # Copy of file with invalid value or apiVersion error without version
                error_mapping_dir = os.path.join(yaml_base_directory, 'erroresMapeo')
                os.makedirs(error_mapping_dir, exist_ok=True)
                dest_path = os.path.join(error_mapping_dir, os.path.basename(file_path))
                shutil.copy(file_path, dest_path)    
                continue
    except yaml.YAMLError as e:
        with open(error_log_path, 'a', encoding='utf-8') as error_log:
            error_log.write(f"[YAML ERROR] en {file_path}: {str(e)}\n")
        # Copy file with YAML error
        error_yaml_dir = os.path.join(yaml_base_directory, 'erroresYAML')
        os.makedirs(error_yaml_dir, exist_ok=True)
        dest_path = os.path.join(error_yaml_dir, os.path.basename(file_path))
        shutil.copy(file_path, dest_path)

    except FileNotFoundError:
        with open(error_log_path, 'a', encoding='utf-8') as error_log:
            error_log.write(f"[NOT FOUND] Archivo no encontrado: {file_path}\n")
    except Exception as e:
        with open(error_log_path, 'a', encoding='utf-8') as error_log:
            error_log.write(f"[GENERAL ERROR] en archivo {file_path}: {str(e)}\n")


def read_yaml_files_from_directory(directory_path):
    """
    Read and process all YAML files in a given directory.

    Args:
        directory_path (str): Directory containing YAML files.

    Yields:
        Generator: Results from `process_yaml_file`.
    """

    # Check if the directory is empty
    if not any(fname.endswith((".yaml", ".yml")) for fname in os.listdir(directory_path)):
        print(f"[AVISO] Carpeta vacía o sin YAMLs: {directory_path}")
        return  # This folder is skipped and continues with the next one.
    
    for filename in os.listdir(directory_path):
        if filename.endswith((".yaml", ".yml")):
            file_path = os.path.join(directory_path, filename)
            yield from process_yaml_file(file_path)  # Generator instead of list

            gc.collect()  # Periodically free memory

def iterate_all_buckets(base_dir, bucket_list):
    """
    Iterate over all directories representing bucket sizes and process YAMLs within.

    Args:
        base_dir (str): Base directory containing bucket folders.
        bucket_list (list): List of bucket folder names.

    Yields:
        Generator: YAML processing results from each file.
    """

    for bucket in bucket_list:
        bucket_path = os.path.normpath(os.path.join(base_dir, bucket))
        if os.path.isdir(bucket_path):
            yield from read_yaml_files_from_directory(bucket_path)

def convert_all_datetimes(obj):
    """
    Convert all datetime, date, and time objects to ISO format strings in nested data.

    Args:
        obj (any): Input object (dict, list, or primitive).

    Returns:
        any: Transformed object with datetime strings.
    """

    if isinstance(obj, dict):
        return {k: convert_all_datetimes(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_all_datetimes(i) for i in obj]
    elif isinstance(obj, datetime):
        return obj.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    elif isinstance(obj, (date, time)):
        return obj.isoformat() # HH:MM:SS
    return obj

def contains_datetime(obj):
    """
    Check if any datetime, date, or time objects exist in the nested structure.

    Args:
        obj (any): Input object to scan.

    Returns:
        bool: True if datetime-related types are found, False otherwise.
    """

    if isinstance(obj, dict):
        return any(contains_datetime(v) for v in obj.values())
    elif isinstance(obj, list):
        return any(contains_datetime(i) for i in obj)
    return isinstance(obj, (datetime, date, time))


def load_features_csv(csv_path):
    """
    Load a CSV file of mapped features and return it as a dictionary.

    Args:
        csv_path (str): Path to the features CSV.

    Returns:
        dict: Dictionary mapping features to metadata including Midle, Turned, and Value.
    """

    feature_dict = {}
    with open(csv_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            feature_name = row['Feature']
            feature_dict[feature_name] = {
                "middle": row['Midle'],
                "turned": row['Turned'],
                "value": row['Value']
            }
    return feature_dict

def search_features_in_csv(hierarchical_props, key_value_pairs, csv_dict):
    """
    Match YAML properties to UVL feature names based on CSV metadata.

    Args:
        hierarchical_props (list): Flattened hierarchical properties from YAML.
        key_value_pairs (list): List of key-value tuples from YAML.
        csv_dict (dict): Dictionary of UVL features and their metadata.

    Returns:
        dict: Mapping from hierarchical YAML paths to UVL feature names.
    """

    feature_map = {}

    for feature, meta in csv_dict.items():
        middle, turned, value = meta["middle"], meta["turned"], meta["value"]
        if f"_{root_info.get('apiVersion', 'unknown')}_{root_info.get('kind', 'unknown')}_" in feature:
            for hierarchical_prop in hierarchical_props:
                if middle.strip() and hierarchical_prop.endswith(middle):   
                    if value == "-":
                        feature_map[hierarchical_prop] =  {"feature_type": "array", "feature": feature}
                    else:
                        ## Normal execution
                        feature_map[hierarchical_prop] = feature
                
                aux_hierchical_maps = feature.rsplit("_", 1)[0] ## The last part of the feature is omitted to make it possible to compare with the hierarchical_prop and filter the related ones.
                ## Conditions where you want to capture the map features named in the YAMLS
                if middle.strip() and turned == "KeyMap" and feature not in feature_map and aux_hierchical_maps.endswith(hierarchical_prop):
                    aux_hierchical_maps_key = f"{hierarchical_prop}_KeyMap" ## The _KeyMap is created manually because it is not included in the YAMLS.
                    feature_map[aux_hierchical_maps_key] = feature
                elif middle.strip() and turned == "ValueMap" and feature not in feature_map and aux_hierchical_maps.endswith(hierarchical_prop):
                    aux_hierchical_maps_value = f"{hierarchical_prop}_ValueMap" ## The _ValueMap is created manually because it is not included in the YAMLS.
                    feature_map[aux_hierchical_maps_value] = feature
                elif middle.strip() and turned == "StringValue" and feature not in feature_map and aux_hierchical_maps.endswith(hierarchical_prop): ## New addition to add StringValues appearing in the feature list
                    aux_hierchical_arr_string = f"{hierarchical_prop}_StringValue" ## The _StringValue is created manually because it is a custom feature of the model. It is used to refer to arrays of strings.
                    feature_map[aux_hierchical_arr_string] = feature
                elif middle.strip() and turned == "IntegerValue" and feature not in feature_map and aux_hierchical_maps.endswith(hierarchical_prop): ## New addition to add StringValues appearing in the feature list
                    aux_hierchical_arr_integer = f"{hierarchical_prop}_IntegerValue" ## The _StringValue is created manually because it is a custom feature of the model. It is used to refer to arrays of strings.
                    feature_map[aux_hierchical_arr_integer] = feature
                ## StringValueAdditional: Array of Strings that is added differently in the main script of the model.
                elif middle.strip() and turned == "StringValueAdditional" and feature not in feature_map and aux_hierchical_maps.endswith(hierarchical_prop): ## New addition to add StringValues appearing in the feature list
                    aux_hierchical_arr_string_additional = f"{hierarchical_prop}_StringValueAdditional" ## The _StringValue is created manually because it is a custom feature of the model. It is used to refer to arrays of strings.
                    feature_map[aux_hierchical_arr_string_additional] = feature
                ## To add the incorporation of the data selection type features, they are added “manually”. When there is a match of the feature with Turned equal to asString, asNumber or asInteger, they are added if the
                ## inheritance matches the omitted feature. It is added by the alternativity of the model and in the output the one that appears in the JSON is selected. Not knowing the value that is added to the property, it is not possible to define before the data type
                elif middle.strip() and turned == "asString" and feature not in feature_map and aux_hierchical_maps.endswith(hierarchical_prop): ## New addition to add asString in the feature list
                    aux_hierchical_as_string = f"{hierarchical_prop}_asString" ## The _asString is created manually because it is a custom feature of the model. It is used to refer to the String type data selection.
                    feature_map[aux_hierchical_as_string] = feature
                elif middle.strip() and turned == "asNumber" and feature not in feature_map and aux_hierchical_maps.endswith(hierarchical_prop): ## New addition to add asNumber in the feature list
                    aux_hierchical_as_number = f"{hierarchical_prop}_asNumber" ## The _asNumber is created manually because it is a custom feature of the model. It is used to refer to the Number type data selection.
                    feature_map[aux_hierchical_as_number] = feature
                elif middle.strip() and turned == "asInteger" and feature not in feature_map and aux_hierchical_maps.endswith(hierarchical_prop): ## New addition to add asInteger in the feature list
                    aux_hierchical_as_integer = f"{hierarchical_prop}_asInteger" ## The _asInteger is created manually because it is a custom feature of the model. It is used to refer to the Integer type data selection.
                    feature_map[aux_hierchical_as_integer] = feature
                elif middle.strip() and turned == "isNull" and feature not in feature_map and aux_hierchical_maps.endswith(hierarchical_prop):
                    aux_hierchical_is_null = f"{hierarchical_prop}_isNull" ## The _isNull is created manually because it is a custom feature of the model. It is used to refer to the features with null value in the properties. It is added to be able to reference such non-value...
                    feature_map[aux_hierchical_is_null] = feature
                elif middle.strip() and turned == "isEmpty" and feature not in feature_map and aux_hierchical_maps.endswith(hierarchical_prop):
                    aux_hierchical_is_empty = f"{hierarchical_prop}_isEmpty" ## The _isEmpty is created manually because it is a custom feature of the model. It is used to refer to the features with empty value in the properties. It is added to be able to reference such non-value...
                    feature_map[aux_hierchical_is_empty] = feature
                elif middle.strip() and turned == "isEmpty02" and feature not in feature_map and aux_hierchical_maps.endswith(hierarchical_prop):
                    aux_hierchical_is_empty = f"{hierarchical_prop}_isEmpty02" ## The _isEmpty is created manually because it is a custom feature of the model. It is used to refer to the features with empty value in the properties. It is added to be able to reference such non-value...
                    feature_map[aux_hierchical_is_empty] = feature
                # Representation of the selected values, it is checked if any yaml value matches the last part...
                elif middle.strip() and hierarchical_prop in hierarchical_props and hierarchical_prop.endswith(middle) and value == "preserveUnknownFields" and feature not in feature_map: # preserveUnknownFieldsX
                    print(f"Coincidencia features   {feature}   {hierarchical_prop} {aux_hierchical_maps}")
                    feature_map[hierarchical_prop] =  {"feature_type": "specialType", "feature": feature}

                """elif middle.strip() and hierarchical_prop in hierarchical_props and hierarchical_prop.endswith(middle) and aux_hierchical_maps.endswith(hierarchical_prop) and value == "preserveUnknownFieldsX" and feature not in feature_map: # preserveUnknownFieldsX
                    print(f"Coincidencia features  X {feature}   {hierarchical_prop} {aux_hierchical_maps}")
                    feature_map[hierarchical_prop] =  {"feature_type": "specialTypeX", "feature": feature}"""

                    ##feature_map[aux_hierchical_maps_key] = feature
                    ## Definir funcionamiento para marcar el preserveUnknownFields como
                    # Evitamos mapear el contenido: solo dejamos la clave principal como bool True
                    #new_data[value_features] = True
                    #auxFeaturesAddedList.add(value_features)
                    #aux_hierchical_prop.append(key_features)

                for key, yaml_value in key_value_pairs:
                    if value and str(yaml_value) == value and feature not in feature_map: ## Try to avoid adding the same feature
                        aux_hierchical_value_added = f"{key}_{yaml_value}" ## The yaml_value is added manually because in the inheritance the value of the yaml properties is not appended.
                        if feature.endswith(aux_hierchical_value_added): ## Perhaps the match can be better defined but this ensures that the value matches the yaml value.
                            feature_map[aux_hierchical_value_added] = feature ## Added the feature that also matches the yaml
                            continue
    return feature_map

def extract_key_value_mappings(value, value_features, feature_map): ## Possible encapsulation of functions to improve readability
    """
    Extract individual key-value mappings from a nested map structure in YAML.

    Args:
        value (dict): Map object from YAML.
        value_features (str): The UVL feature key corresponding to the value.
        feature_map (dict): Current feature map context.

    Returns:
        list: List of key-value pair dictionaries suitable for UVL.
    """

    key_values = []
    aux_feature_maps = value_features.rsplit("_", 1)[0]
    aux_feature_value = f"{aux_feature_maps}_ValueMap"
    for map_key, map_value in value.items():
        key_values.append({
            value_features: map_key,
            aux_feature_value: map_value
        })
    return key_values

def apply_feature_mapping(yaml_data, feature_map, auxFeaturesAddedList, aux_hierchical_prop, mapped_key, aux_bool, depth_mapping = 0):
    """
    Recursively apply UVL feature mapping to a YAML structure.

    Args:
        yaml_data (dict or list): The YAML configuration content.
        feature_map (dict): Mapping of feature names to hierarchical paths.
        auxFeaturesAddedList (set): Set of already-added features to avoid duplication.
        aux_hierchical_prop (list): List of features matched hierarchically.
        mapped_key (str): Current mapped key being processed.
        aux_bool (bool): Flag used to manage array and depth recursion.
        depth_mapping (int, optional): Current recursion depth. Defaults to 0.

    Returns:
        dict or list: Transformed YAML with mapped feature names.
    """

    if isinstance(yaml_data, dict) and feature_map is not None:
        new_data = {}
        possible_type_data = ['asString', 'asNumber', 'asInteger']
        yaml_with_error_type = False
        #print(f"YAML DICT: {yaml_data}")
        for key, value in yaml_data.items():
            aux_nested = False ## boolean to determine if a property has a feature value
            aux_array = False ## boolean to determine if a property contains an array or is an array of features
            aux_maps = False ## marking to determine the maps
            aux_str_values = False
            aux_value_type = False
            aux_value_type_array = False
            aux_feat_empty = False
            aux_feat_null = False
            list_double_version = {'apps_v1', 'batch_v1', 'autoscaling_v1', 'autoscaling_v2', 'policy_v1', 'core_v1'}
            feature_nested = {} ## Structure to add the custom value to define the matching of the default values in the template
            feature_type_value = {}
            feature_map_key_value = {} ## batch.v1 ,autoscaling.v1 y autoscaling.v2, policy.v1, core.v1, core.v1.Binding
            feature_type_array = []
            feature_empty = {}
            feature_null = {}
            
            if isinstance(value, datetime): ## Checking if any of the values are of type Time RCF 3339
                value = value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
            if isinstance(key, str) and key == 'clusterName': ## It checks if any keys match 'clusterName' to omit the field directly. Prop does not validate in schema or doc
                continue
            # print(f"FEAUTRE MAP {feature_map}")
            for key_features, value_features in feature_map.items():
                
                # Normal logic for string type values, the value of the key is changed directly
                if isinstance(value_features, str) and value_features.endswith(key) and value_features not in auxFeaturesAddedList:

                    if key_features.count("_") == 2: # len(auxFeaturesAddedList) < 3 and
                        key = value_features
                        auxFeaturesAddedList.add(value_features)
                        aux_hierchical_prop.append(key_features)
                    elif key_features.count("_") == 3 and any(version in key_features for version in list_double_version): ## batch.v1 ,autoscaling.v1 y autoscaling.v2, policy.v1, core.v1, core.v1.Binding
                        key = value_features
                        auxFeaturesAddedList.add(value_features)
                        aux_hierchical_prop.append(key_features)
                    elif key_features.count("_") == 3:
                            aux_feature_before_insertion = value_features.rsplit("_", 1)[0]                    
                            if aux_feature_before_insertion in auxFeaturesAddedList:
                                key = value_features
                                auxFeaturesAddedList.add(value_features)                            
                                key = value_features
                                aux_hierchical_prop.append(key_features)
                    else:
                        if any(feature.endswith(key) for feature in auxFeaturesAddedList): ## and aux_feature_before_map not in auxFeaturesAddedList
                            aux_feature_before_insertion = value_features.rsplit("_", 1)[0]
                            feature_aux_depth = re.search(r"[A-Z].*", value_features) ## Regex to capture the group of the first match with an uppercase letter: kind always has the first uppercase letter
                            midle_depth = feature_aux_depth.group(0) ## It is the most ‘real’ feature depth, since it is only based on the properties from the kind that have been chained together.

                            if aux_bool and isinstance(mapped_key, str) and mapped_key and depth_mapping == midle_depth.count('_'): ## mapped_key is the father of the arr
                                mapped_key_before = mapped_key.rsplit("_", 1)[0]
                                if aux_bool and mapped_key.count("_") > 2 and mapped_key.count("_") < value_features.count("_") and mapped_key == aux_feature_before_insertion:
                                    key = value_features
                                    auxFeaturesAddedList.add(value_features)
                                    aux_hierchical_prop.append(key_features)
                                elif aux_bool and aux_feature_before_insertion == mapped_key_before: ## inserted with the depth
                                    key = value_features
                                    auxFeaturesAddedList.add(value_features)
                                    aux_hierchical_prop.append(key_features)
                                else:
                                    continue

                            if aux_feature_before_insertion in auxFeaturesAddedList and not aux_bool:
                                if depth_mapping == midle_depth.count('_'):
                                    if mapped_key.rsplit("_", 1)[0] == aux_feature_before_insertion:
                                        key = value_features
                                        auxFeaturesAddedList.add(value_features)
                                        aux_hierchical_prop.append(key_features)
                                elif mapped_key.count("_") > value_features.count("_"):
                                    continue
                            else:
                                continue
                        aux_feature_before_insertion = value_features.rsplit("_", 1)[0]
                        feature_aux_depth = re.search(r"[A-Z].*", value_features) ## Regex to capture the group of the first match with an uppercase letter: kind always has the first uppercase letter
                        midle_depth = feature_aux_depth.group(0)

                        if isinstance(mapped_key, str) and midle_depth.count("_") == depth_mapping:
                            aux_mapped_before = mapped_key.rsplit("_", 1)[0]
                            if mapped_key.count("_") > 2 and mapped_key.count("_") < value_features.count("_"):
                                feature_mapped_key_depth = re.search(r"[A-Z].*", mapped_key) ## Regex to capture the group of the first match with an uppercase letter: kind always has the first uppercase letter
                                mapped_depth = feature_mapped_key_depth.group(0)
                                if aux_feature_before_insertion == mapped_key:
                                    auxFeaturesAddedList.add(value_features)                          
                                    key = value_features
                                    aux_hierchical_prop.append(key_features)
                                else:
                                    continue
                            elif aux_mapped_before in value_features:
                                auxFeaturesAddedList.add(value_features)                          
                                key = value_features
                                aux_hierchical_prop.append(key_features)
                            else:
                                pass
                        else:
                            continue
                # Check arrays or other assigned features, treat dict type values by the type of structure they have. Modification with 'feature_type': 'array'.
                elif key_features.endswith(key) and isinstance(value_features, dict) and value_features.get("feature_type") == "array": ### Comprobando
                    aux_feature_before_insertion = value_features["feature"].rsplit("_", 1)[0]
                    feature_aux_depth = re.search(r"[A-Z].*", value_features["feature"]) ## Regex to capture the group of the first match with an uppercase letter: kind always has the first uppercase letter
                    midle_depth = feature_aux_depth.group(0)
                    mapped_key_before = mapped_key.rsplit("_", 1)[0]

                    if value_features["feature"] not in auxFeaturesAddedList and midle_depth.count("_") == depth_mapping and mapped_key_before in value_features ["feature"]:
                        if mapped_key.count("_") > 2 and mapped_key.count("_") < value_features["feature"].count("_"):
                            if mapped_key == aux_feature_before_insertion:
                                auxFeaturesAddedList.add(value_features["feature"])
                                key = value_features["feature"]
                                aux_hierchical_prop.append(key_features)
                                aux_array = True
                            else:
                                continue
                        auxFeaturesAddedList.add(value_features["feature"])
                        key = value_features["feature"]
                        aux_hierchical_prop.append(key_features)
                        aux_array = True
                elif isinstance(value, list) and key_features.endswith("StringValue") and  isinstance(value_features, str) and "StringValue" == value_features.split("_")[-1]: ## and value_features not in auxFeaturesAddedList
                    aux_key_last_before_map = value_features.split("_")[-2] ## The penultimate prop is obtained
                    aux_feature_before_insertion = value_features.rsplit("_", 1)[0] ## get the value feature minus the last insert

                    str_arr_values = []
                    if value and key == aux_feature_before_insertion and key_features.endswith(f"{aux_key_last_before_map}_StringValue"):### and value.get("key") in value_features  ## key coge los valores del feature mapeado ## key.endswith(aux_key_last_before_map)
                        for str_value in value:
                            str_arr_values.append({
                                value_features: str_value
                            })
                            auxFeaturesAddedList.add(value_features)
                            aux_hierchical_prop.append(key_features)
                        feature_str_value = str_arr_values
                        aux_str_values = True
                ## Seguir un tratamiento similar que con los mapas. Parte final del feature
                elif isinstance(value, list) and key_features.endswith("IntegerValue") and isinstance(value_features, str) and "IntegerValue" == value_features.split("_")[-1]:
                    aux_key_last_before_map = value_features.split("_")[-2]
                    aux_feature_before_insertion = value_features.rsplit("_", 1)[0] ## you get the value feature minus the last insert
                    values_arr_int = []
                    if value and key == aux_feature_before_insertion and key_features.endswith(f"{aux_key_last_before_map}_IntegerValue"):
                        for int_value in value:
                            values_arr_int.append({
                                value_features: int_value
                            })
                            auxFeaturesAddedList.add(value_features)
                            aux_hierchical_prop.append(key_features)
                        feature_str_value = values_arr_int
                        aux_str_values = True
                elif isinstance(value, dict) and key_features.endswith("StringValueAdditional") and isinstance(value_features, str) and "StringValueAdditional" == value_features.split("_")[-1]: ## and value_features not in auxFeaturesAddedList
                    aux_key_last_before_map = value_features.split("_")[-2]
                    aux_feature_before_insertion = value_features.rsplit("_", 1)[0] ## you get the value feature minus the last insert
                    str_values = []
                    if value and key == aux_feature_before_insertion and key_features.endswith(f"{aux_key_last_before_map}_StringValueAdditional"):
                        for str_key, str_value in value.items():
                            str_values.append({
                                value_features:f"{str_key}:{str_value}" 
                            })
                        auxFeaturesAddedList.add(value_features) ## Added by list check
                        aux_hierchical_prop.append(key_features)
                        feature_str_value = str_values
                        aux_str_values = True
                elif isinstance(value, dict) and key_features.endswith("KeyMap") and isinstance(value_features, str) and "KeyMap" == value_features.split("_")[-1] and value_features not in auxFeaturesAddedList:
                    aux_key_last_before_map = value_features.split("_")[-2]
                    aux_feature_before_map = value_features.rsplit("_", 1)[0]
                    key_values = []
                    if key.endswith(aux_key_last_before_map) and key_features.endswith(f"{aux_key_last_before_map}_KeyMap") and key == aux_feature_before_map: # Several checks are made to see if it is the right feature ## key obtains the values of the mapped feature
                        for map_key, map_value in value.items():
                            aux_feature_maps = value_features.rsplit("_", 1)[0] ## the feature is obtained by removing the last part to manually add the ValueMap
                            aux_feature_value = f"{aux_feature_maps}_ValueMap"
                            key_values.append({
                                value_features: map_key,
                                aux_feature_value: map_value
                            })
                            auxFeaturesAddedList.add(value_features)
                            auxFeaturesAddedList.add(aux_feature_value)
                        feature_map_key_value = key_values
                        aux_maps = True

                elif any(key_features.endswith(keyword) for keyword in possible_type_data) and isinstance(value_features, str) and value_features not in auxFeaturesAddedList and value_features.endswith(key_features): ## and any(keyword == value_features.split("_")[1] for keyword in possible_type_data) ### isinstance(value, str) and # and key_features.endswith(possible_type_data)
                    aux_key_last_before_value = value_features.split("_")[-2]
                    aux_value_last = value_features.rsplit("_", 1)[0]
                    if key == aux_value_last:
                        if isinstance(value, dict):
                            for key_item, value_item in value.items():
                                if value_features not in auxFeaturesAddedList:
                                    feature_entry = {}  # Dictionary for each feature
                                    # Validate that the value is consistent with the expected type of the feature
                                    if isinstance(value_item, str) and value_features.endswith("asString"):
                                        feature_entry[value_features] = f"{key_item}:{value_item}"
                                    elif isinstance(value_item, int) and value_features.endswith("asInteger"):
                                        feature_entry[value_features] = f"{key_item}:{value_item}"
                                    elif isinstance(value_item, float) and value_features.endswith("asNumber"): ## There may be cases that in the doc are defined as Number but in the Yaml you enter an Int and it is not detected
                                        ## Alternative to take into account the Integer and map them to Number if necessary. Vice versa for the other case.
                                        ## Add to condition: or (isinstance(value_item, int)
                                        # value_item = float(value_item) if isinstance(value_item, int) else value_item
                                        feature_entry[value_features] = f"{key_item}:{value_item}"
                                    if feature_entry:
                                        feature_type_array.append(feature_entry)
                        
                            if len(feature_type_array) > 0:
                                aux_value_type_array = True
                                auxFeaturesAddedList.add(value_features)
                                aux_hierchical_prop.append(key_features)
                        else:
                            if isinstance(value, str) and key_features.endswith(f"{aux_key_last_before_value}_asString"):
                                feature_type_value[value_features] = value
                                aux_value_type = True
                                auxFeaturesAddedList.add(value_features)
                                aux_hierchical_prop.append(key_features)
                            elif isinstance(value, int) and key_features.endswith(f"{aux_key_last_before_value}_asInteger"):
                                feature_type_value[value_features] = value
                                aux_value_type = True
                                auxFeaturesAddedList.add(value_features)
                                aux_hierchical_prop.append(key_features)
                            elif isinstance(value, float) and key_features.endswith(f"{aux_key_last_before_value}_asNumber"):
                                feature_type_value[value_features] = value
                                aux_value_type = True 
                                auxFeaturesAddedList.add(value_features)
                                aux_hierchical_prop.append(key_features)
                # Representation of the selected values, it is checked if any yaml value matches the last part of the characteristics in the list.
                elif isinstance(value_features, str) and value == value_features.split("_")[-1] and value_features not in auxFeaturesAddedList:
                    aux_key_last_before_value = value_features.split("_")[-2]
                    if value_features.endswith(key_features) and key.endswith(aux_key_last_before_value):
                        aux_nested = True
                        feature_nested[value_features] = aux_nested ## value: at the end the boolean value is left as the added feature is boolean as well
                        auxFeaturesAddedList.add(value_features)
                        aux_hierchical_prop.append(key_features)

                elif isinstance(value_features, str) and isinstance(value, dict) and not value and 'isEmpty02' == value_features.split("_")[-1] and value_features not in auxFeaturesAddedList:
                    aux_key_last_before_value = value_features.split("_")[-2]
                    aux_feature_before_insertion = value_features.rsplit("_", 1)[0] ## you get the value feature minus the last insert
                    if key == aux_feature_before_insertion and value_features.endswith(key_features) and key_features.endswith(f"{aux_key_last_before_value}_isEmpty02"): # and key_features.endswith(f"{aux_key_last_before_map}_StringValueAdditional"):
                        aux_feat_empty = True
                        feature_empty[value_features] = aux_feat_empty
                        auxFeaturesAddedList.add(value_features)
                        aux_hierchical_prop.append(key_features)
                    
                elif isinstance(value_features, str) and isinstance(value, dict) and not value and 'isEmpty' == value_features.split("_")[-1] and value_features not in auxFeaturesAddedList:
                    aux_key_last_before_value = value_features.split("_")[-2] ## 
                    aux_feature_before_insertion = value_features.rsplit("_", 1)[0] 
                    if key == aux_feature_before_insertion and value_features.endswith(key_features) and key_features.endswith(f"{aux_key_last_before_value}_isEmpty"): # and key_features.endswith(f"{aux_key_last_before_map}_StringValueAdditional"):
                        aux_feat_empty = True
                        feature_empty[value_features] = aux_feat_empty
                        auxFeaturesAddedList.add(value_features)
                        aux_hierchical_prop.append(key_features)

                elif isinstance(value_features, str) and value is None and 'isNull' == value_features.split("_")[-1] and value_features not in auxFeaturesAddedList:
                    aux_key_last_before_value = value_features.split("_")[-2]
                    aux_feature_before_insertion = value_features.rsplit("_", 1)[0]
                    if key == aux_feature_before_insertion and key_features.endswith(f"{aux_key_last_before_value}_isNull"):
                        aux_feat_null = True
                        feature_null[value_features] = aux_feat_null
                        auxFeaturesAddedList.add(value_features)
                        aux_hierchical_prop.append(key_features)
                # Representation of the selected values, it is checked if any yaml value matches the last part...
                # 
                elif key_features.endswith(key) and isinstance(value_features, dict) and value_features.get("feature_type") == "specialType" and not value_features.get("feature_type") == "array": # and value_features in auxFeaturesAddedList
                    auxFeaturesAddedList.add(value_features["feature"])
                    key = value_features["feature"]
                    aux_hierchical_prop.append(key_features)                    
                    #continue  # saltar hijos
                    ## elif value_features.get("feature_type") == "preserveUnknownFieldsX" and value_features not in auxFeaturesAddedList:
                """elif key_features.endswith(key) and isinstance(value_features, dict) and value_features.get("feature_type") == "specialTypeX" and not value_features.get("feature_type") == "array": # and value_features in auxFeaturesAddedList
                    auxFeaturesAddedList.add(value_features["feature"])
                    key = value_features["feature"]
                    aux_hierchical_prop.append(key_features)"""

            mapped_key = feature_map.get(key, key)
            aux_arr_key = None
            aux_array_bool = False
            aux_bool_dict = False ## unused
            if aux_nested:
                new_data[mapped_key] = feature_nested
            elif aux_feat_empty:
                new_data[mapped_key] = feature_empty
            elif aux_feat_null:
                new_data[mapped_key] = feature_null
            elif aux_str_values:
                new_data[mapped_key] = feature_str_value
            elif aux_value_type : 
                new_data[mapped_key] = feature_type_value
            elif aux_value_type_array:
                new_data[mapped_key] = feature_type_array
            elif aux_array or isinstance(value, list):
                if aux_maps: 
                    new_data[mapped_key] = feature_map_key_value
                elif value is None:
                    new_data[mapped_key] = []
                else:
                    aux_bool = aux_array
                    try:
                        new_data[mapped_key] = [apply_feature_mapping(item, feature_map, auxFeaturesAddedList.copy(), aux_hierchical_prop, mapped_key, aux_bool, depth_mapping+1) if isinstance(item, (dict, list)) else item for item in value] ## auxFeaturesAddedList: antes de la mod
                    except TypeError as te:
                        print(f"[ERROR DE TIPO] en key {mapped_key} (valor: {value}) - {te}")
                        yaml_with_error_type = True ## To mark yamls with error for revision. Not implemented already
                        with open("./error_log_mapping01Types.log", "w", encoding="utf-8") as error_log:
                            error_log.write(f"[ERROR DE TIPO] en key: {mapped_key}, Valor inválido: {value} - {te}\n")
            else:
                aux_bool = aux_array
                try:
                    new_data[mapped_key] = apply_feature_mapping(value, feature_map, auxFeaturesAddedList, aux_hierchical_prop, mapped_key, aux_bool, depth_mapping+1) if isinstance(value, (dict, list)) else value
                except TypeError as te:
                    yaml_with_error_type = True ## To mark yamls with error for revision. Not implemented already
                    with open("./error_log_mapping01Types.log", "w", encoding="utf-8") as error_log:
                        error_log.write(f"[ERROR DE TIPO] 2º else, en key: {mapped_key}, Valor inválido: {value} - {te}\n")
            ## Condition to omit the props without feature mapping
            if isinstance(key, str) and key not in feature_map and '_io_' not in key: ## all(not k.startswith(key + "_") for k in feature_map)
                #print(f"PROPS QUE NO SE MAPEAN: {key}    {value}")
                return True
        return new_data

    elif isinstance(yaml_data, list):
        print(f"YAML DATA ELIF {yaml_data}")
        return [apply_feature_mapping(item, feature_map, auxFeaturesAddedList, aux_hierchical_prop, mapped_key, aux_bool,depth_mapping+1) for item in yaml_data]


    return yaml_data

## route of the downloaded yamls: C:\projects\kubernetes_fm\scripts\download_manifests\YAMLs
# Read YAMLs and extract properties
## yaml_data_list = yaml_base_directory ## = iterate_all_buckets(yaml_base_directory, buckets)
yaml_data_list = read_yaml_files_from_directory(yaml_base_directory)

# Save folder output with JSON files
output_json_dir = '../resources/kyverno_policies_jsons' ## disallow-host-namespaces
#output_invalid_kinds_versions = './generateConfigs/outputs_no_validkinds_versions'
os.makedirs(output_json_dir, exist_ok=True)  # Create the folder if it does not exist
# Prepare structure for JSONs
#output_data = []
file_count = {}  # To handle multiple documents
# CSV file path
csv_file_path = '../resources/mapping_csv/kyverno_mapping_properties_features.csv'
csv_dict = load_features_csv(csv_file_path)

for filename, index, yaml_data, simple_props, hierarchical_props, key_value_pairs, root_info in yaml_data_list: ## yaml_data_list:    
    auxFeaturesAddedList = set()
    mapped_key = {}
    aux_hierchical = []
    aux_bool = False
    depth_mapping = 1 ## Depth take into account the number of the recursive stroke

    feature_map = search_features_in_csv(hierarchical_props, key_value_pairs, csv_dict)
    updated_config = apply_feature_mapping(yaml_data, feature_map, auxFeaturesAddedList, aux_hierchical, mapped_key, aux_bool, depth_mapping)
    base_filename = os.path.splitext(os.path.basename(filename))[0]

    yaml_entry = {
        "filename": f"{base_filename}.yaml",
        "apiVersion": root_info.get("apiVersion", "N/A"),
        "config": updated_config
    }
    
    if base_filename not in file_count:
        file_count[base_filename] = 0
    file_count[base_filename] += 1 
    
    json_filename = "01-Sin nombre"
    if file_count[base_filename] > 1:
        json_filename = f"{base_filename}_{file_count[base_filename]}.json"
    else:
        json_filename = f"{base_filename}.json" 
    
    print(f"Processing file: {json_filename}")
    output_json_path = os.path.normpath(os.path.join(output_json_dir, json_filename)) ## Adapts to OS output, standardize routing / OR.

    need_fix_type = contains_datetime(yaml_entry) ## flag to determine the content of the yaml entry types, if there is time, date or datetime, convert_all is called.
    if need_fix_type:
        yaml_entry = convert_all_datetimes(yaml_entry) ## Function to check if there is any value with datetime format in nested structures that may cause an error.
    try:
        with open(output_json_path, 'w', encoding='utf-8') as json_file:
            json.dump(yaml_entry, json_file, ensure_ascii=False, indent=4)
    except TypeError as e:
        with open("./errors_serialization.log", "a", encoding="utf-8") as err_log:
            err_log.write(f"{output_json_path} → {e}\n")
    print(f"Saved file: {output_json_path}\n")

print(f"All files have been processed and saved.")