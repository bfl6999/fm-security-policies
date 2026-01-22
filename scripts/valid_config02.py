# This script checks whether a configuration (given as a list of keys) is valid according to a feature model.

from flamapy.metamodels.configuration_metamodel.models import Configuration
from flamapy.metamodels.fm_metamodel.models import FeatureModel, Feature
from flamapy.metamodels.fm_metamodel.transformations import UVLReader, FlatFM
from flamapy.metamodels.pysat_metamodel.models import PySATModel
from flamapy.metamodels.pysat_metamodel.transformations import FmToPysat
from flamapy.metamodels.pysat_metamodel.operations import (PySATSatisfiable, PySATSatisfiableConfiguration)

from pathlib import Path
import os

import logging
import contextlib, io
from scripts.configurationJSON01 import ConfigurationJSON ## clase Reader JSON
#from configurationJSON01 import ConfigurationJSON ## clase Reader JSON
from scripts._inference_policy import extract_policy_kinds_from_constraints, infer_policies_from_kind
import time  # Libreria para calcular los tiempos de procesamiento

#FM_PATH = "../variability_model/kyverno_clusterpolicy_test2.uvl"
#FM_PATH = "../variability_model/policies_template/policy_structure01.uvl"

HERE   = Path(__file__).resolve().parent
ROOT   = HERE.parent
MODELS = ROOT / "variability_model" / "policies_template"
RES    = ROOT / "resources"

UVL_PATH = MODELS / "policy_structure03.uvl"
# usar str(UVL_PATH) si la librería lo exige
path_json = RES / "valid_yamls" / ".rc-template.json" ##1-metallb5_2_Test01  1-metallb5_2_Test02-Invalid,test-require-run-as-nonroot_1.json,
VALIDATE_ONLY_FIRST_CONFIG = True ## Use unit or total validation version

def get_all_parents(feature: Feature) -> list[str]:
    parent = feature.get_parent()
    return [] if parent is None  else [parent.name] + get_all_parents(parent)


def get_all_mandatory_children(feature: Feature) -> list[str]:
    children = []
    for child in feature.get_children():
        if child.is_mandatory():
            children.append(child.name)
            children.extend(get_all_mandatory_children(child))
    return children


def complete_configuration(configuration: Configuration, fm_model: FeatureModel) -> Configuration:
    """Given a partial configuration completes it by adding the parent's features and
    children's features that must be included because of the tree relationships of the 
    provided FM model."""
    configs_elements = dict(configuration.elements)
    for element in configuration.get_selected_elements():
        feature = fm_model.get_feature_by_name(element)
        if feature is None:
            raise Exception(f'Error: the element "{element}" is not present in the FM model.')
        children = {child: True for child in get_all_mandatory_children(feature)}
        parents = {parent: True for parent in get_all_parents(feature)}
        for parent in parents:
            parent_feature = fm_model.get_feature_by_name(parent)
            parent_children = get_all_mandatory_children(parent_feature)
            children.update({child: True for child in parent_children})
        configs_elements.update(children)
        configs_elements.update(parents)
    return Configuration(configs_elements)

def valid_config_version_json(configuration_json: Configuration, fm_model: FeatureModel, sat_model: PySATModel, sat_features: set[str], auto_policies) -> bool: ## Instead of passing it (configuration: list[str] we pass the JSON list we generated in the JSON Conf suffix_map: dict[str, list[str]],
    """
    Check if a configuration is valid (satisfiable) according to the SAT model.

    Args:
        configuration_json (Configuration): Configuration to validate.
        fm_model (FeatureModel): The feature model.
        sat_model (PySATModel): The SAT-based feature model.

    Returns:
        tuple: (bool indicating validity, list of selected feature names)
    """
    # 1) EXTRAER constraints → mapa {policy: kinds}
    #constraint_kinds_map = extract_policy_kinds_from_constraints(UVL_PATH)

    # 2) detectar políticas aplicables
    #auto_policies = infer_policies_from_kind(configuration_json.elements, constraint_kinds_map)

    # 3) Integrarlas en la propia config (NO en el archivo JSON)
    for policy in auto_policies: ### In testing
        configuration_json.elements[policy] = True

    config = complete_configuration(configuration_json, fm_model)
    config.set_full(True)
    #print(f"PRINT CONFIG {config}")

    #sat_features = set(sat_model.variables.keys())
    adjusted = {}
    match_cache = {}
    start_mathing_features = time.time()
    for k, v in config.elements.items():
        if k in match_cache:
            matches = match_cache[k]
        else:
            matches = [
                f for f in sat_features
                if f.endswith("_" + k) or f.endswith("_n1_" + k)
            ]
            match_cache[k] = matches

        if matches:
            adjusted[matches[0]] = bool(v)
        else:
            adjusted[k] = bool(v)
            
    end_mathing_features = time.time()
    matching_time = round(end_mathing_features - start_mathing_features, 4)
    print(f"Tiempo de coincidencias de la configuracion {matching_time}")

    # Crear nueva configuración normalizada
    config = Configuration(adjusted)

    start_satisfiable_model = time.time()  # Start of validation time
    satisfiable_op = PySATSatisfiableConfiguration()
    end_satisfiable_model = time.time()
    satisfiable_time = round(end_satisfiable_model - start_satisfiable_model, 4)
    print(f"Tiempo de satisfacer la config  {satisfiable_time}")
    satisfiable_op.set_configuration(config)
    return satisfiable_op.execute(sat_model).get_result(), config.get_selected_elements()


#def valid_config_version_json(configuration_json: Configuration, fm_model: FeatureModel, sat_model: PySATModel, sat_features: set[str]) -> bool: ## Instead of passing it (configuration: list[str] we pass the JSON list we generated in the JSON Conf suffix_map: dict[str, list[str]],
    """
    Check if a configuration is valid (satisfiable) according to the SAT model.

    Args:
        configuration_json (Configuration): Configuration to validate.
        fm_model (FeatureModel): The feature model.
        sat_model (PySATModel): The SAT-based feature model.

    Returns:
        tuple: (bool indicating validity, list of selected feature names)
    """
    """# 1) EXTRAER constraints → mapa {policy: kinds}
    constraint_kinds_map = extract_policy_kinds_from_constraints(UVL_PATH)

    # 2) detectar políticas aplicables
    auto_policies = infer_policies_from_kind(configuration_json.elements, constraint_kinds_map)

    # 3) Integrarlas en la propia config (NO en el archivo JSON)
    for policy in auto_policies: ### In testing
        configuration_json.elements[policy] = True

    config = complete_configuration(configuration_json, fm_model)
    config.set_full(True)
    #print(f"PRINT CONFIG {config}")

    #sat_features = set(sat_model.variables.keys())
    adjusted = {}
    match_cache = {}
    start_mathing_features = time.time()
    for k, v in config.elements.items():
        if k in match_cache:
            matches = match_cache[k]
        else:
            matches = [
                f for f in sat_features
                if f.endswith("_" + k) or f.endswith("_n1_" + k)
            ]
            match_cache[k] = matches

        if matches:
            adjusted[matches[0]] = bool(v)
        else:
            adjusted[k] = bool(v)
            
    end_mathing_features = time.time()
    matching_time = round(end_mathing_features - start_mathing_features, 4)
    print(f"Tiempo de coincidencias de la configuracion {matching_time}")

    # Crear nueva configuración normalizada
    config = Configuration(adjusted)

    start_satisfiable_model = time.time()  # Start of validation time
    satisfiable_op = PySATSatisfiableConfiguration()
    end_satisfiable_model = time.time()
    satisfiable_time = round(end_satisfiable_model - start_satisfiable_model, 4)
    print(f"Tiempo de satisfacer la config  {satisfiable_time}")
    satisfiable_op.set_configuration(config)
    return satisfiable_op.execute(sat_model).get_result(), config.get_selected_elements()"""

def inizialize_model(model_path):
    fm_model = UVLReader(model_path).transform()
    sat_model = FmToPysat(fm_model).transform()
    return fm_model, sat_model

def main(configuration, fm_model, sat_model, cardinality):
    error = ''
    try:
        valid, complete_config = valid_config_version_json(configuration, fm_model, sat_model) ## valid_config
        # If the configuration is not valid but contains cardinality, we consider it valid (we do this because within a feature with a cardinality 
        # of more than 1, there could be an alternative feature, choosing one of the options each time and causing a validation error).
        if not valid and cardinality == True:
            valid = True
    except Exception as e:
        valid = False
        error = str(e)
    return valid, error, complete_config


if __name__ == '__main__':
    # You need the model in SAT
    fm_model = UVLReader(str(UVL_PATH)).transform()
    #sat_model = FmToPysat(fm_model).transform()
    ## Pre evaluation of sectioned model. Depends of section Policies
    start_startup_model = time.time()  # Start of validation time
    
    flat_fm_op = FlatFM(fm_model)
    flat_fm_op.set_maintain_namespaces(False)  # False para quitar el prefijo del import, con True se mantiene.
    flat_fm = flat_fm_op.transform()
    

    # Baja el nivel global
    logging.basicConfig(level=logging.ERROR)

    for name in (
        'flamapy',
        'flamapy.metamodels',
        'flamapy.metamodels.fm_metamodel',
        'flamapy.metamodels.pysat_metamodel',
    ):
        logging.getLogger(name).setLevel(logging.ERROR)

    print("SE LLEGA HASTA AQUI")
    
    silent = io.StringIO()
    with contextlib.redirect_stdout(silent):
        sat_model = FmToPysat(flat_fm).transform()
    # 3) Precalcular set de features SAT (y si quieres, índice de sufijos)
    SAT_FEATURES = set(sat_model.variables.keys())
    end_startup_model = time.time()  # End of validation time
    validation_time = round(end_startup_model - start_startup_model, 4)

    print(f"Tiempo de start config of FMs   {validation_time}")
    
    #sat_model = FmToPysat(flat_fm).transform()

    # Check if the model is valid
    ##### Omited
    ##valid = PySATSatisfiable().execute(sat_model).get_result()
    ##print("SE QUEDA PILLADO AQUI 3")
    ##print(f'Valid?: {valid}')
    #path_json = '../resources/kyverno_policies_jsons/disallow-host-ports.json'
    #path_json = '../resources/valid_yamls/1-metallb5_2_Test01.json'

    configuration_reader = ConfigurationJSON(str(path_json))
    configurations = configuration_reader.transform()
    print(f"Configuraciones que hay:    {len(configurations)}")
    ##elements = listJson
    """for i, config in enumerate(configurations):
        configuration = configuration_reader.transform()
        print(f'Configuration {i+1}: {config.elements}')"""

    print(f"#########     VALIDACION")
    
    print("FEATURES en SAT model:") ## Uncoment for print sat features in output file
    
    out_path = os.path.join(os.path.dirname(__file__), "sat_features_dump.txt")
    with open(out_path, "w", encoding="utf-8") as f_out:
        f_out.write("FEATURES en SAT model:\n")
        for f in sat_model.variables.keys():
            f_out.write(f"- {f}\n")
            
    print(f"[INFO] Se ha guardado la lista completa de features en: {out_path}")

    """for f in sat_model.variables.keys():
        print("-", f)"""
    #suffix_map = build_suffix_index(SAT_FEATURES)
    if VALIDATE_ONLY_FIRST_CONFIG:

        config = configurations[0] ## The first configuration is obtained
        start_validation_time = time.time()  # Start of validation time
        valid, complete_config = valid_config_version_json(config, flat_fm, sat_model, SAT_FEATURES)
        end_validation_time = time.time()  # End of validation time

        validation_time = round(end_validation_time - start_validation_time, 4)
        print(f"CONF VALID? {valid} {validation_time} \n{config.elements}")
    else:
        for i, config in enumerate(configurations):
            valid, complete_config = valid_config_version_json(config, flat_fm, sat_model)
            print(f"CONF VALID? {valid}")
            #print(f"Config complet {complete_config}")
            print(f'Configuration {i+1}: {config.elements}  {valid}')