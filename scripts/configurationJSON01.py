##https://raw.githubusercontent.com/flamapy/flamapy_fw/refs/heads/develop/flamapy/metamodels/configuration_metamodel/transformations/configuration_basic_reader.py
import json
import os
from flamapy.core.transformations.text_to_model import TextToModel

from copy import deepcopy
from itertools import product
from flamapy.metamodels.configuration_metamodel.models.configuration import Configuration
from flamapy.core.utils import file_exists
from flamapy.core.exceptions import ConfigurationNotFound

from pathlib import Path

class ConfigurationJSON(TextToModel):
    @staticmethod
    def get_source_extension() -> str:
        return 'json'

    def __init__(self, path: str) -> None:
        p = Path(path)
        if not p.is_absolute():
            base = Path(__file__).resolve().parent   # ...\scripts
            p = (base / p).resolve()
        self._path = str(p)    
    @staticmethod
    def qualify(fid: str, namespace: str = "") -> str:
        """Add the namespace if not present"""
        if not namespace:
            return fid
        return fid if fid.startswith(namespace) else f"{namespace}{fid}"
    
    def transform(self):
        """
        Transform the JSON configuration file into a list of Configuration objects.

        Soporta JSON combinado:
        {
          "policies": { "Disallow_hostPath": true, ... },
          "config": { "io_k8s_api_core_v1_Pod_spec_hostPID": true, ... }
        }
        """
        json_data = self.get_configuration_from_json(self._path)

        base_config = {}
        blocks = []

        # 1) Políticas activas (si existen en el JSON)
        policies = json_data.get('policies', {})
        for pname, enabled in policies.items():
            if enabled:
                # OJO: el nombre aquí debe coincidir con la feature del FM de Policies.
                base_config[pname] = True

        # 2) Config de K8s (aplicar namespace 'Kubernetes.' a TODAS las claves)
        config_node = json_data.get('config', {})
        # Si no hay 'config' (compatibilidad antigua), intenta usar raíz
        if not config_node and 'config' in json_data:
            config_node = json_data['config']

        # Extrae features calificadas con namespace
        self.extract_features(config_node, base_config, blocks, namespace='')#Pod.

        # 3) Generar combinaciones como antes
        configurations = self.generate_combinations(base_config, blocks)
        return configurations

    def extract_features(self, data, base_config, blocks, namespace: str = ""):
        """
        Recursively extract base feature values and blocks of alternative feature sets.
        Aplica 'namespace' a todas las claves que inserta (p.ej., 'Kubernetes.').
        """
        qualify = self.qualify  # alias local

        if isinstance(data, dict):
            for key, value in data.items():
                qkey = qualify(key, namespace)

                if isinstance(value, (str, int, float, bool)):
                    base_config[qkey] = value

                elif isinstance(value, dict):
                    base_config[qkey] = True
                    self.extract_features(value, base_config, blocks, namespace)

                elif isinstance(value, list):
                    if not value:
                        if key:
                            base_config[qkey] = True
                        continue

                    if all(isinstance(x, dict) for x in value):
                        combined_block = []
                        if len(value) > 0:
                            for item in value:
                                static = {}
                                lists = {}
                                aux_lists = {}
                                aux_combined_block = []

                                for k, v in item.items():
                                    qk = qualify(k, namespace)

                                    if isinstance(v, list):
                                        static[qk] = True
                                        extracted_values = []
                                        inner_aux_combined_block = []
                                        for it in v:
                                            if isinstance(it, dict):
                                                if len(it) == 1:
                                                    inner_value = list(it.values())[0]
                                                    inner_key = list(it.keys())[0]
                                                    q_inner_key = qualify(inner_key, namespace)
                                                    if isinstance(inner_value, (str, int, float, bool)):
                                                        extracted_values.append(inner_value)
                                                        aux_lists[q_inner_key] = extracted_values
                                                    elif isinstance(inner_value, dict):
                                                        inner_value[q_inner_key] = True
                                                        inner_aux_combined_block.append(inner_value)
                                                    else:
                                                        pass
                                                else:
                                                    flat_kv = self.flatten_primitive_kv(it, namespace)
                                                    inner_aux_combined_block.append(flat_kv)

                                            elif isinstance(it, (str, int, float, bool)):
                                                extracted_values.append(it)

                                        if extracted_values:
                                            lists = aux_lists
                                        if inner_aux_combined_block:
                                            blocks.append(inner_aux_combined_block)

                                    elif isinstance(v, (str, int, float, bool)):
                                        static[qk] = v

                                    elif isinstance(v, dict):
                                        self.extract_features(v, static, blocks, namespace)

                                if lists:
                                    keys = list(lists.keys())
                                    value_lists = [lists[k] for k in keys]

                                    for prod in product(*value_lists):
                                        merged = {k: prod[i] for i, k in enumerate(keys)}
                                        merged.update(static)
                                        combined_block.append(merged)
                                else:
                                    combined_block.append(static.copy())
                        else:
                            if isinstance(value, (str, int, float, bool)):
                                base_config[qkey] = value

                        blocks.append(combined_block)
                        base_config[qkey] = True

        elif isinstance(data, list):
            # No suele darse en tu estructura de raíz, pero lo dejamos por si acaso
            for item in data:
                if isinstance(item, dict):
                    self.extract_features(item, base_config, blocks, namespace)

    def generate_combinations(self, base_config, blocks, max_combinations = 10000):
        """
        Generate all possible combinations between blocks while including base configuration.
        """
        def backtrack(index, current, result):
            if len(result) >= max_combinations:
                return
            if index == len(blocks):
                merged = deepcopy(base_config)
                for partial in current:
                    merged.update(partial)
                result.append(Configuration(merged))
                return

            for option in blocks[index]:
                current.append(option)
                backtrack(index + 1, current, result)
                current.pop()

        result = []
        backtrack(0, [], result)
        return result

    def flatten_primitive_kv(self ,d, namespace: str = ""):
        """
        Flatten a dictionary to extract all primitive key-value pairs.
        Aplica 'namespace' a las claves insertadas.
        """
        qualify = self.qualify
        flat = {}
        for k, v in d.items():
            qk = qualify(k, namespace)
            if isinstance(v, (str, int, float, bool)):
                flat[qk] = v
            elif isinstance(v, dict):
                flat[qk] = True
                inner = self.flatten_primitive_kv(v, namespace)
                flat.update(inner)
        return flat

    def get_configuration_from_json(self, path: str) -> dict:

        p = Path(path)
        if not p.exists():
            # opcional: log útil para depurar
            # import logging; logging.error(f"No existe: {p}")
            raise ConfigurationNotFound

        with p.open('r', encoding='utf-8') as jsonfile:
            return json.load(jsonfile)

        
if __name__ == '__main__':

    #path_json = '../resources/kyverno_policies_jsons/disallow-host-namespaces.json'
    path_json = '../resources/valid_yamls/01-Pod-Annotation.json'

    # Imprimir todas las configuraciones generadas    
    configuration_reader = ConfigurationJSON(path_json)
    configurations = configuration_reader.transform()

    print(f"Configuraciones que hay:    {len(configurations)}")
    for i, config in enumerate(configurations):
        configuration = configuration_reader.transform()
        print(f'Configuration {i+1}: {config.elements}') ##{config.elements"""