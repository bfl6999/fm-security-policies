import csv
from collections import defaultdict

import re
import yaml

from tools_extraction.extract_policies_general import (
    clean_description,
    get_base_prefix,
    load_feature_dict,
    load_kinds_prefix_mapping,
    normalize_kind_name
)

def build_field_map(csv_path):
    field_map = defaultdict(list)

    with open(csv_path) as f:
        reader = csv.DictReader(f)

        for row in reader:
            # Ex: Detect feature using the FM mapping
            semantic_key = row["feature_name"]  # p.ej.: securityContext.capabilities.add // We need to take account the rest of the part of the features using the comments Kinds
            field_map[semantic_key].append(row["feature_path"])

    return field_map

def normalize_rego_path(rego_path):
    # Eliminamos el prefijo 'container.' para que no interfiera con la búsqueda
    if rego_path.startswith("container."):
        return rego_path.replace("container.", "")
    return rego_path

def find_uvl_path_for_rego(kind, rego_path, feature_dict, kind_map): ## feature_dictç
    #print(f"Features dictss {feature_dict}")
    #kind_cap = kind.capitalize()
    real_kind = normalize_kind_name(kind, kind_map)
    #rego_key = rego_path.replace(".", "_")  # container.securityContext.capabilities.add
    rego_key = normalize_rego_path(rego_path).replace(".", "_")

    # Buscar las coincidencias en el diccionario
    candidates = []

    # 1. Definimos los "ámbitos" que nos interesan buscar
    # 'default' es para propiedades del Pod (hostPID, etc.)
    # Los otros son para propiedades de contenedores
    scope_buckets = {
        "default": [],
        "containers": [],
        "initContainers": [],
        "ephemeralContainers": []
    }

    markers = {
        "containers": "_containers_",
        "initContainers": "_initContainers_",
        "ephemeralContainers": "_ephemeralContainers_"
    }
    found_any = False
# 2. Búsqueda y Clasificación
    for midle, row in feature_dict.items():
        # Filtro básico: Debe ser del Kind correcto y contener la clave Rego
        if midle.startswith(real_kind + "_") and rego_key in midle:
            found_any = True
            
            # Clasificamos en el bucket correcto
            assigned_scope = "default"
            for scope, marker in markers.items():
                if marker in midle:
                    assigned_scope = scope
                    break
            
            scope_buckets[assigned_scope].append(row)

    if not found_any:
        return [] # Devolvemos lista vacía en lugar de None

    results = []

    # 3. Selección de Ganadores (Fan-Out)
    
    # Verificamos si encontramos propiedades de contenedores
    container_matches = any(scope_buckets[k] for k in markers)

    if container_matches:
        # CASO A: Es una propiedad de contenedor (ej: securityContext, image, env)
        # Devolvemos el mejor candidato de CADA tipo de contenedor que exista
        for scope in markers:
            candidates = scope_buckets[scope]
            if candidates:
                # Elegimos la más específica (path más largo) dentro de su categoría
                best = max(candidates, key=lambda r: len(r["Midle"]))
                is_list = (best["Value"] == "-")
                results.append((best["Feature"], is_list, best["Value"]))
    else:
        # CASO B: Es una propiedad global del Pod (ej: hostPID, restartPolicy)
        # Solo miramos el bucket default
        candidates = scope_buckets["default"]
        if candidates:
            best = max(candidates, key=lambda r: len(r["Midle"]))
            is_list = (best["Value"] == "-")
            results.append((best["Feature"], is_list, best["Value"]))

    return results
    

def extract_metadata_from_rego(rego_text):
    lines = rego_text.splitlines()
    capture = False
    meta_lines = []

    for line in lines:
        stripped = line.strip()

        # Start metadata
        if stripped.startswith("# METADATA"):
            capture = True
            continue

        # Stop when metadata ends
        if capture and not stripped.startswith("#"):
            break

        # Collect metadata commented lines preserving indentation
        if capture and line.lstrip().startswith("#"):
            # Find index of '#' in original line to preserve indent
            idx = line.index("#")
            yaml_part = line[idx+1:]   # drop '#' but *not* indentation after it
            meta_lines.append(yaml_part.rstrip())

    if not meta_lines:
        return {}

    # Join and remove first leading blank if present
    meta_text = "\n".join(meta_lines).lstrip("\n")

    try:
        meta_yaml = yaml.safe_load(meta_text)
        if not isinstance(meta_yaml, dict):
            return {}
    except Exception as e:
        print("YAML ERROR:", e)
        print("YAML TEXT:\n", meta_text)
        return {}

    # Handle custom nested or flattened
    custom = meta_yaml.get("custom") or {}
    #print("Custom:", custom)
    if not isinstance(custom, dict):
        custom = {}

    # extract types
    kinds = []
    selectors = (
        custom.get("input", {}).get("selector", [])
        if "input" in custom
        else []
    )

    for sel in selectors:
        subtypes = sel.get("subtypes", [])
        for item in subtypes:
            if isinstance(item, dict) and "kind" in item:
                kinds.append(item["kind"].lower())

    return {
        "title": meta_yaml.get("title", ""),
        "description": meta_yaml.get("description", ""),
        "severity": custom.get("severity", ""),
        "id": custom.get("id", ""),
        "short_code": custom.get("short_code", ""),
        "recommended_action": custom.get("recommended_action", ""),
        "kinds": sorted(set(kinds)),
    }


def extract_conditions_from_rego(rego_text, recommended_action=""):
    # Example match: container.securityContext.capabilities.add[_] == "SYS_MODULE"
    pat_str = re.compile(r'(\S+?)\s*(==|!=)\s*"([^"]+)"')
    matches_str = pat_str.findall(rego_text)
    #print(f"MATCHES NONE {matches_str}")
    conditions = []
    cond_text = recommended_action.replace('"', "'")
    
    for field, op, value in matches_str:
        # normalize container.securityContext.capabilities.add[_]
        field = field.replace("[_]", "")
        conditions.append({
            "field": field,
            "operator": op,
            "value": value
        })
    
    # Extraer propiedades desde texto si no hay condiciones detectadas
    if not conditions and recommended_action:
        #print(f"reccomended {recommended_action}")
        cond_text = recommended_action.replace('"', "'")
        prop_pat = re.findall(r"'(spec[.\w\[\]]+)'", cond_text)
        for prop in prop_pat:
            # Si el texto dice "to true" => interpretamos que queremos != true
            val = "true" if "true" in cond_text.lower() else "false"
            conditions.append({"field": prop, "operator": "==", "value": val})

        prop_pat_container = re.findall(r"'(containers[.\w\[\]]+)'", cond_text)
        #prop_pat_container = re.findall(r"['\"](containers(?:\[\]\.|[\w\.\[\]]+)*)['\"]", cond_text)

        #print(f"Prop pat  DUPLICADO EN RECCOMENDED  {prop_pat_container}")
        if prop_pat_container and ('>' not in cond_text and '<' not in cond_text):
            for prop01 in prop_pat_container:
                # Si el texto dice "to true" => interpretamos que queremos != true
                val = "true" if "true" in cond_text.lower() else "false"
                field_name = prop01.replace("containers[].","").replace("containers[*].","")
                conditions.append({"field": field_name, "operator": "==", "value": val})

    # Regex 3: Para números enteros (ej: ... <= 10000)
    # \d+ captura uno o más dígitos
    
    #pat_num = re.compile(r'(\S+?)\s*(==|!=|<=|>=|<|>)\s*(\d+)\b')
    pat_num = re.compile(r"'(containers[.\w\[\]\*]+)'[^<>=]+(==|!=|<=|>=|<|>)\s*(\d+)")
    matches_num = pat_num.findall(cond_text)
    if matches_num:
        for field, op, value in matches_num:
                val = ">" if ">" in cond_text.lower() else "<"
                field_name = field.replace("containers[].","").replace("containers[*].","")
                conditions.append({"field": field_name, "operator": val, "value": value, # El valor es un string '10000'
                })

    # Si aún no hay condiciones, buscar rutas de 'msg' en el código
    if not conditions:
        msg_pat = re.findall(r"'(spec[.\w\[\]]+)'", rego_text)
        print(f"Prop pat    {msg_pat}")
        for prop in msg_pat:
            conditions.append({"field": prop, "operator": "==", "value": "true"})

    # Detect hostPort usage: ports[_].hostPort
    hostport_pat = re.compile(r'\bports\[_?\]\.hostPort\b|\bports\[\*\]\.hostPort\b')

    if hostport_pat.search(rego_text):
        conditions.append({
            "field": "container.ports.hostPort",
            "operator": "EXISTS",
            "value": ""  # not needed
        })

    return conditions

def parse_rego_policy(path):
    with open(path, "r", encoding="utf-8") as f:
        rego = f.read()

    metadata = extract_metadata_from_rego(rego)
    conds = extract_conditions_from_rego(rego, metadata["recommended_action"])

    return {
        "metadata": metadata,
        "conditions": conds
    }


def detect_intent(recommended_action, value):
    """
    Intenta adivinar si es una Prohibición (Forbidden) o un Requerimiento (Required)
    basado en el texto para desempatar casos dudosos.
    """
    #text = (meta.get("recommended_action", "") + " " + meta.get("short_code", "")).lower()
    
    # Palabras clave de Prohibición
    if any(x in recommended_action.lower() for x in ["do not set", "false", "disallow", "no-", "drop", "to 'false'"]):
        return "PROHIBITION" # Esperamos !Feature
    
    # Palabras clave de Requerimiento
    if any(x in recommended_action.lower() for x in ["to true", "require", "must be", "enable"]):
        return "REQUIREMENT" # Esperamos Feature
    
    return "UNKNOWN"

def rego_policy_to_uvl(policy, field_map, kind_map):

    # Campos que queremos extraer
    meta = policy["metadata"]
    cond = policy["conditions"][0]  # Asumimos 1 condición base por ahora
    recommended_action = meta['recommended_action']
    # --- tool ---
    tool = "trivy"
    # --- feature name ---
    feature_name = meta["short_code"].replace("-", "_")
    # --- severity ---
    severity = meta.get("severity", "").lower()
    # --- nombre original ---
    name = meta.get("short_code", "")
    # --- Descripcion ---
    doc = clean_description(meta.get("description", "")).replace("'", "")
    # --- Kinds de la politica ---
    kinds_list = sorted(set(k for k in meta.get("kinds", [])))
    kinds_value = ", ".join(kinds_list)
    # # --- Source of implementation ---
    raw_source = 'OPA-Rego'
    # --- Extraer campo canonical desde conditions ---
    rego_field = cond["field"].replace(".", "_")
    rego_field_key = normalize_rego_path(rego_field)
    # # --- Accion recomendada ---
    clean_recommended_action_rego = clean_description(recommended_action)
    # --- Construcción del bloque UVL ---
    attrs = []
    attrs.append(f"tool '{tool}'")
    if severity:
        attrs.append(f"severity '{severity}'")
    if name:
        attrs.append(f"name '{name}'")
    if rego_field_key:
        attrs.append(f"fields '{rego_field_key}'")
    if kinds_value:
        attrs.append(f"kinds '{kinds_value}'")
    #if category:
    #    attrs.append(f"category '{category}'")
    if doc:
        attrs.append(f"doc '{doc}'")
    if clean_recommended_action_rego:
        attrs.append(f"RecommendedAction '{clean_recommended_action_rego}'")
    if raw_source:
        attrs.append(f"raw_source '{raw_source}'")

    feature_block = f"{feature_name} {{" + ", ".join(attrs) + "}"
    #feature_block = f"""{feature_name} {{doc '{clean_description_rego}', severity '{meta['severity'].lower()}', tool 'OPA', recommended '{clean_recommended_action_rego}'}}"""

    field = cond["field"]
    operator = cond["operator"]
    value = cond["value"]
    if '.' in value:
        value = value.replace('.', '_') 
    # Convert Rego container path to canonical lookup key
    
    #print(f"field key   {field}")
    field_key = normalize_rego_path(field)
    
    """# Feature name sanitized
    feature_name = meta["short_code"].replace("-", "_") # meta["id"] + "_" + 
    ## To Do: clean the descriptions
    clean_description_rego = clean_description(meta['description'])
    clean_recommended_action_rego = clean_description(meta['recommended_action'])"""
    #feature_block = f"""{feature_name} {{doc '{clean_description_rego}', severity '{meta['severity'].lower()}', tool 'OPA', recommended '{clean_recommended_action_rego}'}}"""
    
    constraint_parts = [] ## Added only candidate crossed
    kinds = meta.get("kinds", [])
    intent = detect_intent(recommended_action, value)

    if kinds:
        for kind in meta["kinds"]:
            #print(f"Kind    {kind}")
            found_features = find_uvl_path_for_rego(kind, field_key, field_map, kind_map)
    
            if not found_features:
                print(f"[WARNING] No UVL mapping for field '{field_key}' in kind '{kind}'")
                continue
            kind_cap = get_base_prefix(kind.capitalize()) ### Import of objects, adjust like the generate_uvl_policies -- If 

            # Operador UVL traducido
            #print(f"operator    {operator}  {value}")
            for feature, is_list, value_field in found_features:
                if operator == "==" and not value.lower() == "true" and not value.lower() == "false":
                    expr = f"{kind_cap}.{feature} != '{value}'"
                elif operator == "!=" and not value.lower() == "true":
                    expr = f"{kind_cap}.{feature} == '{value}'"
                elif intent == "PROHIBITION":
                    expr = f"!{kind_cap}.{feature}"
                elif intent == "REQUIREMENT":
                    expr = f"{kind_cap}.{feature}"
                elif operator == ">": ## Case runs_with_UID_le_10000
                    expr = f"{kind_cap}.{feature} > {value}"            
                else:
                    expr = f"UNSUPPORTED_OPERATOR({operator})"
                if expr:
                    constraint_parts.append(expr)
    # --- Case 2: No kinds → buscar por feature global --- Se asigna Pod por defecto
    else:
        print("[INFO] Policy without explicit kinds. Searching by property only...")
        matches = []
        kind = 'Pod' ## Kind por defecto asignado para automountServiceAccountToken
        for midle, row in field_map.items():
            # Buscar coincidencias con el nombre de la propiedad
            if field_key.replace(".", "_") in midle and midle.startswith(kind):
                matches.append(row)
        print(f"MATCHES {matches}")
        if not matches:
            print(f"[WARNING] No features matched for property '{field_key}'")
            return None

        for row in matches:
            feature = row["Feature"]
            aux = re.search(r"[A-Z].*", feature)
            kind = aux.group(0).split("_")[0]
            kind_cap = get_base_prefix(kind.capitalize()) ## Added the matching Kind
            if operator == "==" and value.lower() in ("true", "false"):
                expr = f"!{kind}.{feature}" if value.lower() == "true" else f"{feature}"
            elif operator == "==" and value not in ("true", "false"):
                expr = f"{kind}.{feature} != '{value}'"
            elif operator == "!=" and value.lower() == "true":
                expr = f"{kind}.{feature}"
            elif operator == ">":
                expr = f"{kind}.{feature} > {value}"
            else:
                expr = f"UNSUPPORTED_OPERATOR({operator})"
            constraint_parts.append(expr)

    #print(f"Const parts {constraint_parts}")
    if not constraint_parts:
        print("[ERROR] No constraints generated, skipping policy")
        return None

    # Join con AND ya que todos los kinds deben cumplir la policy
    constraint = f"{feature_name} => " + " & ".join(constraint_parts)
    #print(f"CONSTRAINT: {constraint}")
    return feature_block, constraint



# DEMO USAGE
if __name__ == "__main__":
    ## ../resources/kyverno_policies_yamls
    field_map = load_feature_dict("../resources/mapping_csv/kubernetes_mapping_properties_features.csv")
    #data = parse_rego_policy("../resources/kyverno_policies_yamls/OPA_Policies/SYS_ADMIN_capability.rego")
    data = parse_rego_policy("../resources/OPA_Policies/protecting_pod_service_account_tokens.rego")

    kind_map = load_kinds_prefix_mapping("../resources/mapping_csv/kubernetes_kinds_versions_detected.csv")

    # Generate UVL feature block and constraint
    feature_block, constraint = rego_policy_to_uvl(data, field_map, kind_map)

    print(f"######PRUEBAS")

    if feature_block and constraint:
        print("\nFeature Block:\n", feature_block)
        print("\nConstraint:\n", constraint)
    else:
        print("No valid UVL mapping found.")