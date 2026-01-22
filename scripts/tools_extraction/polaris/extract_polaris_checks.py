# -*- coding: utf-8 -*-

import os
import csv
import yaml
import re

from tools_extraction.extract_policies_general import clean_description
from tools_extraction.polaris.definitions_objects import CONTROLLER_KINDS

# =========================
# Carga de FM y Kinds
# =========================

def load_feature_dict_polaris(csv_file):
    """
    Carga Midle -> fila completa del CSV de mapping K8s.
    """
    feature_dict = {}
    with open(csv_file, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            feature_dict[row["Feature"]] = row
    return feature_dict


def load_kinds_prefix_mapping(csv_file):
    """
    Carga {Kind -> Prefix}. Ahora mismo no lo usamos mucho porque
    Feature ya viene con el prefijo completo, pero lo dejamos
    por si quieres hacer fallbacks o debug.
    """
    # Definimos qué preferimos (puedes ajustar el orden)
    VERSION_PRIORITY = ["v1", "v2", "v1beta1", "v1beta2", "v2beta1"]
    
    # Paso 1: Agrupar todas las opciones
    raw_map = {}
    with open(csv_file, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            kind = row["Kind"]
            prefix = row.get("Prefix") or row.get("Version") or ""
            version = row.get("Version", "")

            if kind not in raw_map:
                raw_map[kind] = []
            
            # Guardamos la info completa
            raw_map[kind].append({"prefix": prefix, "version": version})

    # Paso 2: Elegir el ganador para cada Kind
    final_kind_map = {}
    
    for kind, candidates in raw_map.items():
        # Función para ordenar: Si la versión está en nuestra lista, usa su índice (0 es mejor).
        # Si no está (ej. 'extensions'), ponle un valor alto (99) para que quede al final.
        candidates.sort(key=lambda x: VERSION_PRIORITY.index(x["version"])
                        if x["version"] in VERSION_PRIORITY else 99)
        
        # El primero de la lista ordenada es el mejor
        best_candidate = candidates[0]
        final_kind_map[kind] = best_candidate["prefix"]

    return final_kind_map
    #return kind_map

def resolve_ast_ref(ast, ref: str):
    """
    Resuelve un $ref del estilo "#/$defs/x/y/z" dentro del mismo AST.
    """
    if not ref.startswith("#/"):
        return None

    path = ref[2:].split("/")  # remove "#/"
    node = ast
    for key in path:
        if not isinstance(node, dict) or key not in node:
            return None
        node = node[key]
    return node
# =========================
# Helpers de Polaris
# =========================

def normalize_schema_string(schema_string: str) -> str:
    """
    Limpia plantillas Go {{ ... }} de schemaString y deja YAML lo más
    cercano posible a un JSON Schema válido.
    """
    # Elimina bloques de comentarios {{/* ... */}}
    cleaned = re.sub(r"\{\{/\*.*?\*/\}\}", "", schema_string, flags=re.DOTALL)

    # Elimina líneas/fragmentos con {{ ... }}
    cleaned = re.sub(r"\{\{.*?\}\}", "", cleaned, flags=re.DOTALL)

    # Limpia líneas vacías y espacios sobrantes
    cleaned = "\n".join(
        line.rstrip()
        for line in cleaned.splitlines()
        if line.strip()
    )
    return cleaned


def schema_string_to_ast(schema_string: str):
    """
    Convierte un schemaString Polaris (tras limpiar Go templates) en
    un AST (dict) de JSON Schema usando yaml.safe_load.
    """
    try:
        cleaned = normalize_schema_string(schema_string)
        if not cleaned.strip():
            return None
        ast = yaml.safe_load(cleaned)
        if not isinstance(ast, dict):
            return None
        return ast
    except Exception as e:
        print(f"[ERROR] No se pudo parsear schemaString: {e}")
        return None
    

def clean_cap_pattern(pattern: str) -> str:
    """
    Limpia patrones tipo '^(?i)NET_ADMIN$' -> 'NET_ADMIN'
    """
    return (
        pattern.replace("^(?i)", "")
            .replace("(?i)", "")
            .lstrip("^")
            .rstrip("$")
    )

def resolve_ref(root_schema: dict, ref: str):
    """
    Resuelve un $ref del estilo "#/$defs/goodSecurityContext" dentro del JSON Schema.
    """
    if not isinstance(root_schema, dict):
        return None
    if not ref.startswith("#/"):
        return None
    parts = ref[2:].split("/")
    node = root_schema
    for p in parts:
        if p in node:
            node = node[p]
        else:
            return None
    return node


def resolve_target_kinds(check: dict):
    """
    Devuelve lista de Kinds "reales" K8s sobre las que aplica el check.

    Reglas:
    - target: Controller + controllers.include -> los Kinds incluidos (Deployment, StatefulSet, ...)
    - target: PodSpec -> ["Pod"]
    - target: Container + schemaTarget: PodSpec -> ["Pod"]
    - target: Container sin schemaTarget -> ["Container"] (kind lógico abstracto)
    - target: apiGroup/Kind (rbac.authorization.k8s.io/ClusterRole) -> ["ClusterRole"]
    - target simple (Pod, Deployment, ...) -> [target]
    """
    target = check.get("target", "")
    controllers = check.get("controllers", {}) or {}
    schema_target = check.get("schemaTarget", "")

    # Caso especial: Controller
    if target == "Controller":
        # 1. Si existe 'include', es una lista taxativa. Solo devolvemos esos.
        included = controllers.get("include", [])
        if included:
                return included
        # Usamos la variable importada directamente
        candidates = list(CONTROLLER_KINDS) # Copia de la lista global
        
        # 3. Filtramos los 'exclude' si existen
        excluded = controllers.get("exclude", [])
        final_list = [k for k in candidates if k not in excluded]
        
        return final_list
    # PodSpec: se refiere al spec de un Pod
    if target == "PodSpec":
        return ["Pod"]

    # Container + PodSpec: containers dentro de PodSpec (Pod.spec.containers)
    if target == "Container" and schema_target == "PodSpec":
        return ["Pod"]

    # Container sin schemaTarget: lo tratamos como kind abstracto "Container"
    if target == "Container":
        return ["Container"]

    # apiGroup/Kind
    if "/" in target:
        return [target.split("/")[-1]]

    # target directo
    return [target]


def context_kind_for(real_kind: str, check: dict, prop_path: str) -> str:
    """
    Determina el contexto de FM (prefijo Midle) que usaremos para buscar en el CSV.

    Ejemplos:
    - runAsPrivileged (target=Container, schemaTarget=PodSpec) -> "Pod_spec_containers"
    - hostIPCSet       (target=PodSpec)                        -> "Pod_spec"
    - deploymentMissingReplicas (target=Controller + Deployment) -> "Deployment_spec"
    - readinessProbeMissing (target=Container sin schemaTarget)  -> "Container"
    """
    target = check.get("target", "")
    schema_target = check.get("schemaTarget", "")

    # Container + PodSpec → Pod_spec_containers_*
    if real_kind == "Pod" and target == "Container" and schema_target == "PodSpec":
        return f"{real_kind}_spec_containers"

    # PodSpec directo → Pod_spec_*
    if target == "PodSpec" and real_kind == "Pod":
        ### Use the 5 templates with PodSpec target
        return f"{real_kind}_spec"

    # Controller + Deployment/StatefulSet/... → <Kind>_spec_*
    if target == "Controller" and real_kind in (
        "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"):
        if "metadata" in prop_path:
            return f"{real_kind}"
        return f"{real_kind}_spec"

    # Recursos tipo Pod, Deployment,... si el path empieza por spec. → <Kind>_spec
    if prop_path.startswith("spec.") and real_kind in (
        "Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"
    ):
        return f"{real_kind}_spec"

    # Container sin schemaTarget → Container_*
    if real_kind == "Container":
        return "Container"

    # ClusterRole, ClusterRoleBinding, Role, RoleBinding, ServiceAccount, etc.
    return real_kind


# =========================
# Extracción de condiciones desde JSON Schema Polaris
# =========================

def extract_conditions_from_schema(schema, controllers=None, prefix="", root_schema=None):
    """
    Extrae condiciones reales de un JSON Schema Polaris.

    Devuelve lista de (prop_path, op, val), p.ej.:
    - ("automountServiceAccountToken", "!=", True)
    - ("spec.replicas", ">=", 2)
    - ("securityContext.allowPrivilegeEscalation", "==", False)
    """
    if root_schema is None:
        root_schema = schema

    conds = []
    if not isinstance(schema, dict):
        return conds

    props = schema.get("properties", {})
    #print(f"Props extraction    {props}")
    # 1) Propiedades directas
    for name, rule in props.items():
        prop_path = f"{prefix}.{name}" if prefix else name
        # $ref → expandir
        if "oneOf" in rule and isinstance(rule["oneOf"], list):
            for option in rule["oneOf"]:
                # Opción simple: contains.pattern
                contains = option.get("contains")
                if isinstance(contains, dict) and "pattern" in contains:
                    literal = clean_cap_pattern(contains["pattern"])
                    conds.append((prop_path, "contains", literal))
                    print(f"Condition with oneOf    {prop_path} {literal}")

                # Opción compuesta: allOf con varios contains
                """if "allOf" in option and isinstance(option["allOf"], list): ## Uncomment if want to use the full insecureCapabilities Strs
                    for sub in option["allOf"]:
                        sub_contains = sub.get("contains")
                        if isinstance(sub_contains, dict) and "pattern" in sub_contains:
                            literal = clean_cap_pattern(sub_contains["pattern"])
                            conds.append((prop_path, "not_contains", literal))
                            print(f"Condition with allOf    {prop_path} {literal}")"""
        if "$ref" in rule:
            resolved = resolve_ref(root_schema, rule["$ref"])
            if resolved:
                conds.extend(
                    extract_conditions_from_schema(resolved, prefix=prop_path, root_schema=root_schema)
                )
            continue
        if "allOf" in rule and isinstance(rule["allOf"], list):
            for entry in rule["allOf"]:
                if (
                    isinstance(entry, dict)
                    and "not" in entry
                    and isinstance(entry["not"], dict)
                    and "contains" in entry["not"]
                ):
                    contains = entry["not"]["contains"]
                    if isinstance(contains, dict) and "pattern" in contains:
                        pattern = contains["pattern"]

                        # Convertir ^(?i)SYS_ADMIN$ → SYS_ADMIN
                        literal = (
                            pattern.replace("^(?i)", "")
                                .replace("(?i)", "")
                                .replace("^", "")
                                .replace("$", "")
                        )

                        conds.append((prop_path, "not_contains", literal))
        # not.const → !=
        if "not" in rule and isinstance(rule["not"], dict) and "const" in rule["not"]:
            ## {name} have the cpu, memory requests/limits Efficiency case to modify with the Strings updates would be done
            #print(f"not const detected  {rule}  {name}")
            conds.append((prop_path, "!=", rule["not"]["const"]))

        # const → ==
        if "const" in rule:
            conds.append((prop_path, "==", rule["const"]))
        # Recursión en arrays: items.properties.hostPort.const
        if rule.get("type") == "array" and "items" in rule:
            conds.extend(
                extract_conditions_from_schema(
                    rule["items"], prefix=prop_path, root_schema=root_schema
                )
            )
        # pattern
        if "pattern" in rule:
            conds.append((prop_path, "matches", rule["pattern"]))

        # not.pattern
        if "not" in rule and isinstance(rule["not"], dict) and "pattern" in rule["not"]:
            conds.append((prop_path, "not matches", rule["not"]["pattern"]))

        # mínimo numérico (p.ej. replicas >= 2)
        if "minimum" in rule:
            conds.append((prop_path, ">=", rule["minimum"]))
        ## minItems for arrays
        if "minItems" in rule:
            conds.append((prop_path, "==", "true"))
            
        # Recursión en sub-propiedades
        if "properties" in rule and not "metadata" in name: ## Check for special deffs
            conds.extend(
                extract_conditions_from_schema(rule, prefix=prop_path, root_schema=root_schema)
            )
        if "metadata" in name:
            print(f"Metadata detectado {rule}   {prop_path}")
            aux_value_key = rule.get("required")
            print(f"Aux value   {aux_value_key}")
            if aux_value_key:
                for prop in aux_value_key:
                    if prop == "labels":
                        prop_path += f"_{prop}"
                        aux_properties = rule.get("properties")
                        aux_rule = aux_properties.get("labels").get("properties")
                        if aux_rule:
                            print(f"Prop path aux   {prop_path} aux_properties:  {aux_properties}   get {aux_rule}")   
                            conds.append((prop_path, "Map", aux_rule))
                        else: ## preparar caso minProperties
                            print(f"No aux rule for labels   {prop_path} ")
            else:
                print(f"No aux value key for metadata   {prop_path} {aux_value_key}")
    # 2) required → != null
    """if "required" in schema and isinstance(schema["required"], list):
        for req in schema["required"] and not :
            prop_path = f"{prefix}.{req}" if prefix else req
            conds.append((prop_path, "!=", None))"""
    
    required_preperty = schema.get("required")
    required_aux_allOf = schema.get("allOf") ## oneOf
    if not props and required_preperty and not required_aux_allOf: ## Checks simples without properties => Directly required
        #print(f"Required property simple    {required_preperty} {required_aux_allOf}")
        for required in required_preperty:
            prop_path = f"{prefix}.{required}" if prefix else required
            conds.append((prop_path, "match", "required"))

    """if controllers: ## Done for controllers property simple without properties
        print(f"Controllers detected in cond  {controllers} {required_preperty}")
        if required_preperty and not aux_min:
            for required in required_preperty:
                print(f"Kind excluded for  {prefix}  {required} {prop_path}")
                prop_path = f"{prefix}.{required}" if prefix else required
                conds.append((prop_path, "==", "true")) ##
        unique_schema = schema.get("required")
        if unique_schema:
            print(f"required property   {required_preperty} {unique_schema} ")"""

    # 3) anyOf / allOf
    for key in ("anyOf", "allOf"):
        if key in schema and isinstance(schema[key], list):
            for block in schema[key]:
                conds.extend(
                    extract_conditions_from_schema(block, prefix=prefix, root_schema=root_schema)
                )

    return conds

def extract_semantic_conditions_from_ast(ast, prefix="", result=None, root_ast=None):
    """
    Extrae condiciones semánticas desde el AST de un schemaString.

    Devuelve una lista que puede contener:
    - Tuplas simples:   (prop_path, op, val)
    - Marcadores OR:    ("__OR__", [ [conds_branch1], [conds_branch2], ... ])

    Donde cada conds_branch es una lista de tuplas (prop_path, op, val).
    """
    if result is None:
        result = []
    if root_ast is None:
        root_ast = ast

    if not isinstance(ast, dict):
        return result
    if "$ref" in ast:
        resolved = resolve_ast_ref(root_ast, ast["$ref"])
        if resolved:
            extract_semantic_conditions_from_ast(resolved, prefix, result, root_ast=root_ast)
    # 1) PROPERTIES: recursión por subcampos
    if "properties" in ast and isinstance(ast["properties"], dict):
        for prop, rule in ast["properties"].items():
            new_prefix = f"{prefix}.{prop}" if prefix else prop
            extract_semantic_conditions_from_ast(rule, new_prefix, result, root_ast=root_ast)

    # 2) Const / not / pattern / contains / minimum en el nodo actual
    if "pattern" in ast:
        result.append((prefix, "matches", ast["pattern"]))

    if "const" in ast:
        result.append((prefix, "==", ast["const"]))

    if "minimum" in ast:
        print(f"AST schme   {ast}  {prefix}")
        result.append((prefix, ">=", ast["minimum"]))

    # contains (ej. array contains elementos que matchean un patrón)
    if "contains" in ast and isinstance(ast["contains"], dict):
        if "pattern" in ast["contains"]:
            result.append((prefix, "contains", ast["contains"]["pattern"]))

    # not con const / pattern / contains
    if "not" in ast and isinstance(ast["not"], dict):
        not_block = ast["not"]
        if "const" in not_block:
            result.append((prefix, "!=", not_block["const"]))
        if "pattern" in not_block:
            result.append((prefix, "not matches", not_block["pattern"]))
        if "contains" in not_block and isinstance(not_block["contains"], dict):
            if "pattern" in not_block["contains"]:
                result.append((prefix, "not_contains", not_block["contains"]["pattern"]))

    # 3) anyOf → lista de alternativas (OR)
    if "anyOf" in ast and isinstance(ast["anyOf"], list):
        branches = []
        for option in ast["anyOf"]:
            branch_conds = []
            extract_semantic_conditions_from_ast(option, prefix, branch_conds, root_ast=root_ast)
            if branch_conds:
                branches.append(branch_conds)
        if branches:
            result.append(("__OR__", branches))

    # 4) allOf → AND de bloques (simplemente recursión)
    if "allOf" in ast and isinstance(ast["allOf"], list):
        for block in ast["allOf"]:
            extract_semantic_conditions_from_ast(block, prefix, result, root_ast=root_ast)

    return result

def find_feature(context_kind: str, prop_path: str, feature_dict: dict, kind_map: dict = None):
    """
    Busca una característica en el Feature Model con estrategia híbrida.
    
    1. Estrategia Rápida (Recomendada): Usa kind_map para construir la key exacta.
    2. Estrategia Fallback: Escanea todo el dict priorizando versiones estables.
    """
    # Normalizamos la propiedad (spec.replicas -> spec_replicas)
    prop_key = prop_path.replace(".", "_")
    clean_kind = context_kind.split("_")[0]

    # ---------------------------------------------------------
    # ESTRATEGIA 1: Búsqueda Directa (O(1)) - "Happy Path"
    # ---------------------------------------------------------
    if kind_map:
        prefix = kind_map.get(clean_kind)
        if prefix:
            # Construimos la llave maestra: Prefijo + Kind + Propiedad
            # Ej: io_k8s_api_autoscaling_v1_HorizontalPodAutoscaler_spec_minReplicas
            candidate_key = f"{prefix}_{clean_kind}_{prop_key}"
            
            if candidate_key in feature_dict:
                return feature_dict[candidate_key]
                
            # Optimización: Si tenemos prefijo pero falló el match exacto,
            # podríamos intentar buscar solo features que empiecen por ese prefijo
            # antes de ir al fallback global. (Opcional, para mantenerlo simple pasamos al 2)

    # ---------------------------------------------------------
    # ESTRATEGIA 2: Fallback Heurístico (O(N)) - "Rescue Path"
    # ---------------------------------------------------------
    
    candidates_equal = []
    candidates_suffix = []
    fallback = []

    # Definimos la prioridad AQUÍ, mirando la KEY (Nombre Largo), no el Midle.
    def get_priority_key(item_tuple):
        """
        Recibe (feature_long_name, row_data).
        Devuelve (score_version, longitud).
        """
        f_name, row = item_tuple
        midle = row.get("Midle", "")

        # 1. Prioridad por Versión (Buscamos en el NOMBRE LARGO)
        if "_v1_" in f_name:      score = 1
        elif "_v2_" in f_name:    score = 2
        elif "beta" in f_name:    score = 3
        else:                     score = 10

        # 2. Desempate por Longitud (Buscamos en el MIDLE)
        return (score, len(midle))

    # Iteramos sobre el diccionario completo
    for feature_long_name, row in feature_dict.items():
        midle = row.get("Midle", "")
        
        # Filtro de contexto básico
        if not midle.startswith(clean_kind + "_"):
            continue

        # Extraemos el sufijo real
        suffix = midle[len(clean_kind) + 1 :]

        # Empaquetamos el candidato (Key + Value) para la función de prioridad
        candidate = (feature_long_name, row)

        if suffix == prop_key:
            candidates_equal.append(candidate)
        elif suffix.endswith("_" + prop_key):
            candidates_suffix.append(candidate)
        elif prop_key in suffix:
            fallback.append(candidate)

    # Selección del ganador
    # min() devuelve la tupla (key, row), nosotros retornamos row
    
    if candidates_equal:
        best = min(candidates_equal, key=get_priority_key)
        return best[1]

    if candidates_suffix:
        best = min(candidates_suffix, key=get_priority_key)
        return best[1]

    if fallback:
        best = min(fallback, key=get_priority_key)
        return best[1]

    return None


# =========================
# Parser de checks Polaris
# =========================

def parse_polaris_check(path):
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        return None

    schema = data.get("schema") or {}
    if not schema and "schemaString" in data:
        try:
            schema = yaml.safe_load(data["schemaString"])
        except Exception:
            schema = {}

    return {
        "id": os.path.basename(path).replace(".yaml", ""),
        "category": data.get("category", ""),
        "target": data.get("target", ""),
        "schemaTarget": data.get("schemaTarget", ""),
        "controllers": data.get("controllers", {}),
        "schema": schema,
        "schemaString": data.get("schemaString", ""),
        "success": data.get("successMessage", ""),
        "failure": data.get("failureMessage", ""),
    }


# =========================
# Construcción de expresiones UVL
# =========================

def build_uvl_expr(kind_name: str, feature: str, op: str, val):
    full_feature = f"{kind_name}.{feature}"
    print(f"Full feature build {full_feature}")
    if op == "==":
        #print(f"full feature ===    {full_feature}  op  {op}    {kind_name}")
        if isinstance(val, bool) or val == "true" or val == "false":
            return full_feature if val else f"!{full_feature}"
        
        if isinstance(val, (int,float)):
            return f"{full_feature} == {val}"
        
        if val is None:
            return f"{full_feature} == null"
        if full_feature.endswith('securityContext_procMount'):
            return f"({full_feature}_StringValue == '{val}')"
        if full_feature.endswith('_imagePullPolicy'):
            return f"({full_feature}_{val})"
        
        return f"{full_feature} == '{val}'"

    if op == "!=":
        print(f"full feature    {full_feature}  op  {op}    {kind_name} {val}")
        if isinstance(val, bool):
            return f"!{full_feature}" ## {str(val).lower()}
        elif isinstance(val, str) and val == 'null':
            return f"{full_feature} != null"
        elif val == '': ## Case Efficiency empty string
            print("Empty string detected")
            return f"{full_feature}"
        if val is None:
            return f"{full_feature}"
        if full_feature.endswith('securityContext_seccompProfile_type'):
                if val == 'Unconfined':
                    return f"{full_feature}_Unconfined"
                #return f"({full_feature}_StringValue == '{val}')"
    
    if op == ">=": ## differences between our modify model :: _valueInt **
        return f"{full_feature} > {val}"

    if op == "matches":
        if full_feature.endswith("Container_image"):
            return f"{full_feature}_Removed"
        return f"{full_feature} == '{val}'"
    ##not_contains
    if op == "not matches":
            if '.' in val:
                val = clean_description(val)
            return f"({full_feature} != '{val}')"
    
    if op == "contains":
        # Convención: para arrays tipo capabilities_drop
        if full_feature.endswith("capabilities_drop"):
            return f"({full_feature}_StringValue == '{val}')"
        return f"({full_feature} == '{val}')"

    if op == "not_contains":
        if full_feature.endswith("capabilities_add"):
            return f"({full_feature}_StringValue != '{val}')"
        return f"({full_feature} != '{val}')"
    
    ## New match Simple
    if op == "match":
        #if full_feature.endswith("spec_priorityClassName "):
        #    return f"({full_feature} == '{val}')" # Is a Str feature with a simple use
        return f"{full_feature}" ## We define as a simple feature Boolean to use the functionatilly of select it
    
    if op == "Map":
        feature_map_key = f"{full_feature}_KeyMap"
        feature_map_value = f"{full_feature}_ValueMap"
        for key, value  in val.items():
            const_value = value.get('const')
            key = key.replace(".", "_")
        ##.replace("{", "","}", "", ".", "")
        print(f"Full feauture   {full_feature}  {val}   {const_value}  {value}")
        const_value = const_value.replace("{", "").replace("}", "").replace(".", "_").replace(" ","")
        return f"{feature_map_key} == '{key}' & {feature_map_value} == '{const_value}'"
        
        
    # Fallback genérico
    return f"{full_feature} {op} '{val}'"


def map_semantic_conds_to_uvl(check, semantic_conds, feature_dict, kind_map):
    """
    Convierte la lista de condiciones semánticas (incluyendo OR-groups)
    en una única expresión UVL para este check.

    Usa:
    - target del check para elegir contexto (Container, Pod, etc.)
    - find_feature(kind_context, prop_path, feature_dict)
    - build_uvl_expr(real_kind, fm_feature, op, val)
    """
    from collections import OrderedDict

    # Resolver Kind real (ej. "Container", "Pod", "ClusterRoleBinding"...)
    # Aquí usamos una aproximación simple y reutilizamos el target.
    real_kind = check["target"]
    if "/" in real_kind:
        # rbac.authorization.k8s.io/ClusterRoleBinding → ClusterRoleBinding
        real_kind = real_kind.split("/")[-1]

    kind_name = real_kind  # usado en la parte "Kind." de UVL
    context_kind = real_kind  # usado para buscar en el FM

    all_simple_exprs = []   # AND global (fuera de OR groups)
    all_or_groups = []      # cada OR group es algo tipo "(expr1 and expr2) or (expr3)"

    paths = {cond[0] for cond in semantic_conds}
    
    if "spec.minReplicas" in paths and "spec.maxReplicas" in paths:
        print(f"Check minMaxReplicas detectado {check['id']}    {paths}")
        interval_max_min = []
        for path, op, val in semantic_conds:
            row = find_feature(context_kind, path, feature_dict)
            feature = row["Feature"]
            if feature.endswith("spec_minReplicas"):
                feature_max = feature.replace("minReplicas", "maxReplicas")
                interval_max_min.append(f"{kind_name}.{feature_max} > {kind_name}.{feature}")
            elif feature.endswith("spec_maxReplicas"):
                interval_max_min.append(f"{kind_name}.{feature} > {val}")
        return " & ".join(interval_max_min)
    
    for cond in semantic_conds:
        # OR-group: ("__OR__", [ [ (path,op,val)... ], [ ... ] ])
        if isinstance(cond, tuple) and len(cond) == 2 and cond[0] == "__OR__":
            branches = cond[1]
            branch_exprs = []
            for branch in branches:
                local_exprs = []
                for path, op, val in branch:
                    row = find_feature(context_kind, path, feature_dict)
                    if not row:
                        print(f" No FM match for Context={context_kind}, prop={path}")
                        continue
                    fm_feature = row["Feature"]

                    uvlexpr = build_uvl_expr(kind_name, fm_feature, op, val)
                    if uvlexpr:
                        local_exprs.append(uvlexpr)
                if local_exprs:
                    # dentro de una rama OR, juntamos con AND
                    branch_exprs.append("(" + " & ".join(OrderedDict.fromkeys(local_exprs)) + ")")
            if branch_exprs:
                # OR entre ramas
                or_expr = " or ".join(branch_exprs)
                all_or_groups.append(or_expr)
            continue

        # Condición simple: (path, op, val)
        if isinstance(cond, tuple) and len(cond) == 3:
            print(f"Semantic conditions to map continue {cond}")
            path, op, val = cond
            #print(f"Simple condition cond   {path}  {op}  {val}")
            row = find_feature(context_kind, path, feature_dict)
            if not row:
                print(f"No FM match for Context={context_kind}, prop={path}")
                continue
            fm_feature = row["Feature"]
            uvlexpr = build_uvl_expr(kind_name, fm_feature, op, val)
            if uvlexpr: ### Pendent of mapping
                all_simple_exprs.append(uvlexpr)
            continue

    # Eliminar duplicados preservando orden
    all_simple_exprs = list(OrderedDict.fromkeys(all_simple_exprs))
    all_or_groups = list(OrderedDict.fromkeys(all_or_groups))

    if not all_simple_exprs and not all_or_groups:
        return None

    # Construcción final de la constraint:
    #   (simple1 & simple2) & ( (branch1) or (branch2) )
    pieces = []
    if all_simple_exprs:
        pieces.append(" & ".join(all_simple_exprs))
    if all_or_groups:
        pieces.append(" & ".join(all_or_groups))

    if len(pieces) == 1:
        return pieces[0]
    return " & ".join(pieces)


# =========================
# Polaris → UVL usando FM
# =========================

def polaris_to_uvl(check, feature_dict, kind_map):
    #print(f"\nCheck: {check['id']}")
    #print(f"Doc {check['failure']}")
    # 0) Resolver Kinds reales sobre los que aplica
    real_kinds = resolve_target_kinds(check)
    # Lista provisional para evitar la encadenacion de las propiedades con recursos Strings detectados en Efficiency
    suffixes_to_strip = ("requests.cpu", "limits.cpu", "requests.memory", "limits.memory")

    # 1) Si hay schemaString → usar parser semántico nuevo
    if check.get("schemaString"):
        ast = schema_string_to_ast(check["schemaString"])
        if not ast:
            print("schemaString sin AST -> skip")
            return None

        semantic_conds = extract_semantic_conditions_from_ast(ast, prefix="", result=None, root_ast=ast)
        if not semantic_conds:
            print("schemaString sin condiciones semánticas -> skip")
            return None

        constraint_expr = map_semantic_conds_to_uvl(check, semantic_conds, feature_dict, kind_map)
        if not constraint_expr:
            print("No se pudo mapear semantic_conds a FM -> skip")
            return None
        
        feature_name = check["id"].replace("-", "_")
        feature_block = (
            f"{feature_name} {{"
            f"tool 'Polaris', "
            f"category '{check['category']}', "
            f"doc '{check['failure']}', "
            f"}}"
        )
            
        constraint = f"{feature_name} => {constraint_expr}"
        return feature_block, constraint
    
    controllers = check.get("controllers", {}) or {} 
    # 2) Extraer condiciones del schema
    conds = extract_conditions_from_schema(check["schema"], controllers)
    if not conds:
        id_check = check["id"]
        print(f"Sin condiciones mapeables → skip    {id_check}")
        print(check)
        return None

    feature_name = check["id"].replace("-", "_")
    feature_block = (
        f"{feature_name} {{doc '{check['failure']}', tool 'Polaris', category '{check['category']}'}}"
    )

    all_parts = []
    for real_kind in real_kinds:
        for prop_path, op, val in conds:
            #if "metadata" in prop_path:
            #    print(f"Condition:  {prop_path} {op}    {val}")
            print(f"  Prop path   {prop_path}  {op} {val}   real_kind={real_kind}")
            context_kind = context_kind_for(real_kind, check, prop_path)

            ## Check for excluded kinds in controllers property if target is PodSpec
            kinds_excluded = controllers.get("exclude", [])
            if kinds_excluded:
                for kind_excluded in kinds_excluded:
                        print(f"Kind excluded  {kind_excluded}")
                        if kind_excluded == real_kind: ## if kind is excluded, we skip the required conditions
                            continue
            if prop_path.endswith(suffixes_to_strip):
                prop_path = prop_path.rsplit(".", 1)[0]
            fm_row = find_feature(context_kind, prop_path, feature_dict)

            if not fm_row:
                print(f"No FM match for Context={context_kind}, prop={prop_path}")
                continue

            feature = fm_row["Feature"]

            if feature.endswith("_runAsUser") and str(val).isdigit(): ## _Removed
                #feature = f"{feature}_valueInt"
                print(f"CONTINUE, case invalid with feat const integer")
                continue

            expr = build_uvl_expr(real_kind, feature, op, val)
            
            if expr.endswith("_Removed"): ## Cases that we need Remove
                continue

            print(f"Expresiones add {expr}  {val}")
            all_parts.append(expr)

    if not all_parts:
        print("Ninguna condición mapeada a FM, se omite este check.")
        return None

    # Opcional: aquí podrías quitar duplicados si quieres
    all_parts = list(dict.fromkeys(all_parts))

    if feature_name == "metadataAndInstanceMismatched": ## Unnused
        # Caso especial: Usamos OR (|)
        joined_parts = " | ".join([f"({part})" for part in all_parts])
    else:
        # Caso por defecto: Usamos AND (&)
        joined_parts = " & ".join(all_parts)

    """if feature_name == "insecureCapabilities" and joined_parts.count(" & ") >= 1: ## Uncomment if want to use the full insecureCapabilities Strs
        joined_parts = joined_parts.replace(" & ", " | ", 1)"""

    constraint = f"{feature_name} => {joined_parts}"
    #constraint = f"{feature_name} => " + " & ".join(all_parts)
    print(f"Constraint  {constraint}")

    return feature_block, constraint

# =========================
# MAIN de prueba
# =========================

if __name__ == "__main__":
    FEATURES_CSV = "../resources/mapping_csv/kubernetes_mapping_properties_features.csv"
    KINDS_CSV    = "../resources/mapping_csv/kubernetes_kinds_versions_detected.csv"
    POLARIS_DIR  = "../resources/Polaris-checks"

    feature_dict = load_feature_dict_polaris(FEATURES_CSV)
    kind_map = load_kinds_prefix_mapping(KINDS_CSV)

    results = []

    for root, _, files in os.walk(POLARIS_DIR):
        for f in files:
            if not f.endswith(".yaml"):
                continue
            full_path = os.path.join(root, f)
            check = parse_polaris_check(full_path)
            if not check:
                continue
            uv = polaris_to_uvl(check, feature_dict, kind_map)
            if uv:
                results.append(uv)

    print("\n\n### FINAL RESULTS ###\n")
    for fb, cons in results:
        print(fb)
        print(cons)
        print("-" * 80)