import yaml
import re
import csv

from tools_extraction.extract_policies_general import (
    clean_description,
)

### Special lists for features modified in Kubernetes FM
special_features_config = ['procMount'] ## Pod_spec_..._procMount was String but in FM k8s is Bool with a mandatory subfeature String Pod_spec_..._procMount_nameStr

def sanitize(name):
    return name.replace("-", "_").replace(".", "_").replace("/", "_").replace(" ", "_").replace("{{", "").replace("}}", "").replace("(", "").replace(")", "").replace(",", "")

def get_base_prefix(kind_prefix):
    if kind_prefix.endswith("Pod_"): ## kind_prefix with underscores _{KIND}_
        return "Pod"
    elif "ServiceAccount" in kind_prefix:
        return "ServAcc"
    elif "Service" in kind_prefix:
        return "Serv"
    elif "ClusterRoleBinding" in kind_prefix: ## ToDo: More specific str of types if add more kindsQ
        return "ClusRole" 
    elif "RoleBinding" in kind_prefix:
        return "RoleBinding"
    elif "Ingress" in kind_prefix:
        return "Ingress"
    elif "Job" in kind_prefix:
        return "Job"
    elif "DaemonSet" in kind_prefix:
        return "DaemonSet"
    elif "Deployment" in kind_prefix:
        return "Deployment"
    elif "StatefulSet" in kind_prefix:
        return "StatefulSet"
    elif "Secret" in kind_prefix:
        return "Secret" # PersistentVolumeClaim
    elif "PersistentVolumeClaim" in kind_prefix:
        return "PersistVolumeClaim" ## PodDisruptionBudgetFeatures
    elif "PodDisruptionBudget" in kind_prefix:
        return "PodDisrupBud"    
    else:
        return "Kubernetes"
    
def extract_policy_info(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        policy = yaml.safe_load(f)

    metadata = policy.get("metadata", {})
    annotations = metadata.get("annotations", {})
    name = metadata.get("name", "")
    title = annotations.get("policies.kyverno.io/title", name)
    category = annotations.get("policies.kyverno.io/category", "Uncategorized")

    return {
        "name": name,
        "title": title,
        "category": category,
        "description": annotations.get("policies.kyverno.io/description", ""),
        "full_yaml": policy
    }

def _extract_canonical_fields_recursive(obj, prefix=""):
    """
    Extrae rutas como spec_hostNetwork, spec_replicas, etc.
    Sin valores, solo la canonical field.
    """
    fields = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            key_clean = sanitize(k.replace("=", "").replace("()", ""))
            new_prefix = f"{prefix}_{key_clean}" if prefix else key_clean
            #if new_prefix.count('_') > 1:
            fields.add(new_prefix)
            fields.update(_extract_canonical_fields_recursive(v, new_prefix))
    return fields


def extract_uvl_attributes_from_policy(policy: dict) -> str:

    # Campos que queremos extraer
    annotations = policy.get("metadata", {}).get("annotations", {})
    metadata = policy.get("metadata", {})
    spec = policy.get("spec", {})
    rules = spec.get("rules", [])
    #doc = annotations.get("policies.kyverno.io/description", "").replace("'", "\\'")

    # Formateo en estilo UVL
    # --- tool ---
    tool = "kyverno"
    # --- severity ---
    severity = annotations.get("policies.kyverno.io/severity", "")
    # --- name of file ---
    file_name = metadata.get("name", "")
    #category = sanitize(category)
    # --- category ---
    category = annotations.get("policies.kyverno.io/category", "Uncategorized")
    category = sanitize(category)
    # --- description ---
    description = annotations.get("policies.kyverno.io/description", "")
    description = clean_description(description).replace("'", "")
    # --- kinds (todos los kinds usados en reglas) ---
    kinds_value = annotations.get("policies.kyverno.io/subject", "")
    # --- canonical_fields ---
    canonical_fields = set()
    for rule in rules:
        pattern = rule.get("validate", {}).get("pattern", {})
        canonical_fields.update(_extract_canonical_fields_recursive(pattern))

    canonical_fields = { ## Delete simple fields like spec, type
    f for f in canonical_fields 
    if len(f.split("_")) >= 2
    }
    canonical_fields_value = ", ".join(sorted(canonical_fields))
    # --- raw_source (YAML comprimido y sanitizado) ---
    raw_source = 'YAML'

    """k8s_version = annotations.get("kyverno.io/kubernetes-version", "")
    action = spec.get("validationFailureAction", "")
    attributes = []
    tool = "kyverno"
    if doc:
        attributes.append(f"doc '{clean_description(doc)}'")
    if severity:
        attributes.append(f"severity '{severity}'")
    if action:
        attributes.append(f"action '{action.lower()}'")
    if k8s_version:
        version_clean = k8s_version.replace(".", "_").replace("-", "‑")  # Usa guiones no separables
        attributes.append(f"k8sRange '{version_clean}'")

    if attributes:
        return f" {{{', '.join(attributes)}}}"
    return """
    # --- Construcción UVL ---
    attrs = []
    attrs.append(f"tool '{tool}'")
    if severity:
        attrs.append(f"severity '{severity}'")
    if file_name:
        attrs.append(f"name '{file_name}'")
    if canonical_fields_value:
        attrs.append(f"fields '{canonical_fields_value}'")
    if kinds_value:
        attrs.append(f"kinds '{kinds_value}'")
    #if category:
    #    attrs.append(f"category '{category}'")
    if description:
        attrs.append(f"doc '{description}'")
    if raw_source:
        attrs.append(f"raw_source '{raw_source}'")

    return " {" + ", ".join(attrs) + "}"

def load_kinds_prefix_mapping(file_path: str) -> dict:
    """
    Create a dict {Kind: Prefix} from the CSV generated by mappingUvlCsvK8sOld.py
    Ex:
        {"Pod": "io_k8s_api_core_v1", "RoleBinding": "io_k8s_api_rbac_v1", ...}
    """
    mapping = {}
    with open(file_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            kind = row["Kind"].strip()
            prefix = row["Prefix"].strip()
            mapping[kind] = prefix
    return mapping

def get_kind_prefix(kind: str, mapping: dict, default: str = "io_k8s_api_core_v1") -> str:
    """
    Devuelve el prefijo correspondiente a un Kind dado.
    Ejemplo:
        get_kind_prefix("Pod", mapping) -> "io_k8s_api_core_v1"
    Si el Kind no existe, usa el prefijo por defecto.
    """
    prefix = mapping.get(kind, default)
    return f"{prefix}_"


def get_kind_prefixes_from_rule(rule: dict) -> list:
    """
    Extrae los prefijos de los kinds especificados en una regla Kyverno.
    Devuelve una lista de strings como: io_k8s_api_core_v1_Pod_
    """
    kinds = rule.get("match", {}).get("any", [{}])[0].get("resources", {}).get("kinds", [])
    """prefix = 'io_k8s_api_core_v1_'
    ##print(f"Kinds en get kind prefix... {kinds}")
    if 'RoleBinding' in kinds: ## and ClusterRoleBinding
        prefix = 'io_k8s_api_rbac_v1_'
        
    return [f"{prefix}{sanitize(kind)}_" for kind in kinds]"""
    # Load the file of kinds, prefix
    kind_prefix_map = load_kinds_prefix_mapping("../resources/mapping_csv/kubernetes_kinds_versions_detected.csv")

    prefixes = []
    for kind in kinds:
        prefix = get_kind_prefix(kind, kind_prefix_map)
        prefixes.append(f"{prefix}{kind}_")
    return prefixes

def build_optional_clause(parent, allowed_values, kind_prefixes):
    """Build the constraint ref '!parent | (parent => val1 | val2 | …)'"""
    if not isinstance(kind_prefixes, list):
        kind_prefixes = [kind_prefixes]
    clauses = []
    #print(f"ALLOWED VALUES  {allowed_values}    {kind_prefixes}")

    for kind_prefix in kind_prefixes:
        allowed_full = [f"Pod.{kind_prefix}{val}" for val in allowed_values]
        allowed_str = " | ".join(allowed_full)
        clause = f"(!Pod.{kind_prefix}{parent} | (Pod.{kind_prefix}{parent} => {allowed_str}))"
        clauses.append(clause)

    return clauses if len(clauses) > 1 else clauses[0]



def handle_annotation_with_wildcard(key: str, value: str, prefix: str):
    """
    Genera pares (feature_path, value) para anotaciones con wildcard (como AppArmor).
    Compatible con el flujo original de extract_constraints_from_policy().
    """
    clean_key = key.strip("=() ").replace("/*", "").replace(".", "_")
    key_feature = f"{prefix}_KeyMap"
    value_feature = f"{prefix}_ValueMap"
    #print(f"key feature and value feature   {key_feature}   {value_feature}")
    # Dividir valores del patrón tipo "runtime/default | localhost/*"
    values = [v.strip().replace("/*", "").replace(".", "_") for v in value.split("|")]

    pairs = [] ## dict?
    for v in values:
        # Cada valor posible genera dos pares: uno para la clave, otro para el valor
        pairs.append((key_feature, f"'{clean_key}'"))
        pairs.append((value_feature, f"'{v}'"))
        #pairs.append((f"{key_feature} '{clean_key}'" ,f"{value_feature} '{v}'"))
    print(f"[Wildcard] Generados {len(pairs)} pares para {clean_key}: {pairs}")
    return pairs


def extract_conditions_from_metadata(obj, prefix="metadata", kind_prefixes=None):
    conditions = []
    optional_clauses = []
    #print(f"Kind Prefixes: {kind_prefixes}")
    if isinstance(obj, dict):
        for k, v in obj.items():
            #print(f"k y v:  {k} {v}")
            # Subnivel: metadata.annotations
            key = k.strip("=() ")
            new_prefix = f"{prefix}_{key}"
            if key == "annotations" and isinstance(v, dict):
                #print(f"detect CASE ANNOTATIONS {v}")
                for subkey, subval in v.items():
                    if '*' in subkey or '.' in subkey: ## Detect of the Key Value of the Pairs
                        # Caso de anotación con wildcard
                        conditions.extend(
                            handle_annotation_with_wildcard(subkey, subval, new_prefix)
                        )
                    else:
                        # Anotación fija (sin wildcard)
                        key_feature = f"{new_prefix}{sanitize(subkey)}"
                        conditions.append((key_feature, f"'{subval}'"))
            else:
                # Otro tipo de clave bajo metadata (p. ej., name, labels)
                #key = k.strip("=() ")
                full_key = f"{prefix}_{sanitize(key)}"
                #print(f"Full key else:  {full_key}")
                conditions.append((full_key, f"'{v}'"))
        #print(f"Conditions: {conditions}     {optional_clauses}")
    return conditions, optional_clauses

def is_flat_pattern(pattern):
    """Devuelve True si el patrón no contiene subniveles (dicts/listas)."""
    if not isinstance(pattern, dict):
        return False
    # Si contiene secciones conocidas, no es plano
    if any(k in pattern for k in ("spec", "metadata")):
        return False
    # Solo consideramos plano si todos los valores son simples
    return all(not isinstance(v, (dict, list)) for v in pattern.values())


"""def build_expression(feature, value):
    val_str = str(value).strip()

    # 1. Caso NULL -> !feature
    if val_str.lower() == "null":
        return f"!{feature}"

    # 2. Caso BOOLEANOS -> feature o !feature
    # ESTE ES EL CAMBIO CLAVE QUE BUSCABAS
    if val_str.lower() == "true":
        return f"{feature}"   # Equivale a "feature == true"
    if val_str.lower() == "false":
        return f"!{feature}"  # Equivale a "feature == false"

    # 3. Caso NÚMEROS (Sin comillas)
    if re.match(r"^-?\d+(\.\d+)?$", val_str):
        return f"{feature} == {val_str}"

    # 4. Caso NEGACIÓN (!)
    if val_str.startswith("!"):
        clean_val = val_str[1:]
        
        # Si negamos un booleano explícito (!true / !false)
        if clean_val.lower() == "true":
            return f"!{feature}" # !true es false
        if clean_val.lower() == "false":
            return f"{feature}"  # !false es true
            
        # Si es número
        if re.match(r"^-?\d+(\.\d+)?$", clean_val):
            return f"{feature} != {clean_val}"
            
        # String normal
        return f"{feature} != '{clean_val}'"

    # 5. Caso RANGOS O MULTI-VALOR (Kyverno "|")
    if "|" in val_str:
        return f"{feature} == '{val_str}'"

    # 6. Caso STRINGS (Default -> Con comillas simples)
    return f"{feature} == '{val_str}'"""


def build_expression(feature, value):
    """Construye la expresión UVL adecuada según el valor detectado."""
    """if value is None or str(value).lower() == "null":
        return f"!{feature}"
    if str(value).lower() in ("true", "false"):
        return f"{feature} = {str(value).lower()}"
    if isinstance(value, (int, float)) or re.match(r"^\d+(\.\d+)?$", str(value).strip()):
        return f"{feature} = {value}"""
    ### Used before
    if isinstance(value, str) and value.startswith("!"):
        clean_val = value[1:]
        if '.' in clean_val:
            clean_val = clean_val.replace('.', '_')
        return f"{feature} != '{clean_val}'"
    return f"{feature} == '{value}'"

def extract_constraints_from_policy(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        policy = yaml.safe_load(f)

    metadata = policy.get("metadata", {})
    annotations = metadata.get("annotations", {})
    title = annotations.get("policies.kyverno.io/title", metadata.get("name", ""))
    name = sanitize(title)
    #print(f"NAMES OF TITLES:  {name}")

    grouped_conditions = {}  # policy_name → list of conditions
    opt_clauses = []
    spec = policy.get("spec", {})
    action = spec.get("validationFailureAction", "") ## type of approach
    #rules = policy.get("spec", {}).get("rules", [])
    rules = spec.get("rules", [])

    #print(f"RULES:  {rules}")
    for rule in rules:
        kind_prefixes = get_kind_prefixes_from_rule(rule)
        pattern = rule.get("validate", {}).get("pattern", {})
        preconds = rule.get("preconditions", {}) ## New case of preconditions, validationFailureAction: Enforce
        ## difference betwwn actions
        # 🔹 1. Detectar y procesar patrones planos (sin spec/metadata)
        if is_flat_pattern(pattern) and action == 'Audit': ## Adding action for differences bettween 
            print(f" Detectado patrón plano en {filepath}")
            for k, v in pattern.items():
                for kind_prefix in kind_prefixes:
                    base_prefix = get_base_prefix(kind_prefix)
                    feature = f"{base_prefix}.{kind_prefix}{sanitize(k)}"
                    if str(v).lower() == "false":
                        expr = f"{feature} = false"
                    elif str(v).lower() == "true":
                        expr = f"{feature} = true"
                    elif re.match(r"^\d+(\.\d+)?$", str(v).strip()):
                        expr = f"{feature} = {v}"
                    else:
                        if v is None or str(v).lower() == "null":
                            print(f"Expr flatten distarcet null: !{feature}")
                            continue
                        if '.' in v:
                            v = v.replace('.', '_')
                        if '!' in v:
                            aux_value = v.replace("!", "")
                            expr = f"{feature} != '{aux_value}'"
                        else:
                            expr = f"{feature} == '{v}'"
                        print(f"Expr flatten distarcet: {expr}")
                    grouped_conditions.setdefault(name, []).append(expr)
            continue

        if preconds and action == 'Enforce':
            any_conds = preconds.get("any", []) or preconds.get("all", [])
            for cond in any_conds:
                key = cond.get("key", "")
                operator = cond.get("operator", "")
                value = cond.get("value", "")
                if '.' in value:
                    value = value.replace('.', '_') 
                # limpiar key para extraer el campo real del request.object
                key_clean = key.replace("{{ request.object.", "").replace(" }}", "")
                key_clean = key_clean.replace("[0]", "").replace("|| ''", "").strip()
                
                for kind_prefix in kind_prefixes:
                    if "Job" in kind_prefix:
                        base_prefix = "Job"
                    else:
                        base_prefix = "Kubernetes"

                    full_feature = f"{base_prefix}.{sanitize(kind_prefix + key_clean)}"

                    if operator.lower() == "notequals":
                        expr = f"{full_feature} == '{value}'"
                    elif operator.lower() == "equals":
                        expr = f"{full_feature} == '{value}'"
                    elif operator.lower() == "anyin":
                        expr = f"{full_feature} == '{value}'"  # simplificado
                    else:
                        expr = f"{full_feature} = '{value}'"

                    grouped_conditions.setdefault(name, []).append(expr)
            continue
        #if "spec" in pattern:
        #    conditions, optional_clauses_from_spec = extract_conditions_from_spec(pattern["spec"], prefix="spec", kind_prefixes= kind_prefixes)
        for section_key in pattern:
            #print(f"CLAVES DE LAS SECCIONES:     {section_key}")
            clean_key = section_key.strip("=() ")
            #print(f"CLAVES LIMPIAS:     {clean_key}")
            if clean_key == "spec":
                extractor = extract_conditions_from_spec
            elif clean_key == "metadata":
                extractor = extract_conditions_from_metadata
            else:
                subpattern = pattern[section_key]

                if isinstance(subpattern, dict):
                    #print(f" Procesando bloque genérico (dict): {clean_key} en {filepath}")
                    for subkey, subval in subpattern.items():
                        for kind_prefix in kind_prefixes:
                            base_prefix = get_base_prefix(kind_prefix)
                            full_feature = f"{base_prefix}.{sanitize(kind_prefix + clean_key + '_' + subkey)}"
                            #print(f"Expr completa01 {full_feature}")
                            expr = build_expression(full_feature, subval)
                            grouped_conditions.setdefault(name, []).append(expr)
                    continue

                elif isinstance(subpattern, list):
                    #print(f" Procesando bloque genérico (list): {clean_key} en {filepath}")
                    for item in subpattern:
                        if not isinstance(item, dict):
                            continue
                        for subkey, subval in item.items():
                            for kind_prefix in kind_prefixes:
                                base_prefix = get_base_prefix(kind_prefix)
                                full_feature = f"{base_prefix}.{sanitize(kind_prefix + clean_key + '_' + subkey)}"
                                expr = build_expression(full_feature, subval)
                                grouped_conditions.setdefault(name, []).append(expr)
                    continue
                print(f" Sección no soportada aún: {section_key}")
                continue

            conditions, optional_clauses_from_spec = extractor(
                pattern[section_key],
                prefix=clean_key,
                kind_prefixes=kind_prefixes
            )

            for path, expected in conditions:
                for kind_prefix in kind_prefixes:
                    # Determinar el submodelo al que pertenece
                    base_prefix = get_base_prefix(kind_prefix)
                    full_feature = f"{base_prefix}.{sanitize(kind_prefix + path)}" ## se usa el kind_prefix encontrado. Se agrega aqui tb el prefijo de metadata..
                    #full_feature = f"Pod.{sanitize(kind_prefix + path)}" ## Deff of features from fm Kubernetes
                    #print(f"EXPECTED:   {expected}  {base_prefix}")
                    if expected == "null":
                        expr = f"!{full_feature}"
                    elif expected == "false": ## expected in ("true", "false"):
                        expr = f"{full_feature} = {expected}"
                    elif expected == True: ## Case of True; readOnlyRootFilesystem 
                        expr = f"{full_feature}"
                    else:
                        #if isinstance(expected, str) and expected.startswith("'!"):
                        #    print(f"CASO ESPECIAL STR NEGADO    {expected}")
                        # Si es un número (int o float), usar un único '='
                        if re.match(r"^\d+(\.\d+)?$", str(expected).strip()):
                            expr = f"{full_feature} = {expected}"
                        else:
                            if optional_clauses_from_spec:
                                continue
                            ## Probar mod de los string con ! aqui ###
                            if '!' in expected:
                                aux_expected = expected.replace("!", "")
                                expr = f"{full_feature} != '{aux_expected}'"
                            else:
                                expr = f"{full_feature} == {expected}"

                    grouped_conditions.setdefault(name, []).append(expr)
            # Add the constraints
            #for clause in opt_clauses:
            #    grouped_conditions.setdefault(name, []).append(clause)
            #print(f"Optional clauses {optional_clauses_from_spec}")
            opt_clauses.extend(optional_clauses_from_spec)

    return grouped_conditions, {name: opt_clauses}

def extract_constraints_from_deny_conditions(policy):
    constraints_by_policy = {}
    metadata = policy.get("metadata", {})
    annotations = metadata.get("annotations", {})
    title = annotations.get("policies.kyverno.io/title", metadata.get("name", ""))
    policy_feature = sanitize(title)

    rules = policy.get("spec", {}).get("rules", [])
    for rule in rules:
        deny = rule.get("validate", {}).get("deny", {})
        conditions_block = deny.get("conditions", {})

        if isinstance(conditions_block, dict) and "all" in conditions_block:
            conditions = conditions_block["all"]
        else:
            conditions = conditions_block

        kind_prefixes = get_kind_prefixes_from_rule(rule)

        exprs_by_feature = {}

        for cond in conditions:
            if not isinstance(cond, dict):
                continue

            key = cond.get("key", "")
            operator = cond.get("operator", "")
            values = cond.get("value", [])

            if isinstance(values, str):
                #print(f"Valores del value:  {values}")
                values = [values]

            if "spec." in key:
                raw_path = key.split("request.object.")[-1]
                raw_path = raw_path.replace("{{", "").replace("}}", "").strip()
                expanded_paths = expand_path_brackets(raw_path)

                for kind_prefix in kind_prefixes:
                    for path in expanded_paths:
                        sanitized_path = sanitize(path)
                        feature_base = f"Pod.{kind_prefix + sanitized_path}" ## Change de basic_prefix for the Imported module?
                        if feature_base.endswith("_"):
                            feature_base = feature_base[:-1]
                        if (isinstance(values, list) and len(values) > 0) and operator and feature_base:
                            for v in values:
                                if operator == "AnyNotIn":
                                    if isinstance(v, str) and "-" in v:
                                        try:
                                            start, end = v.split("-")
                                            start = int(start) - 1
                                            end = int(end) + 1
                                            condition = f"({feature_base} > {start} & {feature_base} < {end})"
                                        except ValueError:
                                            continue
                                    else:
                                        condition = f"{feature_base} = {v}"
                                    exprs_by_feature.setdefault(feature_base, []).append(condition)
                        elif isinstance(values, int):
                            if operator == "GreaterThan":
                                condition = f"{feature_base} > {values}"
                            elif operator == "LessThan":
                                condition = f"{feature_base} < {values}"
                            else:
                                continue
                            exprs_by_feature.setdefault(feature_base, []).append(condition)
                            print(f"Salida provisional de error en values INT: {condition}  {feature_base}")

        # Agroup the expressions by features
        all_exprs = []
        for base, conds in exprs_by_feature.items():
            if len(conds) > 1:
                all_exprs.append(f"({' | '.join(conds)})")
            elif conds:
                all_exprs.append(conds[0])

        if all_exprs:
            if len(all_exprs) > 1:
                combined = f"({' & '.join(all_exprs)})"
            else:
                combined = all_exprs[0]
            constraints_by_policy.setdefault(policy_feature, []).append(combined)

    return constraints_by_policy

def expand_path_brackets(path):
    def expand(p):
        m = re.search(r'\[([^\]]+)\]', p)
        if not m:
            return [p.replace("[]", "")]
        pre = p[:m.start()]
        post = p[m.end():]
        options = [opt.strip() for opt in m.group(1).split(',')]
        expanded = []
        for opt in options:
            expanded += expand(pre + opt + post)
        return expanded

    return expand(path)

def extract_conditions_from_spec(obj, prefix="spec", kind_prefixes = None):
    conditions = []
    optional_clauses = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            #print(f"Key value   {k}   {v}")
            key = k.strip("=() ").replace("X(", "").replace(")", "")
            new_prefix = f"{prefix}_{key}"

            if key in special_features_config: ## Change the special features if procedure
                new_prefix = f"{new_prefix}_nameStr"
                #print(f"New Prefix: {new_prefix}")

            elif new_prefix.endswith('seccompProfile_type'):
                # Este bloque detecta claves como:
                # =(seccompProfile.type): "RuntimeDefault | Localhost"
                if k.startswith("=(") and v and "|" in v:
                    base_feature = new_prefix  # sin los valores
                    allowed_values = []
                    values = [val.strip() for val in v.split("|")]
                    for value in values:
                        clean_val = value.strip()
                        sub_feature = f"{base_feature}_{clean_val}"
                        allowed_values.append(sub_feature)
                 
                    clauses = build_optional_clause(base_feature, allowed_values, kind_prefixes)
                    if isinstance(clauses, list):
                        optional_clauses.extend(clauses)
                    else:
                        optional_clauses.append(clauses)                                     
            
            if isinstance(v, dict):
                #conditions.extend(extract_conditions_from_spec(v, new_prefix))
                #¡print(f"V IF V   {v}   {new_prefix}")
                child_conditions, child_optional_clauses = extract_conditions_from_spec(v, new_prefix, kind_prefixes)
                conditions.extend(child_conditions)
                optional_clauses.extend(child_optional_clauses)                
            elif isinstance(v, list) and len(v) > 0 and isinstance(v[0], dict):
                #conditions.extend(extract_conditions_from_spec(v[0], new_prefix))
                #print(f"V list elif   {v}   {new_prefix}")
                child_conditions, child_optional_clauses = extract_conditions_from_spec(v[0], new_prefix, kind_prefixes) ## Prevent
                conditions.extend(child_conditions)
                optional_clauses.extend(child_optional_clauses)             
            else:
                #print(f"ELSE   {v}   {new_prefix}") ## caso spec defaultBackend: se arregla con la deteccion automatica del prefijo y cambio
                if isinstance(v, str):
                    ## No usa values con punto
                    if v.lower() == "false":
                        v = "false"
                    elif v.lower() == "true": ## Caso readOnlyRootFilesystem
                        v = "true"
                    elif v.strip().lower() == "null":
                        v = "null"
                    elif v.isdigit():
                        #print(f"Valores DIGIT   {v}")
                        v = v  # número como string, no cambiar
                    elif 'spec_type' in new_prefix: ## Case which we can define as a Alternative match Strings
                            aux_value = v
                            if '!' in aux_value:
                                aux_value = v.replace("!","")
                                v = "false"
                                ## boolean negado
                            ##caso normal
                            else:
                                v = "true"
                            new_prefix = f"{new_prefix}_{aux_value}"
                    elif '<'  in v or '>' in v: ## Not works actually for string max, min
                        s = v.strip()

                        # Captura operadores: <, >, <=, >=  y el valor a la derecha (si existe)
                        m = re.match(r'^\s*(<=|>=|<|>)\s*(.+?)\s*$', s)

                        if not m:
                            # Caso raro: tiene < o > pero no es "operador valor" (ej: "a < b")
                            # Decide: o lo dejas como string tal cual, o lo registras y sigues
                            value_int = None
                            # v se queda igual
                        else:
                            op, raw_rhs = m.group(1), m.group(2).strip()

                            # Si no hay nada a la derecha, evitamos el IndexError y lo tratamos como string
                            if raw_rhs == "":
                                value_int = None
                                v = op  # o v = s, según lo que quieras
                            else:
                                # Int si es entero (soporta negativos). Si no, string.
                                if re.fullmatch(r'-?\d+', raw_rhs):
                                    value_int = int(raw_rhs)
                                    v = f"{op} {value_int}"
                                else:
                                    value_int = raw_rhs
                                    v = f"{op} {raw_rhs}"
                              
                        if new_prefix.endswith('spec_maxUnavailable'): ## specific case for alternatyve types values; asString, asInteger
                            new_prefix = f"{new_prefix}_asInteger" if isinstance(value_int, int) else f"{new_prefix}_asString"
                    
                    else: ## fallback
                        if '.' in v: ## Remove the points in values of strings
                            v = v.replace('.', '_')
                        v = str(v)  #v = f"'{str(v)}'"
                        #print(f"{v} {new_prefix}")
                elif isinstance(v, (int, float)):
                    #print(f"Valores Caso INT   {v}")
                    v == str(v)
                elif isinstance(v,list): ## Capture cases where the value is a arr not typed yet
                    if new_prefix.endswith('spec_accessModes'): ## Specific case for the personality modification of the representation of the String Arrays
                        for value_access in v:
                            v = value_access
                        new_prefix = f"{new_prefix}_StringValue"
                    else:
                        print(f"Case not evaluated: {new_prefix}")
                else:
                    # fallback
                    print(f"Valores fallback   {v}")
                    v = f"{str(v)}" ##v = f"'{str(v)}'"
                
                conditions.append((new_prefix, v))
    return conditions, optional_clauses