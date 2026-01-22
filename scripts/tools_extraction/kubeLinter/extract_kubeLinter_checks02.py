# extract_kubeLinter_checks.py

import os
import yaml
import csv
import re

# -------------------------------------------------------------------
#  FM HELPERS  (mismo estilo que en Rego / Polaris)
# -------------------------------------------------------------------

def load_feature_dict(csv_file="../resources/mapping_csv/kubernetes_mapping_properties_features.csv"):
    """
    Carga el CSV del FM de Kubernetes en un dict indexado por 'Midle'.

    row:
      Feature, Midle, Turned, Value
    """
    feature_dict = {}
    with open(csv_file, newline='', encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            midle = row["Midle"].strip()
            feature_dict[midle] = row
    return feature_dict


def load_kinds_prefix_mapping(file_path="../resources/mapping_csv/kubernetes_kinds_versions_detected.csv") -> dict:
    """
    Crea dict {Kind: Prefix} desde CSV generado por mappingUvlCsvK8sOld.py

    Version,Kind,Prefix
    ... ,Pod,io_k8s_api_core_v1
    """
    mapping = {}
    with open(file_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            kind = row["Kind"].strip()
            prefix = row["Prefix"].strip()
            mapping[kind] = prefix
    return mapping


def normalize_kind_name(kind, kind_map):
    """
    Intenta casar un nombre de kind (case-insensitive) con alguno del mapping.
    Ej: 'pod' o 'podspec' → 'Pod' si existe en kind_map.
    """
    kind_lower = kind.lower()
    for k in kind_map.keys():
        if k.lower() == kind_lower:
            return k
    # fallback
    return kind.capitalize()


# -------------------------------------------------------------------
#   PARSEO DE CHECKS KUBELINTER (YAML)
# -------------------------------------------------------------------

def parse_kubelinter_check(path):
    """
    Parsea el YAML de un check de KubeLinter.

    Esperamos estructura tipo:

    name: "privileged-container"
    description: ...
    remediation: ...
    scope:
      objectKinds:
        - DeploymentLike
    template: "privileged"
    params: ...
    """
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        return None

    check_id = data.get("template", "")     # clave que identifica template
    name = data.get("name", "")
    template = data.get("template", "")
    description = data.get("description", "")
    remediation = data.get("remediation", "")
    scope = data.get("scope", {})
    params = data.get("params", {})

    return {
        "id": check_id or template or name,
        "name": name,
        "template": template,
        "description": description,
        "remediation": remediation,
        "scope": scope,
        "params": params,
        "raw": data,
    }


# -------------------------------------------------------------------
#  MAPEADOR DE TEMPLATES → CONDICIONES SEMÁNTICAS
# -------------------------------------------------------------------

def derive_context_from_scope(scope):
    """
    Muy simple (y ampliable): dada la scope.objectKinds, devolvemos un "contexto"
    lógico que después mapearemos a Kinds reales.

    Ejemplos:
      DeploymentLike → Pod_spec_containers
      PodLike        → Pod_spec_containers
      DaemonSetLike  → Pod_spec_containers
      Service        → Service_spec_...
    """
    obj_kinds = scope.get("objectKinds", []) if isinstance(scope, dict) else []
    if not obj_kinds:
        return "Pod_spec_containers"

    # Por ahora, si aparece 'DeploymentLike' u otro *Like, asumimos Pod_spec_containers
    for ok in obj_kinds:
        if "deploymentlike" in ok.lower() or "podlike" in ok.lower():
            return "Pod_spec_containers"

    # Fallback general
    return "Pod_spec_containers"


def template_to_semantic_conditions(check):
    """
    Traduce un template concreto de KubeLinter a condiciones semánticas genéricas.

    Devuelve lista de tuplas:
      (context_str, prop_path, op, value)

    donde:
      - context_str: cadena tipo "Pod_spec_containers" (lógica/abstracta)
      - prop_path:   "securityContext.privileged"
      - op:          '==', '!=', '>=', ...
      - value:       True, False, número, None, etc.

    NOTA: Aquí es donde, a medida que amplíes, puedes añadir más plantillas
    conocidas (como hicimos con Polaris).
    """
    t = check["template"]
    scope = check["scope"]
    params = check["params"] or {}

    conds = []

    # Contexto lógico base (se puede refinar)
    ctx = derive_context_from_scope(scope)

    # --- privileged -------------------------------------------------
    # template: "privileged"
    # Semántica: falla si container.securityContext.privileged == true
    # Constraint deseada: "privileged-container => !Container.securityContext.privileged"
    if t == "privileged":
        conds.append((ctx, "securityContext.privileged", "!=", True))
        return conds

    # --- run-as-non-root -------------------------------------------
    # template: "run-as-non-root"
    #
    # Semántica (resumida):
    #   - O bien runAsUser > 0 (en Pod o en Container)
    #   - O bien runAsNonRoot == true (en Pod o Container)
    #   - Si runAsNonRoot==true y runAsUser==0 ⇒ error (caso especial)
    #
    # Para el FM, podemos aproximar como:
    #   runAsNonRoot (pod o contenedor) OR runAsUser>=1
    #
    # Lo modelamos en dos condiciones sencillas que luego se combinarán con OR
    if t == "run-as-non-root":
        # Pod-level
        conds.append(("Pod_spec", "securityContext.runAsNonRoot", "==", True))
        conds.append(("Pod_spec", "securityContext.runAsUser", ">=", 1))
        # Container-level:
        conds.append(("Pod_spec_containers", "securityContext.runAsNonRoot", "==", True))
        conds.append(("Pod_spec_containers", "securityContext.runAsUser", ">=", 1))
        return conds

    # Aquí podrás ir añadiendo otros templates estáticos:
    #   - "allow-privilege-escalation"
    #   - "host-ipc"
    #   - "host-network"
    #   - etc.
    #
    # Por ahora, si no conocemos el template → lista vacía
    return []


# -------------------------------------------------------------------
#  RESOLVER CONTEXTO LÓGICO → Kind + prefix
# -------------------------------------------------------------------

def context_to_kind(context_str):
    """
    Traducimos nuestro 'context_str' lógico a un Kind de Kubernetes
    que tenga sentido para el FM.

    Ejemplos:
      "Pod_spec_containers" → ("Pod", "containers")
      "Pod_spec"            → ("Pod", None)
      "Container"           → ("Container", None)  (si tuvieses Container como Kind separado)
    """
    if context_str == "Pod_spec_containers":
        return "Pod", "containers"
    if context_str == "Pod_spec":
        return "Pod", None
    # fallback simple:
    return "Pod", None


def find_feature_in_fm(kind, prop_path, feature_dict):
    """
    Busca en el FM una Feature que case con:
      - Kind (prefijo de Midle)
      - Propiedades encadenadas (prop_path)

    Ejemplo:
      kind      = "Pod"
      prop_path = "securityContext.runAsNonRoot"

    Buscaremos Midles tipo:
      Pod_spec_containers_securityContext_runAsNonRoot
      Pod_spec_securityContext_runAsNonRoot
    """
    # Convertimos dot-path a estilo Midle: a_b_c
    prop_key = prop_path.replace(".", "_")  # securityContext.runAsNonRoot → securityContext_runAsNonRoot

    candidates = []
    for midle, row in feature_dict.items():
        # midle empieza por 'Pod_spec' o 'Pod_spec_containers'...
        if not midle.startswith(kind + "_"):
            continue
        if prop_key in midle:
            candidates.append(row)

    if not candidates:
        return None

    # Elegimos el Midle más específico (más largo)
    best = max(candidates, key=lambda r: len(r["Midle"]))
    return best


# -------------------------------------------------------------------
#  CONSTRUCCIÓN DE EXPRESIONES UVL
# -------------------------------------------------------------------

def build_uvl_expr(kind_name: str, feature_full: str, op: str, val):
    """
    Construye expresión UVL a partir de:
      kind_name    → "Pod"
      feature_full → "io_k8s_api_core_v1_Pod_spec_containers_securityContext_runAsNonRoot"
      op           → '==', '!=', '>=', 'not_contains', ...
      val          → True/False/número/str

    Salidas ejemplo:
      - "!Pod.io_k8s_api_core_v1_Pod_spec_hostIPC"
      - "Pod.io_k8s_api_core_v1_Pod_spec_containers_securityContext_runAsUser > 0"
    """
    full = f"{kind_name}.{feature_full}"

    if op == "==":
        if isinstance(val, bool):
            if val is True:
                return full  # feature 'true'
            else:
                return f"!{full}"
        if isinstance(val, (int, float)):
            return f"{full} == {val}"
        if val is None:
            return f"{full} == null"
        return f"{full} == '{val}'"

    if op == "!=":
        if isinstance(val, bool):
            if val is True:
                return f"!{full}"
            else:
                return full  # != false  ~ feature 'true'
        if val is None:
            return f"{full} != null"
        return f"{full} != '{val}'"

    if op == ">=":
        return f"{full} > {val}"

    if op == "matches":
        return f"{full} matches '{val}'"

    if op == "not matches":
        return f"!({full} matches '{val}')"

    if op == "not_contains":
        # por ahora, modelo simplificado
        return f"{full}_StringValue != '{val}'"

    # Fallback
    return f"{full} {op} '{val}'"


# -------------------------------------------------------------------
#  CONVERSIÓN CHECK → (feature_block, constraint)
# -------------------------------------------------------------------

def kubelinter_check_to_uvl(check, feature_dict, kind_prefix_map):
    """
    Convierte un check de KubeLinter en un par UVL:
      (feature_block, constraint_expr)

    Si el template no está soportado aún, devuelve None.
    """
    print(f"\nCheck: {check['id']} ({check['name']})")
    print(check)

    semantic_conds = template_to_semantic_conditions(check)
    if not semantic_conds:
        print(f"  ⚠ Template '{check['template']}' aún no soportado → skip")
        return None

    uv_exprs = []

    for context_str, prop_path, op, val in semantic_conds:
        kind, _ = context_to_kind(context_str)
        real_kind = normalize_kind_name(kind, kind_prefix_map)

        if real_kind not in kind_prefix_map:
            print(f"    ⚠ No prefix for Kind={real_kind} (context={context_str})")
            continue

        prefix = kind_prefix_map[real_kind]
        fm_row = find_feature_in_fm(real_kind, prop_path, feature_dict)
        if not fm_row:
            print(f"    ⚠ No FM match for Kind={real_kind}, prop={prop_path}")
            continue

        # Construimos nombre de Feature completo desde CSV
        feature_full = fm_row["Feature"].strip()
        expr = build_uvl_expr(real_kind, feature_full, op, val)
        uv_exprs.append(expr)

    if not uv_exprs:
        print("  ❌ Ninguna condición mapeada a FM → skip")
        return None

    # Combinar condiciones. Para run-as-non-root, idealmente usar OR;
    # aquí empezamos con AND como base, y puedes refinar lógica según el template.
    feature_name = check["id"].replace("-", "_")
    doc = check["description"] or check["name"]

    feature_block = (
        f"{feature_name} "
        f"{{doc '{doc}', tool 'KubeLinter'}}"
    )

    # Estrategia simple: AND entre todas las condiciones
    constraint = f"{feature_name} => " + " & ".join(uv_exprs)
    return feature_block, constraint


# -------------------------------------------------------------------
#  MAIN: EXTRAER TODOS LOS CHECKS Y GENERAR UVL
# -------------------------------------------------------------------

if __name__ == "__main__":
    FEATURES_CSV = "../resources/mapping_csv/kubernetes_mapping_properties_features.csv"
    KINDS_CSV    = "../resources/mapping_csv/kubernetes_kinds_versions_detected.csv"
    CHECKS_DIR   = "../resources/kube_linter/checks_yamls"

    feature_dict   = load_feature_dict(FEATURES_CSV)
    kind_prefix_map = load_kinds_prefix_mapping(KINDS_CSV)

    results = []
    skipped  = []

    for root, _, files in os.walk(CHECKS_DIR):
        for fname in files:
            if not fname.endswith(".yaml"):
                continue
            full_path = os.path.join(root, fname)
            check = parse_kubelinter_check(full_path)
            if not check:
                continue
            uv = kubelinter_check_to_uvl(check, feature_dict, kind_prefix_map)
            if uv:
                results.append(uv)
            else:
                skipped.append((check["id"], check["template"]))

    print("\n\n### CHECKS MAPEADOS AUTOMÁTICAMENTE ###\n")
    for fb, cons in results:
        print(fb)
        print(cons)
        print("-" * 80)

    if skipped:
        print("\n### SKIPPED (sin template soportado) ###\n")
        for cid, t in skipped:
            print(f" - {cid} (template={t})")