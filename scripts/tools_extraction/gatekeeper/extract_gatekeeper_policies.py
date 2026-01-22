import yaml
import os
from pathlib import Path
from collections import defaultdict
from tools_extraction.gatekeeper.gatekeeper_rego_parser import extract_gatekeeper_conditions_from_rego
from tools_extraction.extract_policies_general import (
    load_kinds_prefix_mapping,
    load_feature_dict,
    clean_description,
    get_base_prefix,
    normalize_kind_name,
)

# ============================================================
# Helpers básicos
# ============================================================

def normalize_rego_path(rego_path):
    # Eliminamos el prefijo 'container.' para que no interfiera
    if rego_path.startswith("container."):
        return rego_path.replace("container.", "")
    return rego_path


def load_yaml(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"[ERROR] No se pudo cargar {path}: {e}")
        return None


def sanitize(name: str) -> str:
    return (
        name.replace("-", "_")
            .replace(".", "_")
            .replace("/", "_")
            .replace(" ", "_")
    )


def is_constraint_template(obj: dict) -> bool:
    return isinstance(obj, dict) and obj.get("kind") == "ConstraintTemplate"


def is_constraint(obj: dict) -> bool:
    api = obj.get("apiVersion", "")
    return isinstance(obj, dict) and "constraints.gatekeeper.sh" in api


# ============================================================
# Extracción de REGO desde Templates
# ============================================================

def get_rego_blocks_from_template(template_obj: dict):
    regos = []
    spec = template_obj.get("spec", {})
    targets = spec.get("targets", []) or []

    for t in targets:
        # Formato nuevo: code[]
        code_list = t.get("code", [])
        if isinstance(code_list, list):
            for entry in code_list:
                if entry.get("engine") == "Rego":
                    src = entry.get("source", {})
                    rego_txt = src.get("rego")
                    if isinstance(rego_txt, str):
                        regos.append(rego_txt)

        # Formato viejo: target.rego
        if "rego" in t and isinstance(t["rego"], str):
            regos.append(t["rego"])

    return regos


# ============================================================
# Mapeo REGO → UVL (paths → features)
# ============================================================

def find_gatekeeper_uvl_paths(kind, rego_path, feature_dict, kind_map):
    """
    Mapea un path de REGO a uno o varios features UVL,
    sin codificar políticas específicas.
    """
    real_kind = normalize_kind_name(kind, kind_map)   # p.ej. 'Pod'

    cleaned = rego_path.replace("[*]", "").replace("[]", "").strip()
    parts = cleaned.split(".")
    #print(f"Cleaned     {cleaned}   parts   {parts}")
    suffix = cleaned.replace(".", "_")

    suffix = suffix.lower()
    #print(f"Suffix     {suffix}")
    candidates = []

    for midle, row in feature_dict.items():
        # midle = 'Pod_spec_ephemeralContainers_securityContext_privileged'
        if not midle.startswith(real_kind + "_"):
            continue
        if midle.lower().endswith(suffix):
            candidates.append(row["Feature"])

    return candidates


# ============================================================
# Constraint.kind -> lista de K8s Kinds (Pod, Deployment, ...)
# ============================================================

def build_constraint_kind_map(root_directory: str):
    root = Path(root_directory)
    mapping = {}  # constraintKind -> set(k8sKinds)

    for path in root.rglob("*.yaml"):
        obj = load_yaml(path)
        if not obj or not is_constraint(obj):
            continue

        constraint_kind = obj.get("kind")
        spec = obj.get("spec", {})
        match = spec.get("match", {})
        kinds_block = match.get("kinds", []) or []

        for kentry in kinds_block:
            klist = kentry.get("kinds", []) or []
            for k in klist:
                mapping.setdefault(constraint_kind, set()).add(k)

    return {k: sorted(list(v)) for k, v in mapping.items()}


def build_constraint_params_summary(root_directory: str):
    """
    kind -> param_name -> set(values)
    Es GENERAL: no codifica nombres de políticas ni parámetros.
    """
    root = Path(root_directory)
    summary = {}  # kind -> param_name -> set(values)

    for path in root.rglob("*.yaml"):
        obj = load_yaml(path)
        if not obj or not is_constraint(obj):
            continue

        kind = obj.get("kind")
        spec = obj.get("spec", {})
        params = spec.get("parameters", {})

        if not params or not isinstance(params, dict):
            continue

        kmap = summary.setdefault(kind, {})

        for pname, pvalue in params.items():
            vset = kmap.setdefault(pname, set())

            # escalares
            if isinstance(pvalue, (str, int, float, bool)):
                vset.add(str(pvalue))

            # listas
            elif isinstance(pvalue, list):
                for elem in pvalue:
                    if isinstance(elem, (str, int, float, bool)):
                        vset.add(str(elem))
                    elif isinstance(elem, dict):
                        prefix = elem.get("pathPrefix", None)
                        ro = elem.get("readOnly", None)
                        if prefix is not None:
                            if ro is None:
                                vset.add(f"pathPrefix={prefix}")
                            else:
                                vset.add(f"pathPrefix={prefix},readOnly={ro}")
                        else:
                            vset.add(str(elem))
                    else:
                        vset.add(str(elem))

            # objetos
            elif isinstance(pvalue, dict):
                vset.add(str(pvalue))

            else:
                vset.add(str(pvalue))

    return summary


# ============================================================
# Helpers para parámetros → símbolos UVL
# ============================================================

def make_param_symbol(template_name: str, param_name: str) -> str:
    """
    Construye un identificador simbólico para un parámetro de política.
    Ej: template_name='k8spsphostnetworkingports', param_name='hostNetwork'
    -> HOSTNETWORK_k8spsphostnetworkingports
    """
    base = template_name.replace("-", "_")
    return f"{param_name.upper()}_{base}"


def make_range_param_symbol(template_name: str, bound: str) -> str:
    """
    bound: 'min' | 'max'
    -> MIN_k8spsphostnetworkingports / MAX_k8spsphostnetworkingports
    """
    base = template_name.replace("-", "_")
    return f"{bound.upper()}_{base}"


# ============================================================
# REGO → expresiones UVL (usando parámetros si existen)
# ============================================================
def extract_constraints_from_yaml(constraint_path):
    """
    Lee constraint.yaml y devuelve dict plano con los parámetros reales,
    soportando:
      - booleanos
      - enteros
      - strings
      - arrays de strings (volumes, exemptImages...)
      - arrays de objetos (allowedHostPaths)
    """
    if not os.path.exists(constraint_path):
        return {}

    with open(constraint_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    params = data.get("spec", {}).get("parameters", {})

    extracted = {}

    for key, val in params.items():

        # STRING
        if isinstance(val, str):
            extracted[key] = val

        # BOOLEAN
        elif isinstance(val, bool):
            extracted[key] = val

        # INTEGER
        elif isinstance(val, int):
            extracted[key] = val

        # LIST OF STRINGS
        elif isinstance(val, list) and all(isinstance(x, str) for x in val):
            extracted[key] = ", ".join(val)

        # LIST OF OBJECTS (hostFilesystem)
        elif isinstance(val, list) and all(isinstance(x, dict) for x in val):
            pretty = []
            for obj in val:
                parts = []
                for k2, v2 in obj.items():
                    parts.append(f"{k2}={v2}")
                pretty.append("(" + ",".join(parts) + ")")
            extracted[key] = ", ".join(pretty)

        # fallback — serialize
        else:
            extracted[key] = str(val)

    return extracted



def build_uvl_expressions_for_template(
    template_name: str,
    rego_blocks,
    k8s_kinds,
    feature_dict,
    kind_map,
    params_for_kind,
):
    expressions = []

    # --------------------------------------------------
    # Auxiliar: extremos numéricos para min/max de puertos
    # --------------------------------------------------
    def get_numeric_extreme(pname: str, mode: str):
        """
        mode: 'min' → valor mínimo, 'max' → valor máximo
        Trabaja sobre el set de strings params_for_kind[pname].
        Si no son numéricos, devuelve None.
        """
        if not params_for_kind or pname not in params_for_kind:
            return None
        raw_vals = params_for_kind[pname]
        nums = []
        for v in raw_vals:
            try:
                nums.append(float(v))
            except Exception:
                # Si algún valor no es numérico, abortamos para ese parámetro
                return None
        if not nums:
            return None
        return min(nums) if mode == "min" else max(nums)

    tmpl_base = os.path.splitext(os.path.basename(template_name))[0].lower()

    for rego in rego_blocks:
        #print(f"Rego path   {rego}")
        paths = extract_gatekeeper_conditions_from_rego(rego)
        if not paths:
            continue

        for k8s_kind in k8s_kinds:
            #print(f"Kind    {k8s_kind}")
            base_prefix = get_base_prefix(k8s_kind.capitalize())

            for p in paths:
                # 1) Normalizar el path (quitar índices y ']' residuales)
                cleaned = (
                    p.replace("[*]", "")
                    .replace("[]", "")
                    .replace("[_]", "")
                    .strip()
                )
                # a veces se queda un ']' suelto al final (p.ej. 'securityContext]')
                if cleaned.endswith("]"):
                    cleaned = cleaned.rstrip("]")

                parts = cleaned.split(".") if cleaned else []

                # Ignorar spec.volumes SOLO para hostFilesystem
                if cleaned == "spec.volumes" and tmpl_base in ("k8spsphostfilesystem", "hostfilesystem"):
                    print(f"[INFO] Ignorando {cleaned} para template {tmpl_base}")
                    continue

                last = parts[-1].lower() if parts else ""

                # Buscar features UVL para este path
                features = find_gatekeeper_uvl_paths(
                    k8s_kind, cleaned, feature_dict, kind_map
                )
                if not features:
                    print(f"[WARNING] No UVL mapping for path '{p}' in kind '{k8s_kind}'")
                    continue

                # ------------------------------------------------
                # CASO ESPECIAL 1: rangos de puertos (hostPort/ContainerPort/NodePort)
                #         → usamos parámetros numéricos min/max.
                # ------------------------------------------------
                if last in ("hostport", "containerport", "nodeport") and params_for_kind:
                    # min
                    if "min" in params_for_kind:
                        num_min = get_numeric_extreme("min", "min")
                        if num_min is not None:
                            for feature in features:
                                expr = f"{base_prefix}.{feature} > {int(num_min)}"
                                expressions.append(expr)
                    # max
                    if "max" in params_for_kind:
                        num_max = get_numeric_extreme("max", "max")
                        if num_max is not None:
                            for feature in features:
                                expr = f"{base_prefix}.{feature} < {int(num_max)}"
                                expressions.append(expr)
                    # ya manejado; no caemos en el comportamiento por defecto
                    continue

                # ------------------------------------------------
                # CASO ESPECIAL 2: k8spspvolumetypes (volumes)
                #         Queremos algo del estilo:
                #         Pod.spec.volumes_type == (configMap | secret | ...)
                #         usando los valores reales de constraint.yaml
                # ------------------------------------------------
                if tmpl_base in ("k8spspvolumetypes", "volumetypes") and cleaned == "spec.volumes":
                    if params_for_kind and "volumes" in params_for_kind:
                        vols = sorted(params_for_kind["volumes"])
                        if vols and "*" not in vols:
                            # Solo usamos el primer feature (lo normal es que haya uno)
                            feature = features[0]
                            enum_vals = " | ".join(vols)
                            expr = f"{base_prefix}.{feature} == ({enum_vals})"
                            expressions.append(expr)
                            # IMPORTANTE: no añadimos la negación por defecto
                            continue
                    # Si no hay params o contienen '*', caemos al caso genérico (negación)

                # ------------------------------------------------
                # CASO POR DEFECTO:
                #   - parámetros booleanos (hostNetwork, privileged, hostPID/IPС…)
                #   - paths normales sin rango ni enum explícito
                # Se modela como "no debe darse la condición de violación":
                #         → negación del feature.
                # ------------------------------------------------
                for feature in features:
                    expr = f"!{base_prefix}.{feature}"
                    expressions.append(expr)

    # Deduplicar expresiones
    uniq = []
    seen = set()
    for e in expressions:
        if e not in seen:
            uniq.append(e)
            seen.add(e)

    return uniq
# ============================================================
# Conversión Template → {feature, constraint}
# ============================================================

def gatekeeper_template_to_uvl(
    template_obj,
    constraint_kind_map,
    feature_dict,
    kind_map,
    constraint_params_summary,
):
    """
    Convierte un ConstraintTemplate de Gatekeeper en:
    - feature UVL (enriquecido con parámetros agregados)
    - constraint UVL (usando REGO + parámetros)
    """
    meta = template_obj.get("metadata", {})
    annotations = meta.get("annotations", {}) or {}

    tmpl_name = sanitize(meta.get("name", "") or "GatekeeperTemplate")
    description = annotations.get("description", "") or annotations.get(
        "metadata.gatekeeper.sh/title", ""
    )

    # Tipo de CRD: K8sPSPPrivilegedContainer, etc.
    crd_kind = (
        template_obj.get("spec", {})
        .get("crd", {})
        .get("spec", {})
        .get("names", {})
        .get("kind", "")
    )

    # Kinds K8s a los que se aplica este template
    k8s_kinds = constraint_kind_map.get(crd_kind, [])
    if not k8s_kinds:
        # fallback razonable: la mayoría de PSP se aplican a Pod
        k8s_kinds = ["Pod"]

    rego_blocks = get_rego_blocks_from_template(template_obj)

    # ----------------- Feature UVL -----------------
    attrs = []
    # tool
    attrs.append("tool 'Gatekeeper'")
    # severity (Gatekeeper no la tiene → default)
    severity = annotations.get("severity", "undefined")
    attrs.append(f"severity '{severity}'")
    # category
    category = annotations.get("metadata.gatekeeper.sh/title", "") or annotations.get("category", "") or "General"
    attrs.append(f"category '{sanitize(category)}'")
    # kinds (convertido en string)
    kinds_str = ",".join(k8s_kinds)
    attrs.append(f"kinds '{kinds_str}'")
    # Doc of feature
    if description:
        attrs.append(f"doc '{clean_description(description)}'")
    # parámetros agregados para este CRD kind (si los hay)
    params_for_kind = constraint_params_summary.get(crd_kind, {})
    for pname, values in params_for_kind.items():
        joined = ", ".join(sorted(values))
        #attrs.append(f"{pname} '{joined}'")

    feature_line = f"{tmpl_name} {{{', '.join(attrs)}}}"

    # Si no hay REGO, no generamos constraint
    if not rego_blocks:
        return {
            "feature": feature_line,
            "constraint": None,
        }

    # ----------------- Constraint UVL -----------------
    exprs = build_uvl_expressions_for_template(
        tmpl_name,
        rego_blocks,
        k8s_kinds,
        feature_dict,
        kind_map,
        params_for_kind
    )

    if not exprs:
        return {
            "feature": feature_line,
            "constraint": None,
        }

    body = " & ".join(exprs) if len(exprs) > 1 else exprs[0]
    constraint_line = f"{tmpl_name} => {body}"

    return {
        "feature": feature_line,
        "constraint": constraint_line,
    }


# ============================================================
# Punto de entrada: escanear todo el library de Gatekeeper
# ============================================================

def extract_gatekeeper_policies(root_directory: str):
    """
    Procesa un directorio con la librería de Gatekeeper (ej: 'library/')
    y devuelve una lista de:
        { "feature": "<línea UVL>", "constraint": "<línea UVL>" }
    """
    root = Path(root_directory)

    # Carga mappings desde tus CSV
    feature_dict = load_feature_dict(
        "../resources/mapping_csv/kubernetes_mapping_properties_features.csv"
    )
    kind_map = load_kinds_prefix_mapping(
        "../resources/mapping_csv/kubernetes_kinds_versions_detected.csv"
    )

    # Mapa CRDKind -> [Pod, Deployment, ...]
    constraint_kind_map = build_constraint_kind_map(root_directory)
    # kind -> param_name -> set(values)
    constraint_params_summary = build_constraint_params_summary(root_directory)

    results = []

    for path in root.rglob("*.yaml"):
        obj = load_yaml(path)
        if not obj or not is_constraint_template(obj):
            continue

        item = gatekeeper_template_to_uvl(
            obj,
            constraint_kind_map,
            feature_dict,
            kind_map,
            constraint_params_summary,
        )
        results.append(item)

    return results


# ============================================================
# Script standalone (debug / prueba)
# ============================================================

if __name__ == "__main__":
    # Ajusta esta ruta a tu copia local del Gatekeeper library
    library_dir = "../resources/gatekeeper-library"

    policies = extract_gatekeeper_policies(library_dir)

    print("###### RESULTADOS GATEKEEPER → UVL ######")
    for p in policies:
        print("\nFeature:")
        print(" ", p["feature"])
        if p["constraint"]:
            print("Constraint:")
            print(" ", p["constraint"])