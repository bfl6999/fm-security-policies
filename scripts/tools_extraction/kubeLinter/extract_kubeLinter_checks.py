# extract_kubelinter_checks.py

import os
import re
import yaml
from typing import Dict, List, Tuple, Optional

# ------------------------------
#  Types
# ------------------------------

Condition = Tuple[str, str, str, object]
# (context, prop_path, operator, value)
# e.g. ("Container", "securityContext.privileged", "!=", True)


# ------------------------------
# 1. Indexar templates Go por Key
# ------------------------------

KEY_RE = re.compile(r'Key\s*:\s*"([^"]+)"')


def index_templates_by_key(templates_root: str) -> Dict[str, str]:
    """
    Recorre pkg/templates/**/template.go y crea un índice:
        { template_key: source_code_str }

    No asume nada sobre nombres de carpetas: usa el campo Key del Template.
    """
    key_to_source: Dict[str, str] = {}

    for root, _, files in os.walk(templates_root):
        for f in files:
            if f != "template.go":
                continue
            path = os.path.join(root, f)
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    src = fh.read()
            except OSError:
                continue

            # Buscar Key: "run-as-non-root"
            for m in re.finditer(r'Key\s*:\s*"([^"]+)"', src):
                key = m.group(1).strip()
                key_to_source[key] = src

    return key_to_source


# ------------------------------
# 2. Heurísticas generales sobre el código Go
# ------------------------------

SEC_CTX_BLOCK_RE = re.compile(
    r"if\s+securityContext\s*:=\s*container\.SecurityContext;[^{]*\{(?P<body>.*?)\}",
    re.DOTALL,
)

BOOL_FIELD_TRUE_RE = re.compile(
    r"securityContext\.(?P<field>\w+)\s*!=\s*nil\s*&&\s*\*securityContext\.(?P=field)"
)


def go_field_name_to_json(field: str) -> str:
    """
    Convierte un nombre de campo Go (CamelCase/UpperCamel) a estilo JSON (lowerCamel),
    de forma muy simple: bajar la primera letra.
    Ej: "Privileged" -> "privileged"
        "RunAsNonRoot" -> "runAsNonRoot"
    """
    if not field:
        return field
    return field[0].lower() + field[1:]


def extract_conditions_from_template_go(src: str) -> List[Condition]:
    """
    Intenta extraer condiciones semánticas simples de un template Go.

    Actualmente soporta patrones tipo:

        if securityContext := container.SecurityContext; securityContext != nil {
            if securityContext.Privileged != nil && *securityContext.Privileged {
                // diagnostic
            }
        }

    → Se infiere:
        context = "Container"
        prop_path = "securityContext.privileged"
        op = "!="
        val = True  (es decir: la violación ocurre cuando privileged == true)

    Cualquier template que no siga estos patrones se devuelve vacío (y se loguea fuera).
    """
    conditions: List[Condition] = []

    # Buscar bloque de securityContext
    for m in SEC_CTX_BLOCK_RE.finditer(src):
        body = m.group("body")

        for bf in BOOL_FIELD_TRUE_RE.finditer(body):
            field_go = bf.group("field")           # ej: "Privileged"
            field_json = go_field_name_to_json(field_go)  # "privileged"

            # Interpretación semántica:
            #   Violación cuando field == true ⇒ queremos evitar "true"
            context = "Container"
            prop_path = f"securityContext.{field_json}"
            op = "!="
            val = True
            conditions.append((context, prop_path, op, val))

    return conditions


# ------------------------------
# 3. Leer checks YAML
# ------------------------------

def load_kubelinter_checks_yaml(checks_root: str) -> List[dict]:
    """
    Carga todos los checks YAML (no templates) desde el directorio 'checks_root'.
    Devuelve una lista de:
        {
          "name": ...,
          "description": ...,
          "template": ...,
          "objectKinds": [...],
          "params": {...}
        }
    """
    checks = []
    for root, _, files in os.walk(checks_root):
        for f in files:
            if not f.endswith(".yaml"):
                continue
            path = os.path.join(root, f)
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    data = yaml.safe_load(fh)
            except Exception:
                continue

            if not isinstance(data, dict):
                continue
            if "template" not in data:
                continue

            checks.append({
                "name": data.get("name", os.path.splitext(f)[0]),
                "description": data.get("description", ""),
                "template": data["template"],
                "objectKinds": data.get("scope", {}).get("objectKinds", []),
                "params": data.get("params", {}),
            })
    return checks


# ------------------------------
# 4. Orquestador: YAML + Go → condiciones semánticas
# ------------------------------

def extract_kubelinter_semantic_checks(checks_root: str, templates_root: str):
    """
    Pipeline completo:
      1. Indexa templates Go por Key
      2. Lee todos los checks YAML
      3. Para cada check, busca el template y extrae condiciones
      4. Devuelve una lista de checks enriquecidos con condiciones
    """
    key_to_src = index_templates_by_key(templates_root)
    yaml_checks = load_kubelinter_checks_yaml(checks_root)

    results = []
    skipped = []

    for chk in yaml_checks:
        key = chk["template"]
        src = key_to_src.get(key)
        if not src:
            skipped.append((chk["name"], key, "no-template-found"))
            continue

        conds = extract_conditions_from_template_go(src)
        if not conds:
            skipped.append((chk["name"], key, "no-conditions-detected"))
            continue

        chk_out = {
            "id": key,
            "name": chk["name"],
            "description": chk["description"],
            "objectKinds": chk["objectKinds"],
            "params": chk["params"],
            "conditions": conds,
        }
        results.append(chk_out)

    return results, skipped


# ------------------------------
# 5. (Opcional) Generar una forma UVL intermedia
# ------------------------------

def condition_to_uvl_feature(context: str, prop_path: str) -> str:
    """
    Convierte (context, prop_path) en un identificador de feature "genérico".
    La idea es que luego lo mapees con tu CSV (como haces con Polaris),
    usando context + prop_path para buscar el Midle adecuado.

    Ejemplo:
        context = "Container"
        prop_path = "securityContext.privileged"

    → "Container.securityContext_privileged"
    """
    prop_flat = prop_path.replace(".", "_")
    return f"{context}.{prop_flat}"


def build_uvl_constraint_from_conditions(check: dict) -> str:
    """
    Toma un check con conditions (= lista de Condition) y construye
    una expresión UVL genérica (sin aún meter prefijos io_k8s_...).
    """
    exprs = []
    for (ctx, prop, op, val) in check["conditions"]:
        feature = condition_to_uvl_feature(ctx, prop)

        if op == "!=" and isinstance(val, bool):
            # Interpretamos "campo != true" como "!feature"
            exprs.append(f"!{feature}")
        elif op == "==" and isinstance(val, bool):
            exprs.append(f"{feature}")
        elif op == "not matches":
            exprs.append(f"!({feature} matches '{val}')")
        elif op == "contains":
            exprs.append(f"{feature}_StringValue == '{val}'")
        else:
            # fallback
            exprs.append(f"{feature} {op} {val!r}")

    if not exprs:
        return ""

    if len(exprs) == 1:
        return exprs[0]
    return " & ".join(exprs)


def kubelinter_checks_to_uvl_blocks(checks: List[dict]) -> List[Tuple[str, str]]:
    """
    Devuelve pares (feature_block, constraint) estilo Polaris/OPA:

        feature_block: "privileged {doc '...', tool 'KubeLinter'}"
        constraint:    "privileged => !Container.securityContext_privileged"
    """
    out = []

    for chk in checks:
        feat_name = chk["id"].replace("-", "_")
        doc = chk["description"].replace("'", "\\'")
        feature_block = f"{feat_name} {{doc '{doc}', tool 'KubeLinter'}}"
        rhs = build_uvl_constraint_from_conditions(chk)
        constraint = f"{feat_name} => {rhs}" if rhs else f"{feat_name} => "
        out.append((feature_block, constraint))

    return out


# ------------------------------
# 6. Ejemplo de uso en modo script
# ------------------------------

if __name__ == "__main__":
    # Ajusta estas rutas a tu repo local
    CHECKS_DIR = "../resources/kube_linter/checks_yamls"
    TEMPLATES_DIR = "../resources/kube_linter/templates"

    checks, skipped = extract_kubelinter_semantic_checks(CHECKS_DIR, TEMPLATES_DIR)

    print("\n### CHECKS MAPEADOS AUTOMÁTICAMENTE ###\n")
    for chk in checks:
        print(f"Check: {chk['id']}  ({chk['name']})")
        for c in chk["conditions"]:
            print("  ", c)
        print()

    uvl_blocks = kubelinter_checks_to_uvl_blocks(checks)
    print("\n### BLOQUES UVL GENÉRICOS ###\n")
    for fb, cons in uvl_blocks:
        print(fb)
        print(cons)
        print("-" * 80)

    if skipped:
        print("\n### SKIPPED (sin template o sin patrón reconocible) ###\n")
        for name, key, reason in skipped:
            print(f" - {name} (template={key}) :: {reason}")