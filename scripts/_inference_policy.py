import re

def extract_policy_kinds_from_constraints(uvl_path: str) -> dict:
    """
    Analiza SOLO el bloque 'constraints' del UVL final.
    Devuelve:
        { policy_name: {Kind1, Kind2, ...} }
    """
    policy_kinds = {}
    inside_constraints = False

    with open(uvl_path, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()

            # Detectar inicio del bloque de constraints
            if stripped.startswith("constraints"):
                inside_constraints = True
                continue

            if not inside_constraints:
                continue

            # Omitir líneas vacías
            if not stripped:
                continue

            # Caso: POLITICA => (expresión)
            if "=>" not in stripped:
                continue

            policy, expr = stripped.split("=>", 1)
            policy = policy.strip()
            expr = expr.strip()

            # Extraer todos los nombres de features que aparecen en la expresión
            feature_names = re.findall(r"[A-Za-z0-9_.]+", expr)

            for ft in feature_names:
                # Ignorar prefijo del import: Pod.io_k8s_api_core_v1_Pod_spec...
                if "." in ft:
                    ft = ft.split(".", 1)[1]

                # Debe ser feature real del modelo
                if not ft.startswith("io_k8s_"):
                    continue

                # Detectar Kind usando primera mayúscula
                aux = re.search(r"[A-Z].*", ft)
                if not aux:
                    continue
                kind = aux.group(0).split("_")[0]

                # Registrar el kind para la política
                policy_kinds.setdefault(policy, set()).add(kind)

    return policy_kinds


def detect_kind_from_config(config_elements: dict) -> str | None:
    for k, v in config_elements.items():
        if k.endswith("_kind") and isinstance(v, str):
            return v
    return None

def infer_policies_from_kind(config_elements: dict, policy_kinds_map: dict) -> dict:
    kind = detect_kind_from_config(config_elements)

    if not kind:
        return {}

    selected = {}
    for policy, kinds in policy_kinds_map.items():
        if kind in kinds:
            selected[policy] = True

    return selected

if __name__ == "__main__":
    uvl = "../variability_model/policies_template/policy_structure03.uvl"

    print("Extrayendo políticas desde constraints...")
    policy_kinds = extract_policy_kinds_from_constraints(uvl)

    print(f"Total políticas detectadas: {len(policy_kinds)}")

    # Config ejemplo
    config_test = {
        "io_k8s_api_core_v1_Pod_kind": "Pod",
        "io_k8s_api_core_v1_Pod_apiVersion": "v1"
    }

    detected = infer_policies_from_kind(config_test, policy_kinds)
    count_policies = len(detected)
    print(f"\nPolíticas aplicables para Kind=Pod:  {count_policies}")
    for p in detected:
        print(" -", p)
    
    if not detected:
        print("Ninguna política coincide.")