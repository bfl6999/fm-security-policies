import os
import yaml
import re

def sanitize(name):
    return name.replace("-", "_").replace(".", "_").replace("/", "_").replace(" ", "_").replace("{{", "").replace("}}", "").replace("(", "").replace(")", "")

def clean_description(description: str) -> str:
    return description.replace('\n', ' ') \
                      .replace('`', '') \
                      .replace('´', '') \
                      .replace("'", "_") \
                      .replace('{', '') \
                      .replace('}', '') \
                      .replace('"', '') \
                      .replace("\\", "_") \
                      .replace(".", "") \
                      .replace("//", "_")

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
    }

def extract_constraints_from_policy(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        policy = yaml.safe_load(f)

    metadata = policy.get("metadata", {})
    annotations = metadata.get("annotations", {})
    title = annotations.get("policies.kyverno.io/title", metadata.get("name", ""))
    name = sanitize(title)

    grouped_conditions = {}  # policy_name → list of conditions

    rules = policy.get("spec", {}).get("rules", [])
    for rule in rules:
        kinds = rule.get("match", {}).get("any", [{}])[0].get("resources", {}).get("kinds", [])
        kind_prefixes = [f"io_k8s_api_core_v1_{sanitize(kind)}_" for kind in kinds]
        pattern = rule.get("validate", {}).get("pattern", {})

        if "spec" in pattern:
            conditions = extract_conditions_from_spec(pattern["spec"], prefix="spec")
            for path, expected in conditions:
                for kind_prefix in kind_prefixes:
                    full_feature = sanitize(kind_prefix + path)
                    if expected == "null":
                        expr = f"!{full_feature}"
                    elif expected in ("true", "false"):
                        expr = f"{full_feature} = {expected}"
                    else:
                        # Si es un número (int o float), usar un único '='
                        if re.match(r"^\d+(\.\d+)?$", str(expected).strip()):
                            expr = f"{full_feature} = {expected}"
                        else:
                            expr = f"{full_feature} == {expected}"
                    grouped_conditions.setdefault(name, []).append(expr)

    return grouped_conditions

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

        kinds = rule.get("match", {}).get("any", [{}])[0].get("resources", {}).get("kinds", [])
        kind_prefixes = [f"io_k8s_api_core_v1_{sanitize(kind)}_" for kind in kinds]

        # ⬇️ Mueve aquí la acumulación por feature
        exprs_by_feature = {}

        for cond in conditions:
            if not isinstance(cond, dict):
                continue

            key = cond.get("key", "")
            operator = cond.get("operator", "")
            values = cond.get("value", [])

            if isinstance(values, str):
                values = [values]

            if "spec." in key:
                raw_path = key.split("request.object.")[-1]
                raw_path = raw_path.replace("{{", "").replace("}}", "").strip()
                expanded_paths = expand_path_brackets(raw_path)

                for kind_prefix in kind_prefixes:
                    for path in expanded_paths:
                        sanitized_path = sanitize(path)
                        feature_base = kind_prefix + sanitized_path
                        if feature_base.endswith("_"):
                            feature_base = feature_base[:-1]

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

def extract_conditions_from_spec(obj, prefix="spec"):
    conditions = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            ##print(f"Key value   {k}   {v}")
            key = k.strip("=() ").replace("X(", "").replace(")", "")
            new_prefix = f"{prefix}_{key}"
            if isinstance(v, dict):
                conditions.extend(extract_conditions_from_spec(v, new_prefix))
            elif isinstance(v, list) and len(v) > 0 and isinstance(v[0], dict):
                conditions.extend(extract_conditions_from_spec(v[0], new_prefix))
            else:
                if isinstance(v, str):
                    if v.lower() == "false":
                        v = "false"
                    elif v.lower() == "true":
                        v = "true"
                    elif v.strip().lower() == "null":
                        v = "null"
                    elif v.isdigit():
                        v = v  # número como string, no cambiar
                    else:
                        v = f"'{v}'"
                elif isinstance(v, (int, float)):
                    # print(f"SE DETECTA AQUI:Caso Int")
                    v = str(v)
                else:
                    # fallback
                    v = f"'{str(v)}'"
                conditions.append((new_prefix, v))
    return conditions

def generate_uvl_from_policies(directory, output_path):
    category_map = {}

    for filename in os.listdir(directory):
        if not filename.endswith(".yaml") and not filename.endswith(".yml"):
            continue

        filepath = os.path.join(directory, filename)
        policy = extract_policy_info(filepath)

        cat = sanitize(policy["category"])
        title = sanitize(policy["title"])
        entry = {
            "name": title,
            "description": policy["description"]
        }

        category_map.setdefault(cat, []).append(entry)

    lines = ["namespace PoliciesKyverno", "features", "\tPolicies {abstract}", "\t\toptional"]

    for cat, entries in category_map.items():
        lines.append(f"\t\t\t{cat}")
        lines.append("\t\t\t\toptional")
        for e in entries:
            name = e["name"]
            doc = clean_description(e["description"])
            if doc:
                lines.append(f"\t\t\t\t\t{name} {{doc '{doc}'}}")
            else:
                lines.append(f"\t\t\t\t\t{name}")

    lines.append("constraints")
    for filename in os.listdir(directory):
        if not filename.endswith(".yaml") and not filename.endswith(".yml"):
            continue

        filepath = os.path.join(directory, filename)
        grouped = extract_constraints_from_policy(filepath)
        grouped_deny = extract_constraints_from_deny_conditions(yaml.safe_load(open(filepath)))

        merged = {}
        for g in [grouped, grouped_deny]:
            for policy_name, exprs in g.items():
                merged.setdefault(policy_name, []).extend(exprs)

        for policy_name, exprs in merged.items():
            # Reemplazar '= false' por negación
            normalized_exprs = []
            for expr in exprs:
                if expr.endswith("= false"):
                    normalized_exprs.append(f"!{expr.replace(' = false', '')}")
                else:
                    normalized_exprs.append(expr)

            # Concatenar en una sola línea, agrupando con & si es necesario
            if len(normalized_exprs) == 1:
                constraint = normalized_exprs[0]
            else:
                constraint = f"({' & '.join(normalized_exprs)})"

            lines.append(f"\t{policy_name} => {constraint}")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"✅ UVL generado: {output_path}")

# Ejemplo de uso
if __name__ == "__main__":
    generate_uvl_from_policies(
        directory="../resources/kyverno_policies_yamls",
        output_path="../variability_model/policies_template/policy_structure.uvl"
    )