import os
import yaml
import re

from tools_extraction.extract_opa_batch import parse_opa_directory, parse_polaris_directory, parse_gatekeeper_directory_wrapper

from tools_extraction.kyverno.extract_kyverno_checks import (
    sanitize,
    extract_policy_info,
    extract_uvl_attributes_from_policy,
    extract_constraints_from_policy,
    extract_constraints_from_deny_conditions
)

existing_exprs = set()


def extract_features(expr: str):
    """Devuelve un set de todos los features usados en la expresión."""
    # Extrae cosas del tipo Pod.xxx_yyy_zzz
    matches = re.findall(r"[A-Za-z]+\.[A-Za-z0-9_\.]+", expr)
    return set(matches)


def generate_uvl_from_policies(directory, output_path):
    category_map = {}

    # Recolectar todos los archivos YAML del directorio principal y subcarpetas
    all_yaml_files = []
    for root, _, files in os.walk(directory):
        for filename in files:
            if filename.endswith((".yaml", ".yml")):
                all_yaml_files.append(os.path.join(root, filename))

    for filepath in all_yaml_files:
        filename = os.path.basename(filepath)
        if not filename.endswith(".yaml") and not filename.endswith(".yml"):
            continue
        policy = extract_policy_info(filepath)
        #print(f"This is the policy info: {policy}")

        cat = sanitize(policy["category"])
        title = sanitize(policy["title"])
        #print(f"Titulos ARCHIVOS:   {title}     \n      Category:   {cat}")
        entry = {
            "name": title,
            "description": policy["description"],
            "raw_policy": policy["full_yaml"]
        }

        category_map.setdefault(cat, []).append(entry)

    #lines = ["namespace PoliciesKyverno", "features", "\tPolicies {abstract}", "\t\toptional"]
    lines = ["namespace Policies", "imports", "    k8s.Pod as Pod\n    k8s.ServiceAccount as ServAcc\n    k8s.RoleBinding as RoleBinding\n    k8s.ClusterRoleBinding as ClusRole\n    k8s.Service as Serv\n    k8s.Ingress as Ingress\n    k8s.Job as Job\n    k8s.DaemonSet as DaemonSet\n    k8s.Deployment as Deployment\n    k8s.StatefulSet as StatefulSet\n    k8s.Secret as Secret\n    k8s.PersistentVolumeClaim as PersistVolumeClaim\n"
    "    k8s.PodDisruptionBudget as PodDisrupBud\n    k8s.CronJob as CronJob\n    k8s.ReplicaSet as ReplicaSet\n    k8s.ReplicationController as RepController\n    k8s.Container as Container\n    k8s.PodList as PodList\n    k8s.PodTemplate as PodTemplate\n    k8s.PodTemplateList as PodTemplateList\n    k8s.PodTemplateSpec as PodTemplateSpec\n    k8s.HorizontalPodAutoscaler as HorizontalPodAutoscaler",
    "features", "\tPoliciesKubernetes {abstract}", "\t\toptional"] ## RepController
    
    #opa_results = parse_opa_directory("../resources/OPA_Policies")
    #polaris_results = parse_opa_directory("../resources/Polaris-checks")

    for cat, entries in category_map.items():
        lines.append(f"\t\t\t{cat}")
        lines.append("\t\t\t\toptional")
        for e in entries:
            name = e["name"]
            policy = e.get("raw_policy")
            if policy:
                attrs = extract_uvl_attributes_from_policy(policy)
                lines.append(f"\t\t\t\t\t{name}{attrs}")
            else:
                lines.append(f"\t\t\t\t\t{name}")
            #name = e["name"]
            """doc = clean_description(e["description"])
            if doc:
                lines.append(f"\t\t\t\t\t{name} {{doc '{doc}'}}")
            else:
                lines.append(f"\t\t\t\t\t{name}")"""

    lines.append("\t\t\tOPAConstraints {abstract}")
    lines.append("\t\t\t\toptional")

    ##ll_resources = parse_all_sources("../resources/OPA_Policies", "../resources/Polaris-checks")
    opa_results = parse_opa_directory("../resources/OPA_Policies")
    for opa in opa_results: ## Read OPA Policies
        feature_str = opa["feature"] ## .replace("\n", "\n\t\t\t")
        print(f"Feature str:    {feature_str}")
        lines.append(f"\t\t\t\t\t{feature_str}")

    polaris_results = parse_polaris_directory("../resources/Polaris-checks")
    lines.append("\t\t\tPolarisConstraints {abstract}")
    lines.append("\t\t\t\toptional")

    for check in polaris_results: ## Read OPA Policies
        feature_str = check["feature"] ## .replace("\n", "\n\t\t\t")
        print(f"Feature str:    {feature_str}")
        lines.append(f"\t\t\t\t\t{feature_str}")

    gatekeeper_results = parse_gatekeeper_directory_wrapper("../resources/gatekeeper-library/pod-security-policy")
    lines.append("\t\t\tGatekeeeperConstraints {abstract}")
    lines.append("\t\t\t\toptional")
    for gk in gatekeeper_results:
        feature_str = gk["feature"]
        lines.append(f"\t\t\t\t\t{feature_str}")


    lines.append("\t\t\tPod.PodFeatures")
    lines.append("\t\t\tServAcc.ServiceAccountFeatures")
    lines.append("\t\t\tRoleBinding.RoleBindingFeatures")
    lines.append("\t\t\tClusRole.ClusterRoleBindingFeatures")
    lines.append("\t\t\tServ.ServiceFeatures")
    lines.append("\t\t\tIngress.IngressFeatures")
    lines.append("\t\t\tJob.JobFeatures")
    lines.append("\t\t\tDaemonSet.DaemonSetFeatures")
    lines.append("\t\t\tDeployment.DeploymentFeatures")
    lines.append("\t\t\tStatefulSet.StatefulSetFeatures")
    lines.append("\t\t\tSecret.SecretFeatures")
    lines.append("\t\t\tPersistVolumeClaim.PersistentVolumeClaimFeatures")
    lines.append("\t\t\tPodDisrupBud.PodDisruptionBudgetFeatures")
    lines.append("\t\t\tCronJob.CronJobFeatures") ## ReplicaSet
    lines.append("\t\t\tReplicaSet.ReplicaSetFeatures")
    lines.append("\t\t\tRepController.ReplicationControllerFeatures")
    lines.append("\t\t\tContainer.ContainerFeatures")
    lines.append("\t\t\tPodList.PodListFeatures")
    lines.append("\t\t\tPodTemplate.PodTemplateFeatures")
    lines.append("\t\t\tPodTemplateList.PodTemplateListFeatures")
    lines.append("\t\t\tPodTemplateSpec.PodTemplateSpecFeatures") #PodTemplateFeatures
    lines.append("\t\t\tHorizontalPodAutoscaler.HorizontalPodAutoscalerFeatures")

    lines.append("constraints")
    # Recolectar todos los archivos YAML del directorio principal y subcarpetas (recursivo)
    all_yaml_files = []
    for root, _, files in os.walk(directory):
        for filename in files:
            if filename.endswith((".yaml", ".yml")):
                all_yaml_files.append(os.path.join(root, filename))

    merged = {}

    # Procesar cada archivo YAML
    for filepath in all_yaml_files:
        grouped, optional_clauses = extract_constraints_from_policy(filepath)
        with open(filepath, 'r', encoding='utf-8') as fh:
            policy_obj = yaml.safe_load(fh)
        grouped_deny = extract_constraints_from_deny_conditions(policy_obj)

        optional_grouped = optional_clauses  # ya es un dict con el nombre correcto

        # Combinar grouped, deny y optional en merged
        for g in [grouped, grouped_deny, optional_grouped]:
            for policy_name, exprs in g.items():
                merged.setdefault(policy_name, []).extend(exprs)

    # Formatear y agregar constraints al archivo UVL
    for policy_name, exprs in merged.items():
        normalized_exprs = []
        for expr in exprs:
            if expr.endswith("= false"): ## Formating cases for changed a correct syntax
                normalized_exprs.append(f"!{expr.replace(' = false', '')}")
            elif '= 0' in expr: ## To change every constraint with = 0 for == 0 => Error line 27:262 token recognition error at: '= '
                normalized_exprs.append(f"{expr.replace(' = 0', ' == 0 ')}")
            elif ' < ' in expr or ' > ' in expr: ## Case of mins of maxs
                expr = re.sub(r"==\s*([<>])\s*(\d+)", r"\1 \2", expr) ## Obtain the signal of interval and the number and replaced in 1, 2
                normalized_exprs.append(expr)
            elif re.search(r"\b\d+\s*-\s*\d+\b", expr): ## Case of interval with a '-' between the numbers
                match = re.search(r"(\d+)\s*-\s*(\d+)", expr)
                if match:
                    low_str, high_str = match.groups()
                    low = int(low_str) - 1
                    high = int(high_str) + 1

                    feature = re.split(r"\s*=\s*|\s*[<>]\s*", expr)[0].strip()
                    normalized_exprs.append(f"{feature} > {low}")
                    normalized_exprs.append(f"{feature} < {high}")
                else:
                    print(f"Case not implemented")
                    pass
            else:
                normalized_exprs.append(expr)

        # Lógica especial: AppArmor (KeyMap / ValueMap)
        if len(normalized_exprs) == 1:
            constraint = normalized_exprs[0]
            
        else:
            if any("KeyMap" in expr for expr in normalized_exprs) and any("ValueMap" in expr for expr in normalized_exprs): ## Detect features (K,V)
                # Agroup KeyMap-ValueMap
                grouped = []
                current = []
                for expr in normalized_exprs:
                    current.append(expr)
                    # Each 2 elements we have a Pair (KeyMap, ValueMap)
                    if len(current) == 2:
                        grouped.append(f"({current[0]} & {current[1]})")
                        current = []
                if current: # For safety
                    grouped.append(f"({current[0]})")
                constraint = " | ".join(grouped) ## | for different pairs
            else:
                # Normal case, AND every feature adition because are a differents groups and union intervals
                constraint = f"({' & '.join(normalized_exprs)})"
        lines.append(f"\t{policy_name} => {constraint}")

    used_features = set()

    # Después de generar constraints de Kyverno:
    for line in lines:
        if "=>" in line:
            rhs = line.split("=>", 1)[1]
            feats = extract_features(rhs)
            used_features.update(feats)

    # Añadir OPA sin duplicar expresiones
    for opa in opa_results:
        #lines.append("\t" + opa["constraint"])
        raw = opa["constraint"]
        expr = raw.split("=>", 1)[1] if "=>" in raw else raw
        feats = extract_features(expr)
        lines.append("\t" + raw)
        used_features.update(feats)

    for polaris in polaris_results: ## Write Policies of Polaris
        #print(f"Polaris {polaris}")
        raw = polaris["constraint"]
        expr = raw.split("=>", 1)[1] if "=>" in raw else raw
        expr02 = raw.split("=>", 1)[0]
        feats = extract_features(expr)

        # Si CUALQUIER feature ya ha sido usado → deduplicar
        if any(f in used_features for f in feats) and not expr02.strip() == "hpaMinAvailability": ## Exception for hpaMinAvailability
            print(f"[DEDUP] Omitida constraint con features ya usados: {feats}")
            continue

        lines.append("\t" + raw)
        used_features.update(feats)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"UVL generado: {output_path}")

# Ejemplo de uso
if __name__ == "__main__":
    generate_uvl_from_policies(
        directory="../resources/dataset_final_validated", ## dataset_filtered kyverno_policies_yamls
        output_path="../variability_model/policies_template/policy_structure04.uvl"
    )