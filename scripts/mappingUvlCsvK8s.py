"""
This script parses a UVL (Universal Variability Language) model file and generates
a CSV mapping of feature paths. The output helps in analyzing feature naming structure
and extracting information like API version, kind, and specific value types.

It outputs:
- A CSV listing features with hierarchical metadata (middle, turned, value)
- A CSV of unique (apiVersion, kind) combinations found in the model

Usage:
    Run the script after a UVL model has been generated to extract and organize feature information.
"""

import re
import csv

uvl_model_path = '../variability_model/policies_template/k8s/Kubernetes.uvl'

# Process the model to extract the data in the columns.
csv_data = []
### Rows: Feature, Midle, Turned, Value
## Example: From this feature: io_k8s_apimachinery_pkg_apis_meta_v1_APIVersions_serverAddressByClientCIDRs, we add in the rows:
## io_k8s_apimachinery_pkg_apis_meta_v1_APIVersions_serverAddressByClientCIDRs, APIVersions_serverAddressByClientCIDRs, serverAddressByClientCIDRs,
## io_k8s_api_core_v1_Pod_spec_containers_env_valueFrom_resourceFieldRef_divisor, Pod_spec_containers_env_valueFrom_resourceFieldRef_divisor, divisor,

### Dict to store each apiVersion and kind of those examined from the model.
kinds_versions_set = set()
no_kinds_versions = []

elementos_sin_version_o_kind = []

# Read the UVL file line by line
with open(uvl_model_path, encoding="utf-8") as uvl_model:
    for line in uvl_model:
        # Clear line
        line = line.strip()
        value_row = "-" if "cardinality" in line else "" ## The script is assigned to determine if a feature is an array.
        if not line.startswith(("String", "Boolean", "Integer", "io_k8s_")): # Skip lines that are not features, are defined by these 4 types: String, Integer or headed by io.. Boolean
            if line.startswith("constraints"): ## the reading of the constraints is omitted.
                break   ## Break is used because the only possible place to start with 'constraints' is when declaring constraints.
            continue

        if "cardinality" in line:
            line_feature = line.split("cardinality")[0]
        else:
            line_feature = line.split("{")[0]
        # Determine if the line contains an explicit type
        parts = line_feature.split()
        if len(parts) >= 2: # If there is an explicit data type (String or Integer), extract the name of the feature
            feature = parts[1]
        else:
            # If there is no explicit data type, it is assumed that the first part of the parts is feature
            feature = parts[0]
        ## Additional proof of version and kind
        feature_aux_midle = re.search(r"[A-Z].*", feature)
        #print(f"Feature aux:    {feature_aux_midle}")
        if not feature_aux_midle:
            elementos_sin_version_o_kind.add(feature)

        # Extract prefix: everything before the Kind
        prefix = feature[:feature_aux_midle.start()].rstrip("_")
        #print(f"Prefix:    {prefix}")

        kind = feature_aux_midle.group(0).split('_')[0] ## You get only the Kind
        version_aux = feature.split(kind)[0]
        api_version = version_aux.split('_')[-2]
        group = feature.split("_")[3] ## You get the group without the io.k8s extension...

        if not version_aux or not api_version:
            no_kinds_versions.add((version_aux, kind))
        if (api_version, kind) not in kinds_versions_set:
            kinds_versions_set.add((api_version, kind, prefix))
        if feature_aux_midle:
            kind = feature_aux_midle.group(0).split('_')[0]
            version_aux = feature.split(kind)[0]
            version_parts = version_aux.split('_')

            if len(version_parts) >= 2:
                api_version = version_parts[-2]
                group = version_parts[3] if len(version_parts) > 3 else "core"

                kinds_versions_set.add((api_version, kind, prefix))
            else:
                print(f"⚠ No se pudo extraer apiVersion de: {feature}")
                elementos_sin_version_o_kind.append(feature)
        else:
            print(f"⚠ No se pudo extraer kind de: {feature}")
            elementos_sin_version_o_kind.append(feature)

        # Obtain the parts of the feature
        split_feature = feature.split("_")
        midle_row = feature_aux_midle.group(0)
        turned_row = split_feature[-1] if split_feature else ""    
        # Value: leave empty or assign the value if it is an aggregate feature containing the assigned value.
        value_row = turned_row if "Specific value" in line else value_row ## The value is defined and the Value is assigned if the keywords are found in the documentation.
        # Add to CSV
        csv_data.append([feature, midle_row, turned_row, value_row])

output_file_csv = '../resources/mapping_csv/kubernetes_mapping_properties_features.csv'
output_file_kinds_versions = '../resources/mapping_csv/kubernetes_kinds_versions_detected.csv'

with open(output_file_csv, mode="w", newline="") as csv_file:
    writer = csv.writer(csv_file)
    writer.writerow(["Feature", "Midle", "Turned", "Value"])  ## [str_ouput_rows] # Header writer.writerow(["Feature, Midle, Turned, Value"])
    writer.writerows(csv_data)

with open(output_file_kinds_versions, mode="w", newline="") as apis_file:
    writer = csv.writer(apis_file)
    writer.writerow(["Version", "Kind", "Prefix"])
    for version, kind, prefix in sorted(kinds_versions_set):
        writer.writerow([version, kind, prefix])

print(f"Archivo CSV generado: {output_file_csv}")
print(f"Archivo CSV kinds_versions generado: {output_file_kinds_versions}")
print(f"Kinds version sin nada: {elementos_sin_version_o_kind}")