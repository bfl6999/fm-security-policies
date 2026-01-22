import re
import csv

uvl_model_path = '../variability_model/kyverno_clusterpolicy_test2.uvl'

# Contenedores para la salida
csv_data = []
kinds_versions_set = set()
no_kinds_versions = []
elementos_sin_version_o_kind = []

# Leer el archivo UVL
with open(uvl_model_path, encoding="utf-8") as uvl_model:
    for line in uvl_model:
        original_line = line  # Guardamos para detección de indentación
        line = line.strip()
        value_row = "-" if "cardinality" in line else ""

        if not line.startswith(("String", "Boolean", "Integer")) and not re.match(r"[a-z0-9]+_io_", line):
            if line.startswith("constraints"):
                break
            continue

        if "cardinality" in line:
            line_feature = line.split("cardinality")[0]
        else:
            line_feature = line.split("{")[0]

        parts = line_feature.split()
        feature = parts[1] if len(parts) >= 2 else parts[0]

        feature_aux_midle = re.search(r"[A-Z].*", feature)
        if not feature_aux_midle:
            elementos_sin_version_o_kind.append(feature)
            continue

        midle_row = feature_aux_midle.group(0)
        kind = midle_row.split('_')[0]
        version_aux = feature.split(kind)[0]
        version_parts = version_aux.strip('_').split('_')

        if len(version_parts) >= 2:
            api_version = version_parts[-1]
            kinds_versions_set.add((api_version, kind))
        else:
            no_kinds_versions.append((version_aux, kind))
            elementos_sin_version_o_kind.append(feature)

        split_feature = feature.split("_")
        turned_row = split_feature[-1] if split_feature else ""

        # Valor solo si es línea alternativa con indentación
        if "Specific value" in line:
            value_row = turned_row
        if 'preserveUnknownFields' in line and not 'preserveUnknownFieldsX' in line: ## Differences between 2 types of attribute preserveUnknownFields
            value_row = 'preserveUnknownFields'
        elif 'preserveUnknownFieldsX' in line:
            value_row = 'preserveUnknownFieldsX'
        csv_data.append([feature, midle_row, turned_row, value_row])

# Escribir archivos
output_file_csv = '../resources/mapping_csv/kyverno_mapping_properties_features.csv'
output_file_kinds_versions = '../resources/mapping_csv/kinds_versions_detected.csv'

with open(output_file_csv, mode="w", newline="") as csv_file:
    writer = csv.writer(csv_file)
    writer.writerow(["Feature", "Midle", "Turned", "Value"])
    writer.writerows(csv_data)

with open(output_file_kinds_versions, mode="w", newline="") as apis_file:
    writer = csv.writer(apis_file)
    writer.writerow(["Version", "Kind"])
    for version, kind in sorted(kinds_versions_set):
        writer.writerow([version, kind])

print(f"✅ Archivo CSV generado: {output_file_csv}")
print(f"✅ Archivo CSV kinds_versions generado: {output_file_kinds_versions}")
print(f"🧩 Features sin version o kind: {elementos_sin_version_o_kind}")