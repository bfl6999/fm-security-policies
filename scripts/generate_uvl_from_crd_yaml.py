import yaml
import os

def sanitize(name):
    return name.replace("-", "_").replace(".", "_").replace("/", "").replace(" ", "_")

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

def render_feature(entry, indent=2):
    i = "\t" * indent
    lines = []

    typename = "" if entry.get("type") in ["object", "array", ""] else entry.get("type", "").capitalize()
    name = sanitize(entry["name"])
    doc = entry.get("description", "")
    default = entry.get("default")
    enum = entry.get("enum", [])
    children = entry.get("children", [])

    attributes = []
    if default is not None:
        val = str(default).lower() if isinstance(default, bool) else f"'{default}'"
        attributes.append(f'default {val}')

    if doc:
        if entry.get("x-kubernetes-preserve-unknown-fields") is True: ## New attribute for properties with x-kubernetes-preserve-unknown-fields: true
            if entry.get("type") == 'object': ## Case of properties with partial validation and permissive unknow fields
                print(f"Name de los objects con validacion parcial: {name}")
                attributes.append(f"preserveUnknownFieldsX, doc '{clean_description(doc.strip())}'")
            else:
                attributes.append(f"preserveUnknownFields, doc '{clean_description(doc.strip())}'")
        else:
            attributes.append(f"doc '{clean_description(doc.strip())}'")

        
    attr_str = f" {{{', '.join(attributes)}}}" if attributes else ""
    
    if entry.get("cardinality"): ## print("Prueba teclado01")
        lines.append(f"{i}{name} cardinality {entry['cardinality']}{attr_str}")
    else:
        if typename and typename != 'Boolean' and not enum:
            lines.append(f"{i}{typename} {name}{attr_str}")
        else:
            lines.append(f"{i}{name}{attr_str}")
    ## Detect de alternative values defined by the field enum:
    if enum:
        lines.append(i + "\talternative")
        for val in enum:
            enum_val = sanitize(f"{name}_{val}")
            lines.append(f"{i}\t\t{enum_val} {{doc 'Specific value: {sanitize(val)}'}}")

    if children:
        mand = [c for c in children if c.get("required")]
        opt = [c for c in children if not c.get("required")]
        if mand:
            lines.append(i + "\tmandatory")
            for c in mand:
                lines.extend(render_feature(c, indent + 2))
        if opt:
            if 'oneOf' in entry: ## Detect if the property contains a oneOf
                lines.append(i + "\talternative") ## Put alternative againts opcional
            else:
                lines.append(i + "\toptional")
            for c in opt:
                lines.extend(render_feature(c, indent + 2))

    return lines

def extract_features(schema, parent_name="", required_fields=None):
    required_fields = required_fields or []
    props = schema.get("properties", {})
    features = []

    for key, value in props.items():
        feature = {
            "name": f"{parent_name}_{key}" if parent_name else key,
            "type": value.get("type", "Boolean"),
            "description": value.get("description", ""),
            "default": value.get("default"),
            "enum": value.get("enum", []),
            "required": key in required_fields,
            "children": [],
            "x-kubernetes-preserve-unknown-fields": value.get("x-kubernetes-preserve-unknown-fields"),

        }

        if value.get("type") == "object" and "properties" in value:
            feature["children"] = extract_features(value, feature["name"], value.get("required", []))
        elif value.get("type") == "object" and "additionalProperties" in value:
            ap = value["additionalProperties"]
            if "properties" in ap:
                feature["children"] = extract_features(ap, feature["name"],  ap.get("required", []))
            elif "items" in ap and isinstance(ap["items"], dict):
                feature["cardinality"] = "[1..*]"
                feature["children"] = extract_features(ap["items"], feature["name"], ap["items"].get("required", []))
        elif value.get("type") == "array" and "items" in value:
            feature["cardinality"] = "[1..*]"
            item = value["items"]
            # Detection of oneOf in the item...
            if 'oneOf' in item:
                #print(f"✔️ oneOf detectado en array: {feature['name']}")
                simple_required = []
                for branch in item["oneOf"]:
                    if "required" in branch and len(branch["required"]) == 1:
                        simple_required.append(branch["required"][0])
                if len(simple_required) >= 2:
                    feature["oneOf"] = simple_required
                
            # Subir enum si está dentro de items
            if "enum" in item:
                feature["enum"] = item["enum"]

            # Special case: array of strings, we can consider the option String _secrets cardinality [1..*] directly?: omitting the sub-tree...
            elif item.get("type") == "string":
                feature["children"] = [{
                    "name": feature["name"] + "_StringValue",
                    "type": "String",
                    "description": "Added String mandatory for complete structure Array in the model. The modified is not in json but provides representation of Array of Strings: StringValue",
                    "required": True,
                    "children": []
                }]

            if item.get("type") == "object" and "properties" in item:
                feature["children"] = extract_features(item, feature["name"], item.get("required", []))
        features.append(feature)

    return features

def generate_uvl_from_crd(yaml_path, output_path):
    with open(yaml_path, 'r', encoding='utf-8') as f:
        crd = yaml.safe_load(f)

    kind = crd.get("spec", {}).get("names", {}).get("kind", "UnknownKind")
    group = crd.get("spec", {}).get("group", "unknown.group")
    namespace_name = sanitize(group)
    feature_lines = [f"namespace {namespace_name}", "features", "\tKyvernoCustomResourceDefinition {abstract}", "\t\toptional"]

    for version_entry in crd.get("spec", {}).get("versions", []):
        version = version_entry.get("name", "v1")
        openapi = version_entry.get("schema", {}).get("openAPIV3Schema", {})
        root_name = sanitize(f"{group}_{version}_{kind}")
        doc = openapi.get("description", "")
        features = extract_features(openapi, root_name, openapi.get("required", []))

        feature_lines.append(f"\t\t\t{root_name} {{doc \'{clean_description(doc)}\'}}")

        mandatory = [f for f in features if f.get("required")]
        optional = [f for f in features if not f.get("required")]

        if mandatory:
            feature_lines.append("\t\t\t\tmandatory")
            for feature in mandatory:
                feature_lines.extend(render_feature(feature, indent=5))
        if optional:
            feature_lines.append("\t\t\t\toptional")
            for feature in optional:
                feature_lines.extend(render_feature(feature, indent=5))
        """feature_lines.append("\t\t\t\toptional")
        for feature in features:
            feature_lines.extend(render_feature(feature, indent=5))"""
        
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(feature_lines))

    print(f"UVL generado: {output_path}")

# Uso de prueba:
if __name__ == "__main__":
    #yaml_path="../resources/kyverno_crds_definitions/policies.kyverno.io_validatingpolicies.yaml",
    ## policies.kyverno.io_validatingpolicies
    generate_uvl_from_crd(
        yaml_path="../resources/kyverno_crds_definitions/kyverno.io_clusterpolicies.yaml",
        output_path="../variability_model/kyverno_clusterpolicy_test2.uvl"
    )