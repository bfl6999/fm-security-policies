import re

# ------------------------------------------------------------
# PARSER GATEKEEPER REGO – versión estable + soporte mínimo extra
# ------------------------------------------------------------

VIOLATION_PATTERN = re.compile(
    r"violation\s*\[[^\]]*\]\s*\{(?P<body>.*?)\}",
    re.DOTALL
)

FUNC_CALL_PATTERN = re.compile(
    r"(?P<func>\w+)\s*\((?P<arg>[^\)]+)\)"
)

FUNC_DEF_PATTERN = re.compile(
    r"(?P<func>\w+)\s*\(\s*(?P<param>\w+)\s*\)\s*\{(?P<body>.*?)\}",
    re.DOTALL
)

ATTR_PATTERN = re.compile(
    r"(?P<var>\w+)\.(?P<attr>[A-Za-z_][A-Za-z0-9_\.\\[\]]*)"
)

# patrón específico para las reglas de rangos de hostPort
HOSTPORT_PATTERN = re.compile(
    r"hostPort\s*:=\s*input_containers\[_\]\.ports\[_\]\.hostPort"
)

# últimos segmentos que NO queremos tratar como condiciones reales
INVALID_LAST = {
    "name", "image", "images",
    "securitycontext", "containers",
    "initcontainers", "ephemeralcontainers",
    "metadata", "spec", "namespace",
}


def _clean_attr_last(attr: str) -> str:
    """Limpia el último segmento de un path para compararlo con INVALID_LAST."""
    last = attr.split(".")[-1]
    # quitar índices tipo [_] o [i]
    last = last.replace("[_]", "").replace("[]", "")
    if "[" in last:
        # algo raro como 'volumes[_][x]' -> nos quedamos con 'volumes'
        last = last.split("[", 1)[0]
    return last.lower()


def extract_direct_conditions(body: str):
    """Devuelve pares (var, attr) de condiciones REALES en un bloque Rego.

    Se basa en:
      - coincidencias var.attr
      - filtrado por INVALID_LAST
      - ignorar accesos que claramente son de mensaje/metadata/iteración
    """
    conds = []
    for m in ATTR_PATTERN.finditer(body):
        var = m.group("var")
        attr = m.group("attr")

        # ignorar metadata.* y review.object.metadata.*
        if attr.startswith("review.object.metadata") or attr.startswith("metadata."):
            continue

        # ignorar expresiones puramente de iteración, tipo spec.containers[_]
        if "[" in attr and not attr.endswith("]"):
            # ej: spec.volumes[_][x] lo manejaremos aparte si hace falta
            pass
        elif "[" in attr:
            # típicamente iteradores -> no son condición de seguridad
            continue

        last = _clean_attr_last(attr)
        if last in INVALID_LAST:
            continue

        conds.append((var, attr))
    return conds


def extract_gatekeeper_conditions_from_rego(rego_text: str):
    """Extrae rutas K8s relevantes a partir de un template Rego de Gatekeeper.

    Estrategia:
      1) Localizar el bloque principal 'violation { ... }'
      2) Dentro de violation:
         - extraer condiciones directas var.attr
         - detectar llamadas a funciones auxiliares
      3) Para cada función llamada:
         - localizar su definición
         - extraer var.attr en su cuerpo
         - mapear el parámetro de la función a 'spec'
      4) Detectar patrón especial de hostPort (rangos con min/max)
      5) Añadir soporte mínimo para 'spec.volumes':
         - si aparece un acceso a input.review.object.spec.volumes
           añadimos una ruta abstracta 'spec.volumes'
      6) Expandir variables simbólicas:
         - 'c' -> spec.containers/initContainers/ephemeralContainers
         - 'spec' -> spec.*
    """
    results = []

    # 1. Bloque principal violation
    m = VIOLATION_PATTERN.search(rego_text)
    if not m:
        return []
    violation_body = m.group("body")

    # 2. Llamadas a funciones dentro de violation
    calls = FUNC_CALL_PATTERN.findall(violation_body)
    called_funcs = {f for (f, _arg) in calls}

    # 3. Definiciones de funciones auxiliares
    funcs = []
    for fm in FUNC_DEF_PATTERN.finditer(rego_text):
        funcs.append({
            "name": fm.group("func"),
            "param": fm.group("param"),
            "body": fm.group("body"),
        })

    # 4. Condiciones directas en violation
    results += extract_direct_conditions(violation_body)

    # 5. Condiciones dentro de funciones llamadas (hostPID/hostIPC, etc.)
    for f in funcs:
        if f["name"] not in called_funcs:
            continue
        conds = extract_direct_conditions(f["body"])
        expanded = []
        for var, attr in conds:
            if var == f["param"]:
                # interpretamos el parámetro como 'spec'
                expanded.append(("spec", attr))
        results += expanded

    # 6. hostPort rangos: patrón específico (host-network-ports)
    if HOSTPORT_PATTERN.search(rego_text):
        results.append(("c", "ports.hostPort"))

    # 7. soporte mínimo para volumetypes/hostfilesystem sobre spec.volumes
    #    detectamos acceso a input.review.object.spec.volumes en cualquier forma
    if "input.review.object.spec.volumes" in rego_text:
        results.append(("spec", "volumes"))

    # 8. Expandir variables simbólicas a rutas concretas
    final = []
    for var, attr in results:
        # normalizar índices simples
        attr_norm = (
            attr.replace("[*]", "")
                .replace("[_]", "")
                .replace("[]", "")
        )
        if var == "c":
            final.append(f"spec.containers[*].{attr_norm}")
            final.append(f"spec.initContainers[*].{attr_norm}")
            final.append(f"spec.ephemeralContainers[*].{attr_norm}")
        elif var == "spec":
            final.append(f"spec.{attr_norm}")

    # 9. Deduplicar manteniendo orden
    uniq = []
    seen = set()
    for r in final:
        if r not in seen:
            uniq.append(r)
            seen.add(r)

    return uniq