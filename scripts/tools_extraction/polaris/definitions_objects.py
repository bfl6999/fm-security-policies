## Definition of targets kinds objects. Use the object references that were declared
## in tools like Polaris

"""var knownKinds = []knownKind{{
	"Deployment", "apps/v1",
}, {
	"ReplicaSet", "apps/v1",
}, {
	"CronJob", "batch/v1",
}, {  
	"Job", "batch/v1",
}, {
	"DaemonSet", "apps/v1",
}, {
	"StatefulSet", "apps/v1",
}}"""

# Lista oficial de Controllers soportados por Polaris (sacada de controller-utils)
CONTROLLER_KINDS = [
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "Job",
    "CronJob",
    "ReplicaSet"
]