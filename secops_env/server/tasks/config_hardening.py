"""
Config Hardening Task - Hard Security Task.

Review YAML/JSON configs for security misconfigurations.
"""

import random
from typing import Any, Dict, List, Optional, Tuple
from secops_env.models import SecOpsAction, TaskDifficulty, ActionType


class ConfigHardeningTask:
    """
    Config Hardening Task - Hard Difficulty.

    Objective: Review YAML/JSON configurations for security misconfigurations.

    Success Criteria:
    - All security issues correctly identified
    - Appropriate severity assessment
    - Proper remediation suggestions
    - Correctly hardened configuration output

    Reward Structure:
    - +0.4 for correct issue identification
    - +0.3 for appropriate remediation
    - +0.3 for correct configuration fixes
    """

    SCENARIOS = [
        {
            "config_type": "yaml",
            "content": """apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  containers:
  - name: app
    image: nginx:latest
    securityContext:
      privileged: true
      runAsUser: 0
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all
spec:
  podSelector: {}
  ingress:
  - {}""",
            "issues": [
                {"line": 10, "severity": "CRITICAL", "type": "privileged_container"},
                {"line": 11, "severity": "HIGH", "type": "run_as_root"},
                {"line": 19, "severity": "HIGH", "type": "allow_all_policy"},
            ],
            "fixes": [
                "Set privileged: false",
                "Set runAsUser: 1000 (non-root)",
                "Restrict NetworkPolicy to specific pods",
            ],
        },
        {
            "config_type": "yaml",
            "content": """apiVersion: v1
kind: Pod
metadata:
  name: database-pod
spec:
  containers:
  - name: db
    image: postgres:14
    ports:
    - containerPort: 5432
    env:
    - name: POSTGRES_PASSWORD
      value: "admin123"
    - name: DB_NAME
      value: "production"
---
apiVersion: v1
kind: Service
metadata:
  name: db-service
spec:
  type: LoadBalancer
  ports:
  - port: 5432
    targetPort: 5432""",
            "issues": [
                {"line": 10, "severity": "CRITICAL", "type": "plaintext_secret"},
                {"line": 16, "severity": "CRITICAL", "type": "public_exposure"},
            ],
            "fixes": [
                "Use Kubernetes Secret for password",
                "Change Service type to ClusterIP",
                "Enable network policies",
            ],
        },
        {
            "config_type": "json",
            "content": """{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}""",
            "issues": [
                {"line": 5, "severity": "CRITICAL", "type": "overpermissive_iam"},
            ],
            "fixes": [
                "Restrict actions to specific services",
                "Limit resources to specific ARNs",
                "Add conditions for additional security",
            ],
        },
        {
            "config_type": "yaml",
            "content": """apiVersion: apps/v1
kind: Deployment
metadata:
  name: webapp
spec:
  replicas: 3
  selector:
    matchLabels:
      app: webapp
  template:
    metadata:
      labels:
        app: webapp
    spec:
      containers:
      - name: web
        image: webapp:v1
        ports:
        - containerPort: 8080
        securityContext:
          capabilities:
            add:
            - NET_ADMIN
            - SYS_ADMIN""",
            "issues": [
                {"line": 19, "severity": "HIGH", "type": "excessive_capabilities"},
            ],
            "fixes": [
                "Remove excessive capabilities",
                "Use least privilege principle",
                "Drop all capabilities by default",
            ],
        },
        {
            "config_type": "yaml",
            "content": """apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  database_url: "postgresql://db:5432/prod"
  api_endpoint: "http://internal.api:8080"
  log_level: "debug"
---
apiVersion: v1
kind: Pod
metadata:
  name: app-pod
spec:
  containers:
  - name: app
    image: app:v1
    envFrom:
    - configMapRef:
        name: app-config""",
            "issues": [
                {"line": 3, "severity": "MEDIUM", "type": "sensitive_data_configmap"},
            ],
            "fixes": [
                "Move sensitive data to Secrets",
                "Use external config management",
                "Implement secret rotation",
            ],
        },
        {
            "config_type": "yaml",
            "content": """apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-sa
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: app-admin
subjects:
- kind: ServiceAccount
  name: app-sa
  namespace: default
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io""",
            "issues": [
                {"line": 9, "severity": "CRITICAL", "type": "overpermissive_rbac"},
            ],
            "fixes": [
                "Use specific role instead of cluster-admin",
                "Create namespace-scoped RoleBinding",
                "Follow principle of least privilege",
            ],
        },
        {
            "config_type": "json",
            "content": """{
  "S3Bucket": {
    "PublicAccessBlockConfiguration": {
      "BlockPublicAcls": false,
      "IgnorePublicAcls": false,
      "BlockPublicPolicy": false,
      "RestrictPublicBuckets": false
    }
  }
}""",
            "issues": [
                {"line": 3, "severity": "CRITICAL", "type": "public_s3"},
                {"line": 4, "severity": "CRITICAL", "type": "public_s3"},
                {"line": 5, "severity": "CRITICAL", "type": "public_s3"},
                {"line": 6, "severity": "HIGH", "type": "public_s3"},
            ],
            "fixes": [
                "Set BlockPublicAcls: true",
                "Set IgnorePublicAcls: true",
                "Set BlockPublicPolicy: true",
                "Set RestrictPublicBuckets: true",
            ],
        },
        {
            "config_type": "yaml",
            "content": """apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: frontend-network-policy
spec:
  podSelector:
    matchLabels:
      tier: frontend
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector: {}
  egress:
  - to:
    - podSelector: {}""",
            "issues": [
                {"line": 12, "severity": "HIGH", "type": "allow_all_ingress"},
                {"line": 15, "severity": "HIGH", "type": "allow_all_egress"},
            ],
            "fixes": [
                "Restrict ingress to specific namespaces",
                "Limit egress to required services",
                "Add CIDR blocks for external access",
            ],
        },
        {
            "config_type": "yaml",
            "content": """apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  restartPolicy: Always
  containers:
  - name: test
    image: alpine:latest
    command: ["sh", "-c", "while true; do sleep 3600; done"]
    resources:
      limits:
        cpu: "100m"
        memory: "128Mi"
    securityContext:
      readOnlyRootFilesystem: false
      allowPrivilegeEscalation: true""",
            "issues": [
                {"line": 14, "severity": "MEDIUM", "type": "writable_filesystem"},
                {"line": 15, "severity": "HIGH", "type": "privilege_escalation"},
            ],
            "fixes": [
                "Set readOnlyRootFilesystem: true",
                "Set allowPrivilegeEscalation: false",
                "Add emptyDir volumes for writable paths",
            ],
        },
        {
            "config_type": "json",
            "content": """{
  "apiVersion": "v1",
  "kind": "ReplicationController",
  "metadata": {
    "name": "nginx"
  },
  "spec": {
    "replicas": 3,
    "template": {
      "spec": {
        "containers": [{
          "name": "nginx",
          "image": "nginx:1.14.2",
          "ports": [{"containerPort": 80}],
          "livenessProbe": {
            "httpGet": {"path": "/index.html", "port": 80}
          }
        }]
      }
    }
  }
}""",
            "issues": [
                {"line": 6, "severity": "LOW", "severity": "deprecated_api"},
            ],
            "fixes": [
                "Use Deployment instead of ReplicationController",
                "Update to newer API version",
                "Add resource limits",
            ],
        },
        {
            "config_type": "yaml",
            "content": """apiVersion: v1
kind: Pod
metadata:
  name: monitoring-agent
spec:
  containers:
  - name: agent
    image: prom/node-exporter:latest
    securityContext:
      runAsUser: 0
    ports:
    - containerPort: 9100
      hostPort: 9100
    volumeMounts:
    - name: rootfs
      mountPath: /host
      readOnly: true
  volumes:
  - name: rootfs
    hostPath:
      path: /""",
            "issues": [
                {"line": 7, "severity": "HIGH", "type": "run_as_root"},
                {"line": 9, "severity": "HIGH", "type": "host_port"},
                {"line": 14, "severity": "MEDIUM", "type": "host_path"},
            ],
            "fixes": [
                "Run as non-root user",
                "Remove hostPort binding",
                "Use DaemonSet with proper security context",
            ],
        },
        {
            "config_type": "yaml",
            "content": """apiVersion: v1
kind: Service
metadata:
  name: api-service
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-backend-protocol: http
spec:
  selector:
    app: api
  ports:
  - port: 80
    targetPort: 8080
  type: LoadBalancer""",
            "issues": [
                {"line": 3, "severity": "MEDIUM", "type": "missing_ssl"},
                {"line": 7, "severity": "MEDIUM", "type": "insecure_port"},
            ],
            "fixes": [
                "Enable TLS on load balancer",
                "Use HTTPS backend protocol",
                "Add SSL certificate",
            ],
        },
        {
            "config_type": "yaml",
            "content": """apiVersion: batch/v1
kind: CronJob
metadata:
  name: data-backup
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backup
            image: backup-tool:v1
            env:
            - name: AWS_ACCESS_KEY_ID
              value: "AKIAIOSFODNN7EXAMPLE"
            - name: AWS_SECRET_ACCESS_KEY
              value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
          restartPolicy: OnFailure""",
            "issues": [
                {"line": 13, "severity": "CRITICAL", "type": "plaintext_secret"},
                {"line": 15, "severity": "CRITICAL", "type": "plaintext_secret"},
            ],
            "fixes": [
                "Use IAM Role for pod instead of access keys",
                "Store secrets in Kubernetes Secret",
                "Use IRSA (IAM Roles for Service Accounts)",
            ],
        },
        {
            "config_type": "yaml",
            "content": """apiVersion: v1
kind: Pod
metadata:
  name: development-app
spec:
  containers:
  - name: app
    image: myapp:latest
    env:
    - name: NODE_ENV
      value: "development"
    - name: DEBUG
      value: "true"
    - name: LOG_LEVEL
      value: "debug"
---
apiVersion: v1
kind: LimitRange
metadata:
  name: dev-limits
spec:
  limits:
  - max:
      cpu: "10"
      memory: 20Gi
    min:
      cpu: "50m"
      memory: 5Mi""",
            "issues": [
                {"line": 7, "severity": "MEDIUM", "type": "debug_enabled"},
                {"line": 16, "severity": "MEDIUM", "type": "excessive_limits"},
            ],
            "fixes": [
                "Set NODE_ENV to production",
                "Disable debug mode in production",
                "Set appropriate resource limits",
            ],
        },
        {
            "config_type": "json",
            "content": """{
  "apiVersion": "security.istio.io/v1beta1",
  "kind": "PeerAuthentication",
  "metadata": {
    "name": "default"
  },
  "spec": {
    "mtls": {
      "mode": "PERMISSIVE"
    }
  }
}""",
            "issues": [
                {"line": 8, "severity": "HIGH", "type": "mtls_disabled"},
            ],
            "fixes": [
                "Set mTLS mode to STRICT",
                "Enforce mutual TLS for all traffic",
                "Implement service mesh security",
            ],
        },
    ]

    def __init__(self, difficulty: Optional[str] = None):
        """Initialize the config hardening task."""
        self.max_steps = 8
        self.difficulty = (
            TaskDifficulty.HARD if difficulty is None else TaskDifficulty(difficulty)
        )
        self.objective = "Review the provided configuration file for security misconfigurations. Identify all security issues, assess their severity, suggest fixes, and provide a hardened configuration."

        self._config_content = ""
        self._config_type = ""
        self._expected_issues: List[Dict[str, Any]] = []
        self._expected_fixes: List[str] = []
        self._identified_issues: List[Dict[str, Any]] = []
        self._suggested_fixes: List[str] = []
        self._hardened_config = ""
        self._total_issues = 0

    def generate_scenario(self) -> Dict[str, Any]:
        """Generate a config hardening scenario."""
        scenario = random.choice(self.SCENARIOS)

        self._config_content = scenario["content"]
        self._config_type = scenario.get("config_type", "yaml")
        self._expected_issues = scenario.get("issues", [])
        self._expected_fixes = scenario.get("fixes", [])
        self._identified_issues = []
        self._suggested_fixes = []
        self._hardened_config = ""
        self._total_issues = len(self._expected_issues)

        return {
            "config_content": self._config_content,
            "config_type": self._config_type,
            "instructions": "Review the configuration for security issues. Identify issues with severity (LOW, MEDIUM, HIGH, CRITICAL), suggest fixes, and provide a hardened version.",
        }

    def execute_action(
        self, action: SecOpsAction, grader, task_data: Dict[str, Any]
    ) -> Tuple[float, str, bool, bool]:
        """
        Execute a config hardening action.

        Returns:
            Tuple of (reward, feedback, done, success)
        """
        reward = 0.0
        feedback = ""
        done = False
        success = False

        if action.action_type == ActionType.REVIEW:
            feedback = "Reviewing configuration for security issues..."

        elif action.action_type == ActionType.IDENTIFY_ISSUES:
            self._identified_issues = action.config_issues or []
            score = grader.grade_issue_identification(
                self._identified_issues, self._expected_issues
            )
            reward = score * 0.4
            feedback = f"Identified {len(self._identified_issues)} issues. Accuracy: {score:.2f}"

        elif action.action_type == ActionType.SUGGEST_FIXES:
            self._suggested_fixes = []
            if action.config_issues:
                for issue in action.config_issues:
                    if "fix" in issue:
                        self._suggested_fixes.append(issue["fix"])
            if action.reasoning:
                self._suggested_fixes.append(action.reasoning)

            score = grader.grade_remediation_suggestions(
                self._suggested_fixes, self._expected_fixes
            )
            reward = score * 0.3
            feedback = f"Provided {len(self._suggested_fixes)} remediation suggestions. Coverage: {score:.2f}"

        elif action.action_type == ActionType.APPLY_FIXES:
            self._hardened_config = action.hardened_config or ""

            score = grader.grade_hardened_config(
                self._hardened_config, self._expected_issues, self._config_content
            )
            reward = score * 0.3
            feedback = f"Hardened configuration submitted. Fix coverage: {score:.2f}"

        elif action.action_type == ActionType.FINALIZE:
            if action.config_issues:
                self._identified_issues = action.config_issues

            if action.hardened_config:
                self._hardened_config = action.hardened_config

            score = grader.grade_full_review(
                identified_issues=self._identified_issues,
                suggestions=self._suggested_fixes,
                hardened_config=self._hardened_config,
                expected_issues=self._expected_issues,
                expected_fixes=self._expected_fixes,
                config_content=self._config_content,
            )
            reward = score

            if score >= 0.9:
                feedback = (
                    f"Excellent! All issues identified and fixed. Score: {score:.2f}"
                )
                success = True
                done = True
            elif score >= 0.5:
                feedback = (
                    f"Good review. Some issues may need attention. Score: {score:.2f}"
                )
            else:
                feedback = (
                    f"Incomplete review. Additional issues found. Score: {score:.2f}"
                )

        else:
            feedback = f"Unknown action type: {action.action_type}"

        return reward, feedback, done, success

    def get_info(self) -> Dict[str, Any]:
        """Get current task information."""
        return {
            "difficulty": self.difficulty,
            "objective": self.objective,
            "detected_issues": [i.get("type") for i in self._identified_issues],
            "fixed_issues": [],
            "total_issues": self._total_issues,
        }

    def get_state(self) -> Dict[str, Any]:
        """Get current task state."""
        return {
            "config_type": self._config_type,
            "expected_issues": len(self._expected_issues),
            "identified_issues": len(self._identified_issues),
            "suggested_fixes": len(self._suggested_fixes),
            "has_hardened_config": bool(self._hardened_config),
        }
