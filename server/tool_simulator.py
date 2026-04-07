"""
Tool Simulator - Mock AWS CLI Execution.

Simulates command execution without external dependencies.
Allows agents to execute simulated AWS commands and receive realistic responses.
"""

import re
import time
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class CommandResult:
    success: bool
    output: str
    error: Optional[str] = None
    command: str = ""
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class CloudResource:
    resource_type: str
    resource_id: str
    properties: Dict[str, Any] = field(default_factory=dict)
    public: bool = False
    disabled: bool = False


class ToolSimulator:
    """
    Simulates command execution without external dependencies.

    Supports simulated AWS CLI commands for:
    - S3 bucket operations
    - IAM user management
    - EC2 instance queries
    - Security group configurations
    """

    def __init__(self):
        self.execution_log: List[Dict[str, Any]] = []
        self.cloud_state: Dict[str, Dict[str, CloudResource]] = {
            "s3_buckets": {},
            "iam_users": {},
            "ec2_instances": {},
            "security_groups": {},
        }
        self._execution_count = 0

    def execute_aws_command(
        self, command: str, args: Dict[str, Any] = None
    ) -> CommandResult:
        """
        Parse and execute simulated AWS CLI commands.

        Args:
            command: The AWS CLI command string
            args: Optional parsed arguments

        Returns:
            CommandResult with success status, output, and optional error
        """
        self._execution_count += 1
        args = args or {}

        if "s3api" in command or "s3" in command.lower():
            return self._execute_s3_command(command, args)
        elif "iam" in command.lower():
            return self._execute_iam_command(command, args)
        elif "ec2" in command.lower():
            return self._execute_ec2_command(command, args)
        elif "describe-security-groups" in command:
            return self._execute_security_group_command(command, args)
        else:
            return CommandResult(
                success=False,
                output="",
                error=f"Unknown command type: {command}",
                command=command,
            )

    def _execute_s3_command(self, command: str, args: Dict[str, Any]) -> CommandResult:
        """Execute simulated S3 commands."""
        bucket_name = args.get("bucket") or self._extract_bucket_name(command)

        if "get-public-access-block" in command:
            if bucket_name in self.cloud_state["s3_buckets"]:
                resource = self.cloud_state["s3_buckets"][bucket_name]
                if resource.public:
                    output = f'{{"PublicAccessBlockConfiguration": {{"BlockPublicAcls": false}}}}'
                else:
                    output = (
                        '{"PublicAccessBlockConfiguration": {"BlockPublicAcls": true}}'
                    )
                return CommandResult(success=True, output=output, command=command)
            return CommandResult(
                success=False,
                output="",
                error=f"NoSuchBucket: The specified bucket does not exist",
                command=command,
            )

        elif "put-public-access-block" in command:
            if bucket_name in self.cloud_state["s3_buckets"]:
                self.cloud_state["s3_buckets"][bucket_name].public = False
                self.cloud_state["s3_buckets"][bucket_name].properties[
                    "public_access_blocked"
                ] = True
                self._log_execution(
                    command, {"bucket": bucket_name, "action": "block_public_access"}
                )
                return CommandResult(
                    success=True,
                    output=f"Public access blocked for bucket: {bucket_name}",
                    command=command,
                )
            return CommandResult(
                success=False,
                output="",
                error=f"NoSuchBucket: The specified bucket does not exist",
                command=command,
            )

        elif "list-buckets" in command:
            buckets = list(self.cloud_state["s3_buckets"].keys())
            output = '{"Buckets": ' + str([{"Name": b} for b in buckets]) + "}"
            return CommandResult(success=True, output=output, command=command)

        return CommandResult(
            success=False,
            output="",
            error=f"Unknown S3 command: {command}",
            command=command,
        )

    def _execute_iam_command(self, command: str, args: Dict[str, Any]) -> CommandResult:
        """Execute simulated IAM commands."""
        user_name = (
            args.get("user-name")
            or args.get("UserName")
            or self._extract_username(command)
        )

        if "get-user" in command:
            if user_name in self.cloud_state["iam_users"]:
                resource = self.cloud_state["iam_users"][user_name]
                status = "Disabled" if resource.disabled else "Active"
                output = (
                    f'{{"User": {{"UserName": "{user_name}", "Status": "{status}"}}}}'
                )
                return CommandResult(success=True, output=output, command=command)
            return CommandResult(
                success=False,
                output="",
                error=f"NoSuchEntity: The user {user_name} does not exist",
                command=command,
            )

        elif "update-user" in command or "update-user" in command:
            status = args.get("status") or "Active"
            if user_name in self.cloud_state["iam_users"]:
                self.cloud_state["iam_users"][user_name].disabled = status == "Disabled"
                self._log_execution(command, {"user": user_name, "status": status})
                return CommandResult(
                    success=True,
                    output=f"User {user_name} updated to status: {status}",
                    command=command,
                )
            return CommandResult(
                success=False,
                output="",
                error=f"NoSuchEntity: The user {user_name} does not exist",
                command=command,
            )

        elif "list-users" in command:
            users = list(self.cloud_state["iam_users"].keys())
            output = '{"Users": ' + str([{"UserName": u} for u in users]) + "}"
            return CommandResult(success=True, output=output, command=command)

        return CommandResult(
            success=False,
            output="",
            error=f"Unknown IAM command: {command}",
            command=command,
        )

    def _execute_ec2_command(self, command: str, args: Dict[str, Any]) -> CommandResult:
        """Execute simulated EC2 commands."""
        if "describe-instances" in command:
            instances = []
            for inst_id, inst in self.cloud_state["ec2_instances"].items():
                instances.append(
                    {
                        "InstanceId": inst_id,
                        "State": {
                            "Name": "running" if not inst.disabled else "stopped"
                        },
                        **inst.properties,
                    }
                )
            output = '{"Reservations": [{"Instances": ' + str(instances) + "}]}"
            return CommandResult(success=True, output=output, command=command)

        return CommandResult(
            success=False,
            output="",
            error=f"Unknown EC2 command: {command}",
            command=command,
        )

    def _execute_security_group_command(
        self, command: str, args: Dict[str, Any]
    ) -> CommandResult:
        """Execute simulated security group commands."""
        group_id = args.get("GroupId") or "sg-default"

        if group_id in self.cloud_state["security_groups"]:
            sg = self.cloud_state["security_groups"][group_id]
            output = str({"SecurityGroups": [{"GroupId": group_id, **sg.properties}]})
            return CommandResult(success=True, output=output, command=command)

        return CommandResult(
            success=False,
            output="",
            error=f"InvalidGroup.NotFound: Security group {group_id} not found",
            command=command,
        )

    def _extract_bucket_name(self, command: str) -> Optional[str]:
        """Extract bucket name from command string."""
        match = re.search(r"--bucket\s+(\S+)", command)
        if match:
            return match.group(1)
        match = re.search(r"bucket[/\s]+(\S+)", command, re.IGNORECASE)
        if match:
            return match.group(1)
        return None

    def _extract_username(self, command: str) -> Optional[str]:
        """Extract username from command string."""
        match = re.search(r"--user-name\s+(\S+)", command)
        if match:
            return match.group(1)
        match = re.search(r"user[/\s]+(\S+)", command, re.IGNORECASE)
        if match:
            return match.group(1)
        return None

    def _log_execution(self, command: str, metadata: Dict[str, Any]):
        """Log command execution."""
        self.execution_log.append(
            {
                "command": command,
                "metadata": metadata,
                "timestamp": datetime.now().isoformat(),
                "execution_id": self._execution_count,
            }
        )

    def get_state(
        self, resource_type: str, resource_id: str
    ) -> Optional[CloudResource]:
        """Get current state of a resource."""
        if resource_type in self.cloud_state:
            return self.cloud_state[resource_type].get(resource_id)
        return None

    def update_state(
        self, resource_type: str, resource_id: str, properties: Dict[str, Any]
    ):
        """Update simulated resource state."""
        if resource_type not in self.cloud_state:
            self.cloud_state[resource_type] = {}

        if resource_id in self.cloud_state[resource_type]:
            self.cloud_state[resource_type][resource_id].properties.update(properties)
        else:
            self.cloud_state[resource_type][resource_id] = CloudResource(
                resource_type=resource_type,
                resource_id=resource_id,
                properties=properties,
            )

    def add_bucket(self, bucket_name: str, public: bool = False):
        """Add a simulated S3 bucket to state."""
        self.cloud_state["s3_buckets"][bucket_name] = CloudResource(
            resource_type="s3",
            resource_id=bucket_name,
            properties={"Name": bucket_name},
            public=public,
        )

    def add_user(self, user_name: str, disabled: bool = False):
        """Add a simulated IAM user to state."""
        self.cloud_state["iam_users"][user_name] = CloudResource(
            resource_type="iam",
            resource_id=user_name,
            properties={"UserName": user_name},
            disabled=disabled,
        )

    def add_ec2_instance(self, instance_id: str, properties: Dict[str, Any] = None):
        """Add a simulated EC2 instance to state."""
        self.cloud_state["ec2_instances"][instance_id] = CloudResource(
            resource_type="ec2",
            resource_id=instance_id,
            properties=properties or {},
        )

    def add_security_group(self, group_id: str, properties: Dict[str, Any] = None):
        """Add a simulated security group to state."""
        self.cloud_state["security_groups"][group_id] = CloudResource(
            resource_type="security_group",
            resource_id=group_id,
            properties=properties or {},
        )

    def simulate_delay(self, min_seconds: float = 0.1, max_seconds: float = 0.5):
        """Add realistic delay to command execution."""
        import random

        delay = random.uniform(min_seconds, max_seconds)
        time.sleep(delay)

    def generate_audit_log(self) -> List[Dict[str, Any]]:
        """Return log of all executed commands."""
        return self.execution_log.copy()

    def reset(self):
        """Reset simulator state."""
        self.execution_log = []
        self.cloud_state = {
            "s3_buckets": {},
            "iam_users": {},
            "ec2_instances": {},
            "security_groups": {},
        }
        self._execution_count = 0

    def get_execution_summary(self) -> Dict[str, Any]:
        """Get summary of command executions."""
        return {
            "total_executions": self._execution_count,
            "execution_log_size": len(self.execution_log),
            "resources": {
                resource_type: len(resources)
                for resource_type, resources in self.cloud_state.items()
            },
        }
