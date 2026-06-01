from saif.agents.api_enumeration import ApiEnumerationAgent
from saif.agents.authentication import AuthenticationAgent
from saif.agents.authorization import AuthorizationAgent
from saif.agents.base import BaseAgent
from saif.agents.input_validation import InputValidationAgent
from saif.agents.network import (
    DatabaseServiceAgent,
    HostDiscoveryAgent,
    NetworkDeviceAgent,
    NetworkReconAgent,
    RdpAgent,
    ServiceEnumAgent,
    SmbAgent,
    SnmpAgent,
    SshAgent,
    TlsAgent,
)
from saif.agents.internal import (
    AIPlannerAgent,
    ApiDiscoveryAgent,
    AuthAgent,
    AuthorizationInternalAgent,
    BusinessLogicAgent,
    InputValidationInternalAgent,
    OrchestratorAgent,
    ReconInternalAgent,
    ReportingInternalAgent,
    TokenAgent,
    ToolManagerAgent,
    WebDiscoveryAgent,
)
from saif.agents.recon import ReconAgent
from saif.agents.reporting import ReportingAgent
from saif.agents.web_enumeration import WebEnumerationAgent


AGENTS: dict[str, BaseAgent] = {
    "recon": ReconAgent(),
    "web_enumeration": WebEnumerationAgent(),
    "api_enumeration": ApiEnumerationAgent(),
    "authentication": AuthenticationAgent(),
    "authorization": AuthorizationAgent(),
    "input_validation": InputValidationAgent(),
    "reporting": ReportingAgent(),
    "orchestrator_agent": OrchestratorAgent(),
    "ai_planner_agent": AIPlannerAgent(),
    "tool_manager_agent": ToolManagerAgent(),
    "recon_agent": ReconInternalAgent(),
    "web_discovery_agent": WebDiscoveryAgent(),
    "api_discovery_agent": ApiDiscoveryAgent(),
    "auth_agent": AuthAgent(),
    "token_agent": TokenAgent(),
    "authorization_agent": AuthorizationInternalAgent(),
    "input_validation_agent": InputValidationInternalAgent(),
    "business_logic_agent": BusinessLogicAgent(),
    "reporting_agent": ReportingInternalAgent(),
    "network_recon_agent": NetworkReconAgent(),
    "host_discovery_agent": HostDiscoveryAgent(),
    "service_enum_agent": ServiceEnumAgent(),
    "tls_agent": TlsAgent(),
    "smb_agent": SmbAgent(),
    "snmp_agent": SnmpAgent(),
    "ssh_agent": SshAgent(),
    "rdp_agent": RdpAgent(),
    "database_service_agent": DatabaseServiceAgent(),
    "network_device_agent": NetworkDeviceAgent(),
}


def get_agent(name: str) -> BaseAgent:
    return AGENTS[name]
