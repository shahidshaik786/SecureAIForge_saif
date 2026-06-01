from saif.agents.base import BaseAgent


class NetworkReconAgent(BaseAgent):
    name = "network_recon_agent"


class HostDiscoveryAgent(BaseAgent):
    name = "host_discovery_agent"


class ServiceEnumAgent(BaseAgent):
    name = "service_enum_agent"


class TlsAgent(BaseAgent):
    name = "tls_agent"


class SmbAgent(BaseAgent):
    name = "smb_agent"


class SnmpAgent(BaseAgent):
    name = "snmp_agent"


class SshAgent(BaseAgent):
    name = "ssh_agent"


class RdpAgent(BaseAgent):
    name = "rdp_agent"


class DatabaseServiceAgent(BaseAgent):
    name = "database_service_agent"


class NetworkDeviceAgent(BaseAgent):
    name = "network_device_agent"
