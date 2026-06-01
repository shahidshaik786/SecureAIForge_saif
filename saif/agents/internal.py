from saif.agents.base import BaseAgent


class OrchestratorAgent(BaseAgent):
    name = "orchestrator_agent"


class AIPlannerAgent(BaseAgent):
    name = "ai_planner_agent"


class ToolManagerAgent(BaseAgent):
    name = "tool_manager_agent"


class ReconInternalAgent(BaseAgent):
    name = "recon_agent"


class WebDiscoveryAgent(BaseAgent):
    name = "web_discovery_agent"


class ApiDiscoveryAgent(BaseAgent):
    name = "api_discovery_agent"


class AuthAgent(BaseAgent):
    name = "auth_agent"


class TokenAgent(BaseAgent):
    name = "token_agent"


class AuthorizationInternalAgent(BaseAgent):
    name = "authorization_agent"


class InputValidationInternalAgent(BaseAgent):
    name = "input_validation_agent"


class BusinessLogicAgent(BaseAgent):
    name = "business_logic_agent"


class ReportingInternalAgent(BaseAgent):
    name = "reporting_agent"
