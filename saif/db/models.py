from datetime import datetime
from enum import StrEnum

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from saif.db.base import Base


class ScanStatus(StrEnum):
    CREATED = "created"
    PLANNING = "planning"
    READY = "ready"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPING = "stopping"
    STOPPED = "stopped"
    RESUMING = "resuming"
    COMPLETED = "completed"
    FAILED = "failed"
    FAILED_PRECHECK = "failed_precheck"
    FAILED_AI_TIMEOUT = "failed_ai_timeout"
    FAILED_AI = "failed_ai"
    FAILED_SYSTEM = "failed_system"
    EXECUTION_ERROR = "execution_error"
    AUTH_FAILED = "auth_failed"


class RunStatus(StrEnum):
    QUEUED = "queued"
    PLANNED = "planned"
    RUNNING = "running"
    COMPLETED = "completed"
    FINDING_CREATED = "finding_created"
    ALTERNATE_TOOL_USED = "alternate_tool_used"
    NOT_APPLICABLE = "not_applicable"
    MISSING_PREREQUISITE = "missing_prerequisite"
    MISSING_CREDENTIALS = "missing_credentials"
    MISSING_TOOL = "missing_tool"
    TOOL_INSTALL_FAILED = "tool_install_failed"
    TARGET_UNREACHABLE = "target_unreachable"
    OUT_OF_SCOPE = "out_of_scope"
    MANUAL_CONFIRMATION_REQUIRED = "manual_confirmation_required"
    EXECUTION_ERROR = "execution_error"
    INVALID_REQUEST_TEMPLATE = "invalid_request_template"
    SKIPPED_REQUIRES_TEST_OWNED_OBJECT = "skipped_requires_test_owned_object"
    SKIPPED_REQUIRES_MANUAL_CONFIRMATION = "skipped_requires_manual_confirmation"
    PAUSED = "paused"
    STOPPED = "stopped"
    SKIPPED_BY_USER = "skipped_by_user"


class ToolRegistryStatus(StrEnum):
    INSTALLED = "installed"
    MISSING = "missing"
    INSTALLING = "installing"
    INSTALL_FAILED = "install_failed"
    DISABLED = "disabled"
    UNKNOWN = "unknown"


class AgentJobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    targets: Mapped[list["Target"]] = relationship(back_populates="project", cascade="all, delete-orphan")
    scans: Mapped[list["Scan"]] = relationship(back_populates="project", cascade="all, delete-orphan")


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    scope: Mapped[dict | None] = mapped_column(JSON)

    project: Mapped[Project] = relationship(back_populates="targets")


class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class TestCase(Base):
    __tablename__ = "test_cases"
    __table_args__ = (UniqueConstraint("scan_id", "case_id", "profile", name="uq_test_case_scan_case_profile"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    case_id: Mapped[str] = mapped_column(String(120), nullable=False)
    test_id: Mapped[str | None] = mapped_column(String(160))
    profile: Mapped[str] = mapped_column(String(80), nullable=False)
    phase: Mapped[str] = mapped_column(String(120), nullable=False)
    agent: Mapped[str] = mapped_column(String(120), nullable=False)
    agent_name: Mapped[str | None] = mapped_column(String(120))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str | None] = mapped_column(String(120))
    target: Mapped[str | None] = mapped_column(Text)
    applicability: Mapped[str | None] = mapped_column(String(80))
    prerequisites: Mapped[list | None] = mapped_column(JSON)
    tool: Mapped[str] = mapped_column(String(120), nullable=False)
    selected_tool: Mapped[str | None] = mapped_column(String(120))
    alternate_tools: Mapped[list | None] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(40), default=RunStatus.PLANNED.value, nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=50, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    definition: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    profile: Mapped[str] = mapped_column(String(80), nullable=False)
    ai_provider: Mapped[str | None] = mapped_column(String(80))
    authorized_testing_mode: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    engagement_mode: Mapped[str | None] = mapped_column(String(40))
    credentials_path: Mapped[str | None] = mapped_column(Text)
    source_path: Mapped[str | None] = mapped_column(Text)
    scan_config: Mapped[dict | None] = mapped_column(JSON)
    auth_mode: Mapped[str | None] = mapped_column(String(80))
    destructive_method_policy: Mapped[str | None] = mapped_column(String(80))
    enable_destructive_tests: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    destructive_test_policy: Mapped[str] = mapped_column(String(80), default="detect_only", nullable=False)
    allow_test_owned_object_creation: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    confirm_destructive_testing: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    allow_account_generation: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    allow_authenticated_testing: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    allow_authorization_testing: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    allow_payload_testing: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    allow_rate_limit_testing: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    pause_requested: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    stop_requested: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    status: Mapped[str] = mapped_column(String(40), default=ScanStatus.CREATED.value, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_activity_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    current_phase: Mapped[str | None] = mapped_column(String(120))
    current_agent: Mapped[str | None] = mapped_column(String(120))
    current_tool: Mapped[str | None] = mapped_column(String(120))
    progress_message: Mapped[str | None] = mapped_column(Text)
    progress_percent: Mapped[int | None] = mapped_column(Integer)

    project: Mapped[Project] = relationship(back_populates="scans")
    test_runs: Mapped[list["TestRun"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class ScanEvent(Base):
    __tablename__ = "scan_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    level: Mapped[str] = mapped_column(String(40), nullable=False)
    phase: Mapped[str | None] = mapped_column(String(120))
    agent_name: Mapped[str | None] = mapped_column(String(120))
    tool_name: Mapped[str | None] = mapped_column(String(120))
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    context_json: Mapped[dict | None] = mapped_column(JSON)


class ScanProcess(Base):
    __tablename__ = "scan_processes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    pid: Mapped[int | None] = mapped_column(Integer)
    command: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(80), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    exit_code: Mapped[int | None] = mapped_column(Integer)
    log_path: Mapped[str | None] = mapped_column(Text)


class ScanTestPlan(Base):
    __tablename__ = "scan_test_plan"
    __table_args__ = (UniqueConstraint("scan_id", "category", name="uq_scan_test_plan_category"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    category: Mapped[str] = mapped_column(String(160), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    status: Mapped[str] = mapped_column(String(80), default=RunStatus.PLANNED.value, nullable=False)
    reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ScanPhase(Base):
    __tablename__ = "scan_phases"
    __table_args__ = (UniqueConstraint("scan_id", "phase_name", name="uq_scan_phase_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    phase_name: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[str] = mapped_column(String(40), default=RunStatus.PLANNED.value, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    agent_name: Mapped[str | None] = mapped_column(String(120))
    error_message: Mapped[str | None] = mapped_column(Text)
    summary_json: Mapped[dict | None] = mapped_column(JSON)


class TestRun(Base):
    __tablename__ = "test_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    test_case_id: Mapped[int | None] = mapped_column(ForeignKey("test_cases.id", ondelete="SET NULL"))
    agent_name: Mapped[str | None] = mapped_column(String(120))
    tool_name: Mapped[str | None] = mapped_column(String(120))
    command: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(40), default=RunStatus.PLANNED.value, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    output_summary: Mapped[str | None] = mapped_column(Text)
    evidence_id: Mapped[int | None] = mapped_column(ForeignKey("evidence.id", ondelete="SET NULL"))
    error_message: Mapped[str | None] = mapped_column(Text)
    retry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    output: Mapped[dict | None] = mapped_column(JSON)

    scan: Mapped[Scan] = relationship(back_populates="test_runs")
    test_case: Mapped[TestCase | None] = relationship()


class ToolRun(Base):
    __tablename__ = "tool_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    test_run_id: Mapped[int | None] = mapped_column(ForeignKey("test_runs.id", ondelete="SET NULL"))
    test_case_id: Mapped[int | None] = mapped_column(ForeignKey("test_cases.id", ondelete="SET NULL"))
    agent_name: Mapped[str | None] = mapped_column(String(120))
    tool_name: Mapped[str] = mapped_column(String(120), nullable=False)
    command: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(40), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    evidence_path: Mapped[str | None] = mapped_column(Text)
    output: Mapped[dict | None] = mapped_column(JSON)


class AiCallRun(Base):
    __tablename__ = "ai_call_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    stage: Mapped[str] = mapped_column(String(80), nullable=False)
    agent_name: Mapped[str | None] = mapped_column(String(120))
    model: Mapped[str] = mapped_column(String(160), nullable=False)
    prompt_tokens_estimate: Mapped[int | None] = mapped_column(Integer)
    status: Mapped[str | None] = mapped_column(String(80))
    response_status: Mapped[str] = mapped_column(String(80), nullable=False)
    http_status: Mapped[int | None] = mapped_column(Integer)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    retry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    prompt_summary: Mapped[str | None] = mapped_column(Text)
    prompt_hash: Mapped[str | None] = mapped_column(String(128))
    error_message: Mapped[str | None] = mapped_column(Text)
    request_summary: Mapped[dict | None] = mapped_column(JSON)
    response_summary: Mapped[str | None] = mapped_column(Text)
    parsed_response_json: Mapped[dict | None] = mapped_column(JSON)
    evidence_path: Mapped[str | None] = mapped_column(Text)


class AiDecision(Base):
    __tablename__ = "ai_decisions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    ai_call_id: Mapped[str] = mapped_column(String(160), nullable=False)
    stage: Mapped[str] = mapped_column(String(80), nullable=False)
    phase: Mapped[str | None] = mapped_column(String(120))
    agent: Mapped[str | None] = mapped_column(String(120))
    tool: Mapped[str | None] = mapped_column(String(120))
    model: Mapped[str | None] = mapped_column(String(160))
    prompt_hash: Mapped[str | None] = mapped_column(String(128))
    response_hash: Mapped[str | None] = mapped_column(String(128))
    evidence_path: Mapped[str | None] = mapped_column(Text)
    parsed_response_json: Mapped[dict | None] = mapped_column(JSON)
    decision: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[str | None] = mapped_column(String(40))
    accepted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    rejected_reasons: Mapped[list | None] = mapped_column(JSON)
    used_for_execution: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    used_as_advisory: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class ToolRegistry(Base):
    __tablename__ = "tool_registry"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tool_name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    install_method: Mapped[str | None] = mapped_column(String(120))
    command_path: Mapped[str | None] = mapped_column(Text)
    version: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(40), default=ToolRegistryStatus.UNKNOWN.value, nullable=False)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_install_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    install_attempt_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_error: Mapped[str | None] = mapped_column(Text)
    metadata_json: Mapped[dict | None] = mapped_column("metadata", JSON)


class AgentJob(Base):
    __tablename__ = "agent_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    agent_name: Mapped[str] = mapped_column(String(120), nullable=False)
    job_type: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[str] = mapped_column(String(40), default=AgentJobStatus.QUEUED.value, nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=50, nullable=False)
    input: Mapped[dict | None] = mapped_column(JSON)
    output: Mapped[dict | None] = mapped_column(JSON)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Request(Base):
    __tablename__ = "requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    tool_run_id: Mapped[int | None] = mapped_column(ForeignKey("tool_runs.id", ondelete="SET NULL"))
    method: Mapped[str] = mapped_column(String(20), nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    headers: Mapped[dict | None] = mapped_column(JSON)
    body: Mapped[str | None] = mapped_column(Text)


class Response(Base):
    __tablename__ = "responses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    request_id: Mapped[int] = mapped_column(ForeignKey("requests.id", ondelete="CASCADE"), nullable=False)
    status_code: Mapped[int | None] = mapped_column(Integer)
    headers: Mapped[dict | None] = mapped_column(JSON)
    body_preview: Mapped[str | None] = mapped_column(Text)
    elapsed_ms: Mapped[int | None] = mapped_column(Integer)


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    test_run_id: Mapped[int | None] = mapped_column(ForeignKey("test_runs.id", ondelete="SET NULL"))
    kind: Mapped[str] = mapped_column(String(80), nullable=False)
    path: Mapped[str] = mapped_column(Text, nullable=False)
    summary: Mapped[str | None] = mapped_column(Text)
    metadata_json: Mapped[dict | None] = mapped_column("metadata", JSON)


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    test_run_id: Mapped[int | None] = mapped_column(ForeignKey("test_runs.id", ondelete="SET NULL"))
    finding_uid: Mapped[str | None] = mapped_column(String(80), unique=True)
    finding_type: Mapped[str] = mapped_column(String(40), default="finding", nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(40), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    evidence_id: Mapped[int | None] = mapped_column(ForeignKey("evidence.id", ondelete="SET NULL"))
    status: Mapped[str] = mapped_column(String(40), default="open", nullable=False)
    affected_endpoint: Mapped[str | None] = mapped_column(Text)
    http_method: Mapped[str | None] = mapped_column(String(20))
    parameter: Mapped[str | None] = mapped_column(String(255))
    payload: Mapped[str | None] = mapped_column(Text)
    payload_source: Mapped[str | None] = mapped_column(Text)
    payload_type: Mapped[str | None] = mapped_column(String(120))
    vulnerability_type: Mapped[str | None] = mapped_column(String(120))
    agent_name: Mapped[str | None] = mapped_column(String(120))
    test_case_id: Mapped[str | None] = mapped_column(String(160))
    cwe: Mapped[str | None] = mapped_column(String(80))
    owasp_category: Mapped[str | None] = mapped_column(String(160))
    confidence: Mapped[str | None] = mapped_column(String(40))
    business_impact: Mapped[str | None] = mapped_column(Text)
    technical_impact: Mapped[str | None] = mapped_column(Text)
    reproduction_steps: Mapped[str | None] = mapped_column(Text)
    remediation: Mapped[str | None] = mapped_column(Text)
    secure_code_guidance: Mapped[str | None] = mapped_column(Text)
    references_json: Mapped[list | None] = mapped_column(JSON)
    baseline_evidence_path: Mapped[str | None] = mapped_column(Text)
    attack_evidence_path: Mapped[str | None] = mapped_column(Text)
    ai_reasoning_summary: Mapped[str | None] = mapped_column(Text)
    retest_status: Mapped[str | None] = mapped_column(String(80))
    closure_evidence_path: Mapped[str | None] = mapped_column(Text)
    fixed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class PayloadAttempt(Base):
    __tablename__ = "payload_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"))
    test_case_id: Mapped[str | None] = mapped_column(String(160))
    agent_name: Mapped[str | None] = mapped_column(String(120))
    vulnerability_type: Mapped[str] = mapped_column(String(120), nullable=False)
    endpoint: Mapped[str] = mapped_column(Text, nullable=False)
    method: Mapped[str | None] = mapped_column(String(20))
    parameter_location: Mapped[str | None] = mapped_column(String(80))
    parameter_name: Mapped[str | None] = mapped_column(String(255))
    payload: Mapped[str | None] = mapped_column(Text)
    payload_masked: Mapped[str | None] = mapped_column(Text)
    payload_source: Mapped[str | None] = mapped_column(Text)
    baseline_status: Mapped[int | None] = mapped_column(Integer)
    baseline_body_hash: Mapped[str | None] = mapped_column(String(80))
    attack_status: Mapped[int | None] = mapped_column(Integer)
    attack_body_hash: Mapped[str | None] = mapped_column(String(80))
    body_length_delta: Mapped[int | None] = mapped_column(Integer)
    reflection_detected: Mapped[bool | None] = mapped_column(Boolean)
    error_marker_detected: Mapped[bool | None] = mapped_column(Boolean)
    protected_data_detected: Mapped[bool | None] = mapped_column(Boolean)
    ai_decision_json: Mapped[dict | None] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(80), nullable=False)
    evidence_path: Mapped[str | None] = mapped_column(Text)


class Credential(Base):
    __tablename__ = "credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    label: Mapped[str] = mapped_column(String(120), nullable=False)
    username: Mapped[str | None] = mapped_column(String(255))
    secret_ref: Mapped[str | None] = mapped_column(Text)
    role: Mapped[str | None] = mapped_column(String(120))
    metadata_json: Mapped[dict | None] = mapped_column("metadata", JSON)


class SessionRecord(Base):
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    credential_id: Mapped[int | None] = mapped_column(ForeignKey("credentials.id", ondelete="SET NULL"))
    label: Mapped[str] = mapped_column(String(120), nullable=False)
    cookies: Mapped[dict | None] = mapped_column(JSON)
    headers: Mapped[dict | None] = mapped_column(JSON)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AuthenticatedSession(Base):
    __tablename__ = "authenticated_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    credential_label: Mapped[str] = mapped_column(String(120), nullable=False)
    username: Mapped[str | None] = mapped_column(String(255))
    role: Mapped[str | None] = mapped_column(String(120))
    tenant: Mapped[str | None] = mapped_column(String(120))
    auth_type: Mapped[str] = mapped_column(String(80), nullable=False)
    access_token: Mapped[str | None] = mapped_column(Text)
    access_token_secret: Mapped[str | None] = mapped_column(Text)
    access_token_hash: Mapped[str | None] = mapped_column(String(128))
    access_token_masked: Mapped[str | None] = mapped_column(Text)
    secret_ref: Mapped[str | None] = mapped_column(Text)
    refresh_token: Mapped[str | None] = mapped_column(Text)
    cookie: Mapped[str | None] = mapped_column(Text)
    authorization_header: Mapped[str | None] = mapped_column(Text)
    authorization_header_type: Mapped[str | None] = mapped_column(String(80))
    token_type: Mapped[str | None] = mapped_column(String(80))
    login_status: Mapped[str] = mapped_column(String(80), nullable=False)
    session_status: Mapped[str | None] = mapped_column(String(80))
    metadata_json: Mapped[dict | None] = mapped_column("metadata", JSON)


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"))
    format: Mapped[str] = mapped_column(String(40), nullable=False)
    path: Mapped[str] = mapped_column(Text, nullable=False)
    summary: Mapped[dict | None] = mapped_column(JSON)


class Log(Base):
    __tablename__ = "logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    level: Mapped[str] = mapped_column(String(40), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    context: Mapped[dict | None] = mapped_column(JSON)


class DiscoveredAsset(Base):
    __tablename__ = "discovered_assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    asset_type: Mapped[str] = mapped_column(String(80), nullable=False)
    source: Mapped[str | None] = mapped_column(String(120))
    metadata_json: Mapped[dict | None] = mapped_column("metadata", JSON)


class ApplicationProfile(Base):
    __tablename__ = "application_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    primary_profile: Mapped[str] = mapped_column(String(120), nullable=False)
    secondary_profiles: Mapped[list | None] = mapped_column(JSON)
    lab_profile: Mapped[str | None] = mapped_column(String(120))
    confidence: Mapped[str | None] = mapped_column(String(40))
    detection_rules: Mapped[dict | None] = mapped_column(JSON)
    observed: Mapped[dict | None] = mapped_column(JSON)


class DiscoveredService(Base):
    __tablename__ = "discovered_services"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    service_name: Mapped[str | None] = mapped_column(String(160))
    host: Mapped[str | None] = mapped_column(String(255))
    port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(String(40))
    product: Mapped[str | None] = mapped_column(String(255))
    version: Mapped[str | None] = mapped_column(String(120))
    source: Mapped[str | None] = mapped_column(String(120))
    metadata_json: Mapped[dict | None] = mapped_column("metadata", JSON)


class DiscoveredApiSpec(Base):
    __tablename__ = "discovered_api_specs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    spec_type: Mapped[str] = mapped_column(String(80), nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str | None] = mapped_column(String(80))
    title: Mapped[str | None] = mapped_column(String(255))
    version: Mapped[str | None] = mapped_column(String(120))
    metadata_json: Mapped[dict | None] = mapped_column("metadata", JSON)


class DiscoveredAuthMechanism(Base):
    __tablename__ = "discovered_auth_mechanisms"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    mechanism_type: Mapped[str] = mapped_column(String(120), nullable=False)
    endpoint: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[str | None] = mapped_column(String(40))
    evidence: Mapped[dict | None] = mapped_column(JSON)


class DiscoveredSessionMechanism(Base):
    __tablename__ = "discovered_session_mechanisms"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    mechanism_type: Mapped[str] = mapped_column(String(120), nullable=False)
    location: Mapped[str | None] = mapped_column(String(120))
    token_type: Mapped[str | None] = mapped_column(String(80))
    confidence: Mapped[str | None] = mapped_column(String(40))
    metadata_json: Mapped[dict | None] = mapped_column("metadata", JSON)


class DiscoveredEndpoint(Base):
    __tablename__ = "discovered_endpoints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    method: Mapped[str | None] = mapped_column(String(80))
    endpoint_type: Mapped[str] = mapped_column(String(80), default="web", nullable=False)
    source: Mapped[str | None] = mapped_column(String(120))
    metadata_json: Mapped[dict | None] = mapped_column("metadata", JSON)


class DiscoveredParameter(Base):
    __tablename__ = "discovered_parameters"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    location: Mapped[str] = mapped_column(String(80), nullable=False)
    endpoint: Mapped[str | None] = mapped_column(Text)
    source: Mapped[str | None] = mapped_column(String(120))
    metadata_json: Mapped[dict | None] = mapped_column("metadata", JSON)


class DiscoveredAuthFlow(Base):
    __tablename__ = "discovered_auth_flows"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    flow_type: Mapped[str] = mapped_column(String(120), nullable=False)
    url: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[dict | None] = mapped_column(JSON)


class DiscoveredToken(Base):
    __tablename__ = "discovered_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    token_type: Mapped[str] = mapped_column(String(80), nullable=False)
    location: Mapped[str] = mapped_column(String(120), nullable=False)
    sample: Mapped[str | None] = mapped_column(Text)
    metadata_json: Mapped[dict | None] = mapped_column("metadata", JSON)


class DiscoveredRole(Base):
    __tablename__ = "discovered_roles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    role_name: Mapped[str] = mapped_column(String(120), nullable=False)
    source: Mapped[str | None] = mapped_column(String(120))
    metadata_json: Mapped[dict | None] = mapped_column("metadata", JSON)


class DiscoveredTenant(Base):
    __tablename__ = "discovered_tenants"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    tenant_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    source: Mapped[str | None] = mapped_column(String(120))
    metadata_json: Mapped[dict | None] = mapped_column("metadata", JSON)


class DiscoveredObject(Base):
    __tablename__ = "discovered_objects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    object_type: Mapped[str] = mapped_column(String(120), nullable=False)
    object_ref: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str | None] = mapped_column(String(120))
    metadata_json: Mapped[dict | None] = mapped_column("metadata", JSON)


class AuthorizationMatrix(Base):
    __tablename__ = "authorization_matrix"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    subject: Mapped[str] = mapped_column(String(120), nullable=False)
    role: Mapped[str | None] = mapped_column(String(120))
    endpoint: Mapped[str | None] = mapped_column(Text)
    object_ref: Mapped[str | None] = mapped_column(Text)
    expected_access: Mapped[str | None] = mapped_column(String(80))
    observed_access: Mapped[str | None] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(String(80), nullable=False)
    metadata_json: Mapped[dict | None] = mapped_column("metadata", JSON)


class PipelineArtifact(Base):
    __tablename__ = "pipeline_artifacts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    artifact_type: Mapped[str] = mapped_column(String(120), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    data: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
