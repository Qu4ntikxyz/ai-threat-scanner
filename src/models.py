"""
Data models and types for AI Threat Scanner
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple
from enum import Enum

@dataclass
class ThreatResult:
    """Represents a detected threat"""
    threat_type: str
    pattern: str
    severity: int
    description: str
    position: int = -1
    context: str = "unknown"

# Context types (backward compatibility)
CONTEXT_USER_INPUT = "user_input"
CONTEXT_LLM_RESPONSE = "llm_response"
CONTEXT_UNKNOWN = "unknown"

# New context types for smart matching
CONTEXT_EDUCATIONAL = "educational"
CONTEXT_RESEARCH = "research"
CONTEXT_DOCUMENTATION = "documentation"
CONTEXT_CODE_BLOCK = "code_block"
CONTEXT_CONVERSATION = "conversation"

# Risk levels
RISK_SAFE = "SAFE"
RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"
RISK_CRITICAL = "CRITICAL"

# Risk level thresholds
RISK_THRESHOLDS = {
    RISK_SAFE: 0,
    RISK_LOW: 1,
    RISK_MEDIUM: 20,
    RISK_HIGH: 50,
    RISK_CRITICAL: 80
}

# Smart pattern matching data structures

@dataclass
class PatternMatch:
    """Enhanced pattern match with context information"""
    pattern: str
    pattern_type: str
    position: int
    confidence: float
    context_window: str = ""
    semantic_coherence: float = 0.5
    found: bool = True
    base_severity: int = 0
    adjusted_severity: int = 0
    is_quoted: bool = False
    is_negated: bool = False

@dataclass
class ContextMetadata:
    """Metadata about text context for smart matching"""
    primary_context: str = CONTEXT_UNKNOWN
    secondary_contexts: List[str] = field(default_factory=list)
    confidence_scores: Dict[str, float] = field(default_factory=dict)
    intent_signals: List[str] = field(default_factory=list)
    is_meta_discussion: bool = False
    semantic_markers: Dict[str, int] = field(default_factory=dict)
    has_quotes: bool = False
    has_negation: bool = False

class IntentType(Enum):
    """Types of intent behind patterns"""
    EDUCATIONAL = "educational"
    RESEARCH = "research"
    TESTING = "testing"
    META_DISCUSSION = "meta_discussion"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"

@dataclass
class IntentAnalysis:
    """Analysis of intent behind patterns"""
    intent_type: IntentType = IntentType.UNKNOWN
    confidence: float = 0.5
    threat_reduction: float = 0.0
    supporting_evidence: List[str] = field(default_factory=list)

class WhitelistCategory(Enum):
    """Categories of legitimate use cases"""
    SECURITY_EDUCATION = "security_education"
    ACADEMIC_RESEARCH = "academic_research"
    DOCUMENTATION = "documentation"
    TESTING_DEMO = "testing_demo"
    META_DISCUSSION = "meta_discussion"
    CODE_EXAMPLE = "code_example"

@dataclass
class LegitimacyAnalysis:
    """Analysis of legitimate use cases"""
    is_legitimate: bool = False
    legitimacy_score: float = 0.0
    category: Optional[WhitelistCategory] = None
    evidence: List[str] = field(default_factory=list)

@dataclass
class ThreatScore:
    """Comprehensive threat scoring"""
    raw_score: float = 0.0
    normalized_score: float = 0.0
    components: Dict[str, float] = field(default_factory=dict)
    confidence: float = 0.5
    risk_level: str = RISK_SAFE

# Scoring factors for weighted algorithm
class ScoringFactors:
    """Factors that influence threat scoring"""
    PATTERN_SEVERITY = "pattern_severity"
    CONTEXT_TYPE = "context_type"
    PATTERN_FREQUENCY = "pattern_frequency"
    PATTERN_POSITION = "pattern_position"
    PATTERN_CLUSTERING = "pattern_clustering"
    INTENT_STRENGTH = "intent_strength"
    LEGITIMACY_SCORE = "legitimacy_score"
    CONFIDENCE_LEVEL = "confidence_level"
    SURROUNDING_CONTEXT = "surrounding_context"
    SEMANTIC_COHERENCE = "semantic_coherence"

# Default weights for scoring algorithm
DEFAULT_WEIGHTS = {
    ScoringFactors.PATTERN_SEVERITY: 0.30,
    ScoringFactors.CONTEXT_TYPE: 0.20,
    ScoringFactors.PATTERN_FREQUENCY: 0.10,
    ScoringFactors.PATTERN_POSITION: 0.05,
    ScoringFactors.PATTERN_CLUSTERING: 0.10,
    ScoringFactors.INTENT_STRENGTH: 0.15,
    ScoringFactors.LEGITIMACY_SCORE: -0.40,  # Increase reduction impact for legitimacy
    ScoringFactors.CONFIDENCE_LEVEL: 0.10,
    ScoringFactors.SURROUNDING_CONTEXT: 0.10,
    ScoringFactors.SEMANTIC_COHERENCE: 0.05
}
# Conversation tracking data structures

@dataclass
class ConversationTurn:
    """Represents a single turn in a conversation"""
    turn_number: int
    timestamp: Any  # datetime object
    prompt: str
    response: Optional[str] = None
    threat_result: Optional[Any] = None  # ThreatResult or scan result dict
    context_before: str = ""
    risk_score: float = 0.0
    detected_patterns: List[str] = field(default_factory=list)
    # Additional fields for replay analysis
    role: str = 'user'  # 'user', 'assistant', or 'system'
    content: str = ''  # Alias for prompt/response content
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        # If content is set but prompt is not, use content as prompt
        if self.content and not self.prompt:
            self.prompt = self.content
        # If prompt is set but content is not, use prompt as content
        elif self.prompt and not self.content:
            self.content = self.prompt

@dataclass
class SessionMetadata:
    """Metadata about a conversation session"""
    session_id: str
    created_at: Any  # datetime object
    last_activity: Any  # datetime object
    total_turns: int
    is_active: bool
    timeout_minutes: int
    
@dataclass
class AttackChain:
    """Represents a detected multi-step attack pattern"""
    chain_type: str
    start_turn: int
    end_turn: int
    confidence: float
    description: str
    indicators: List[str] = field(default_factory=list)
    severity: str = "MEDIUM"
    
@dataclass
class ConversationAnalysis:
    """Complete analysis of a conversation session"""
    session_metadata: SessionMetadata
    turns: List[ConversationTurn]
    detected_chains: List[AttackChain]
    cumulative_risk_score: float
    highest_risk_turn: int
    pivot_points: List[int]  # Turn numbers where intent shifts
    escalation_detected: bool
    average_turn_interval: float  # Seconds between turns
    rapid_fire_detected: bool
    attack_indicators: Dict[str, int]  # Pattern counts
    final_risk_level: str
    erosion_analysis: Optional[Dict[str, Any]] = None  # Erosion analysis data
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert analysis to dictionary for reporting"""
        return {
            "session_id": self.session_metadata.session_id,
            "total_turns": self.session_metadata.total_turns,
            "is_active": self.session_metadata.is_active,
            "cumulative_risk_score": round(self.cumulative_risk_score, 2),
            "final_risk_level": self.final_risk_level,
            "highest_risk_turn": self.highest_risk_turn,
            "escalation_detected": self.escalation_detected,
            "rapid_fire_detected": self.rapid_fire_detected,
            "detected_chains": [
                {
                    "type": chain.chain_type,
                    "confidence": round(chain.confidence, 2),
                    "turns": f"{chain.start_turn}-{chain.end_turn}",
                    "description": chain.description
                }
                for chain in self.detected_chains
            ],
            "pivot_points": self.pivot_points,
            "attack_indicators": self.attack_indicators,
            "average_turn_interval": round(self.average_turn_interval, 2),
            "erosion_analysis": self.erosion_analysis
        }

# Constraint Erosion data structures

@dataclass
class ConstraintViolation:
    """Represents a single constraint violation in conversation"""
    turn_number: int
    timestamp: Any  # datetime object
    pattern_type: str
    severity: str  # "minor", "moderate", "severe"
    description: str
    boundary_affected: str
    confidence: float = 0.5
    
@dataclass
class ErosionPattern:
    """Detected erosion pattern in conversation"""
    pattern_type: str
    description: str
    occurrence_count: int
    first_occurrence: int  # Turn number
    last_occurrence: int   # Turn number
    severity_trend: str  # "stable", "escalating", "decreasing"
    confidence: float = 0.5
    
@dataclass
class SafetyBoundary:
    """Represents a safety boundary being tracked"""
    name: str
    initial_threshold: float
    current_threshold: float
    violation_count: int
    description: str
    erosion_history: List[Dict[str, Any]] = field(default_factory=list)
    
@dataclass
class ErosionAnalysis:
    """Complete erosion analysis for a conversation"""
    erosion_score: float  # 0-100 scale
    erosion_velocity: float  # Rate of change
    boundary_integrity: float  # Percentage of boundaries maintained
    manipulation_index: float  # Measure of manipulation tactics
    persistence_factor: float  # How consistently boundaries are pushed
    detected_patterns: List[ErosionPattern]
    violations: List[ConstraintViolation]
    boundaries: List[SafetyBoundary]
    timeline: List[Tuple[int, float]]  # (turn_number, erosion_score)
    critical_points: List[int]  # Turn numbers where erosion accelerated
    risk_level: str  # SAFE, LOW, MEDIUM, HIGH, CRITICAL
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert analysis to dictionary for reporting"""
        return {
            "erosion_score": round(self.erosion_score, 2),
            "erosion_velocity": round(self.erosion_velocity, 2),
            "boundary_integrity": round(self.boundary_integrity, 2),
            "manipulation_index": round(self.manipulation_index, 2),
            "persistence_factor": round(self.persistence_factor, 2),
            "risk_level": self.risk_level,
            "detected_patterns": [
                {
                    "type": p.pattern_type,
                    "occurrences": p.occurrence_count,
                    "turns": f"{p.first_occurrence}-{p.last_occurrence}",
                    "trend": p.severity_trend,
                    "confidence": round(p.confidence, 2)
                }
                for p in self.detected_patterns
            ],
            "violations_summary": {
                "total": len(self.violations),
                "minor": sum(1 for v in self.violations if v.severity == "minor"),
                "moderate": sum(1 for v in self.violations if v.severity == "moderate"),
                "severe": sum(1 for v in self.violations if v.severity == "severe")
            },
            "boundaries_status": [
                {
                    "name": b.name,
                    "integrity": round(b.current_threshold * 100, 1),
                    "violations": b.violation_count
                }
                for b in self.boundaries
            ],
            "critical_points": self.critical_points
        }
# Replay Analysis data structures

@dataclass
class ConversationHistory:
    """Complete conversation history for replay analysis"""
    conversation_id: Optional[str] = None
    turns: List['ConversationTurn'] = field(default_factory=list)
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    platform: Optional[str] = None  # e.g., "openai", "anthropic", "custom"
    metadata: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
            
    def add_turn(self, turn: 'ConversationTurn') -> None:
        """Add a turn to the conversation history"""
        self.turns.append(turn)
        
    def get_user_turns(self) -> List['ConversationTurn']:
        """Get all user turns from the conversation"""
        return [t for t in self.turns if hasattr(t, 'role') and t.role == 'user']
        
    def get_assistant_turns(self) -> List['ConversationTurn']:
        """Get all assistant turns from the conversation"""
        return [t for t in self.turns if hasattr(t, 'role') and t.role == 'assistant']

@dataclass
class ReplayAnalysis:
    """Results from retrospective conversation analysis"""
    conversation_id: str
    total_turns: int
    start_time: Optional[str]
    end_time: Optional[str]
    duration_seconds: Optional[float]
    detected_attacks: List[Dict[str, Any]]
    attack_timeline: 'AttackTimeline'
    threat_actors: List['ThreatActor']
    success_rate: float  # Percentage of successful attacks
    anomaly_score: float  # 0-100 scale
    evolution_patterns: List[Dict[str, Any]]
    correlations: Dict[str, Any]
    risk_assessment: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def get_critical_attacks(self) -> List[Dict[str, Any]]:
        """Get only critical severity attacks"""
        return [a for a in self.detected_attacks if a.get('severity') == 'critical']
        
    def get_attack_summary(self) -> Dict[str, int]:
        """Get summary of attack types detected"""
        summary = {}
        for attack in self.detected_attacks:
            attack_type = attack.get('type', 'unknown')
            summary[attack_type] = summary.get(attack_type, 0) + 1
        return summary

@dataclass
class AttackTimeline:
    """Chronological timeline of attack events"""
    events: List[Dict[str, Any]] = field(default_factory=list)
    
    def add_event(self, turn: int, event_type: str, description: str, 
                  severity: str = "low", timestamp: Optional[str] = None) -> None:
        """Add an event to the timeline"""
        self.events.append({
            'turn': turn,
            'timestamp': timestamp,
            'event_type': event_type,
            'description': description,
            'severity': severity,
            'success': False
        })
        
    def get_events_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        """Get events filtered by severity level"""
        return [e for e in self.events if e.get('severity') == severity]
        
    def get_timeline_summary(self) -> str:
        """Generate a text summary of the timeline"""
        if not self.events:
            return "No events detected"
            
        summary_lines = []
        for event in sorted(self.events, key=lambda x: x['turn']):
            line = f"Turn {event['turn']}: [{event['severity'].upper()}] {event['event_type']} - {event['description']}"
            summary_lines.append(line)
        return "\n".join(summary_lines)

@dataclass
class ThreatActor:
    """Profile of an attacker based on behavior analysis"""
    actor_id: str
    sophistication_level: str  # "low", "medium", "high"
    preferred_techniques: List[str]
    success_rate: float
    persistence_score: float  # 0-100 scale
    behavioral_patterns: Dict[str, Any]
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    total_attacks: int = 0
    successful_attacks: int = 0
    
    def update_success_rate(self) -> None:
        """Update success rate based on attack outcomes"""
        if self.total_attacks > 0:
            self.success_rate = (self.successful_attacks / self.total_attacks) * 100
        else:
            self.success_rate = 0.0
            
    def add_technique(self, technique: str) -> None:
        """Add a newly observed technique"""
        if technique not in self.preferred_techniques:
            self.preferred_techniques.append(technique)
            
    def get_profile_summary(self) -> Dict[str, Any]:
        """Get a summary of the threat actor profile"""
        return {
            'actor_id': self.actor_id,
            'sophistication': self.sophistication_level,
            'top_techniques': self.preferred_techniques[:3],
            'success_rate': round(self.success_rate, 2),
            'persistence': round(self.persistence_score, 2),
            'total_attacks': self.total_attacks
        }

# Extended ConversationTurn for replay analysis compatibility
# Note: ConversationTurn already exists but we extend it with additional attributes
# dynamically when needed in replay_analyzer.py