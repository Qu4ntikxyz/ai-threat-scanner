"""
AI Threat Scanner - Enterprise-Grade Security Analysis for LLM Systems

A comprehensive security tool for detecting and analyzing vulnerabilities in Large Language Models,
including multi-turn attack detection, constraint erosion analysis, and real-world pattern intelligence.
"""

__version__ = "0.2.0"
__author__ = "Qu4ntik Security Research"
__email__ = "me@qu4ntik.xyz"
__license__ = "MIT"

# Core imports for easy access
from .scanner import AIThreatScanner
from .models import (
    ThreatResult, 
    CONTEXT_USER_INPUT, 
    CONTEXT_LLM_RESPONSE, 
    CONTEXT_UNKNOWN,
    CONTEXT_EDUCATIONAL, 
    CONTEXT_RESEARCH, 
    CONTEXT_CODE_BLOCK, 
    CONTEXT_DOCUMENTATION,
    PatternMatch, 
    ContextMetadata, 
    IntentAnalysis, 
    LegitimacyAnalysis, 
    ThreatScore,
    IntentType, 
    WhitelistCategory,
    ConversationTurn,
    SessionMetadata,
    AttackChain,
    ConversationAnalysis,
    ErosionAnalysis,
    ConversationHistory,
    ConstraintViolation,
    ErosionPattern,
    SafetyBoundary,
    ReplayAnalysis,
    AttackTimeline,
    ThreatActor
)
from .reporting import ReportGenerator
from .patterns import get_threat_patterns, get_whitelist_patterns
from .context_analyzer import ContextAnalyzer, ContextType
from .conversation import ConversationSession, ConversationManager, ConversationAnalyzer
from .constraint_erosion import ConstraintErosionDetector
from .attack_chains import get_attack_chain_patterns
from .replay_analyzer import ConversationReplayAnalyzer
from .reddit_patterns import get_reddit_patterns
from .community_patterns import CommunityPatternManager

# Main classes and functions
__all__ = [
    # Core scanner
    "AIThreatScanner",
    "ReportGenerator",
    
    # Models
    "ThreatResult",
    "PatternMatch",
    "ContextMetadata",
    "IntentAnalysis",
    "LegitimacyAnalysis",
    "ThreatScore",
    "IntentType",
    "WhitelistCategory",
    "ConversationTurn",
    "SessionMetadata",
    "AttackChain",
    "ConversationAnalysis",
    "ErosionAnalysis",
    "ConversationHistory",
    "ConstraintViolation",
    "ErosionPattern",
    "SafetyBoundary",
    "ReplayAnalysis",
    "AttackTimeline",
    "ThreatActor",
    
    # Context types
    "CONTEXT_USER_INPUT",
    "CONTEXT_LLM_RESPONSE",
    "CONTEXT_UNKNOWN",
    "CONTEXT_EDUCATIONAL",
    "CONTEXT_RESEARCH",
    "CONTEXT_CODE_BLOCK",
    "CONTEXT_DOCUMENTATION",
    
    # Pattern functions
    "get_threat_patterns",
    "get_whitelist_patterns",
    "get_attack_chain_patterns",
    "get_reddit_patterns",
    
    # Analyzers
    "ContextAnalyzer",
    "ContextType",
    "ConversationSession",
    "ConversationManager",
    "ConversationAnalyzer",
    "ConstraintErosionDetector",
    "ConversationReplayAnalyzer",
    "CommunityPatternManager"
]

# Package metadata
__description__ = "Enterprise-grade security analysis for Large Language Models"
__url__ = "https://github.com/Qu4ntikxyz/ai-threat-scanner"
__keywords__ = ["ai", "security", "llm", "threat-detection", "prompt-injection", "jailbreak", "conversation-analysis", "constraint-erosion"]