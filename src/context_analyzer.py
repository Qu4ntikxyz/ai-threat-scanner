"""
Context analysis module for AI Threat Scanner
Provides sophisticated context detection and analysis capabilities
"""

import re
from typing import Dict, List, Optional, Tuple
from enum import Enum

# Context type enumeration
class ContextType(Enum):
    USER_INPUT = "user_input"
    LLM_RESPONSE = "llm_response"
    CONVERSATION = "conversation"
    CODE_BLOCK = "code_block"
    EDUCATIONAL = "educational"
    RESEARCH = "research"
    DOCUMENTATION = "documentation"
    UNKNOWN = "unknown"

class ContextIndicators:
    """Signals that help identify context type"""
    
    EDUCATIONAL_MARKERS = [
        "example:", "for instance", "tutorial", "lesson",
        "learn", "understand", "explain", "demonstrate",
        "teaching", "educational", "academic", "let me explain",
        "this shows", "to illustrate", "for learning"
    ]
    
    RESEARCH_MARKERS = [
        "research", "analysis", "study", "investigate",
        "vulnerability", "security testing", "penetration test",
        "ethical hacking", "bug bounty", "responsible disclosure",
        "academic paper", "thesis", "dissertation"
    ]
    
    CODE_MARKERS = [
        "```", "def ", "function", "class ", "import ",
        "const ", "var ", "let ", "return ", "if (",
        "print(", "console.log", "#!/", "<?php"
    ]
    
    CONVERSATION_MARKERS = [
        "you:", "user:", "assistant:", "ai:", "bot:",
        "human:", "system:", ">>", "<<", "Q:", "A:",
        "me:", "chatbot:", "gpt:"
    ]
    
    META_DISCUSSION_MARKERS = [
        "prompt injection", "jailbreak technique", "security vulnerability",
        "attack vector", "threat pattern", "security measure",
        "defense mechanism", "mitigation strategy", "discussing about",
        "talking about", "analyzing the", "explaining how"
    ]
    
    DOCUMENTATION_MARKERS = [
        "documentation", "api reference", "user guide",
        "developer guide", "security guide", "best practices",
        "threat model", "risk assessment", "security policy"
    ]

class ContextMetadata:
    """Metadata about text context"""
    
    def __init__(self):
        self.primary_context: ContextType = ContextType.UNKNOWN
        self.secondary_contexts: List[ContextType] = []
        self.confidence_scores: Dict[ContextType, float] = {}
        self.intent_signals: List[str] = []
        self.is_meta_discussion: bool = False
        self.semantic_markers: Dict[str, int] = {}
        self.has_quotes: bool = False
        self.has_negation: bool = False

class ContextAnalyzer:
    """Analyzes text to determine context and extract metadata"""
    
    def __init__(self):
        self.indicators = ContextIndicators()
        
    def analyze_context(self, text: str, window_size: int = 500) -> ContextMetadata:
        """
        Analyze text to determine context and extract metadata
        
        Args:
            text: The input text to analyze
            window_size: Characters to examine around patterns
        
        Returns:
            ContextMetadata with classification and confidence scores
        """
        metadata = ContextMetadata()
        text_lower = text.lower()
        
        # Step 1: Calculate confidence scores for each context type
        metadata.confidence_scores = self._calculate_confidence_scores(text_lower)
        
        # Step 2: Identify primary context type
        metadata.primary_context = self._classify_primary_context(metadata.confidence_scores)
        
        # Step 3: Detect secondary contexts (can have multiple)
        metadata.secondary_contexts = self._detect_secondary_contexts(metadata.confidence_scores)
        
        # Step 4: Extract intent signals
        metadata.intent_signals = self._extract_intent_signals(text_lower)
        
        # Step 5: Identify meta-discussion indicators
        metadata.is_meta_discussion = self._detect_meta_discussion(text_lower)
        
        # Step 6: Detect quotes and negation
        metadata.has_quotes = self._detect_quotes(text)
        metadata.has_negation = self._detect_negation(text_lower)
        
        # Step 7: Extract semantic markers
        metadata.semantic_markers = self._extract_semantic_markers(text_lower)
        
        return metadata
    
    def _calculate_confidence_scores(self, text_lower: str) -> Dict[ContextType, float]:
        """Calculate confidence scores for each context type"""
        scores = {}
        
        # Educational context scoring
        educational_count = sum(1 for marker in self.indicators.EDUCATIONAL_MARKERS 
                              if marker in text_lower)
        scores[ContextType.EDUCATIONAL] = min(educational_count * 0.3, 1.0)
        
        # Research context scoring
        research_count = sum(1 for marker in self.indicators.RESEARCH_MARKERS 
                           if marker in text_lower)
        scores[ContextType.RESEARCH] = min(research_count * 0.35, 1.0)
        
        # Code block scoring
        code_count = sum(1 for marker in self.indicators.CODE_MARKERS 
                        if marker in text_lower)
        scores[ContextType.CODE_BLOCK] = min(code_count * 0.4, 1.0)
        
        # Conversation scoring
        conversation_count = sum(1 for marker in self.indicators.CONVERSATION_MARKERS 
                               if marker in text_lower)
        scores[ContextType.CONVERSATION] = min(conversation_count * 0.25, 1.0)
        
        # Documentation scoring
        doc_count = sum(1 for marker in self.indicators.DOCUMENTATION_MARKERS 
                       if marker in text_lower)
        scores[ContextType.DOCUMENTATION] = min(doc_count * 0.3, 1.0)
        
        # Default scores for basic types
        scores[ContextType.USER_INPUT] = 0.5  # Default assumption
        scores[ContextType.LLM_RESPONSE] = 0.3  # Lower default
        scores[ContextType.UNKNOWN] = 0.1
        
        return scores
    
    def _classify_primary_context(self, confidence_scores: Dict[ContextType, float]) -> ContextType:
        """Identify the primary context type based on confidence scores"""
        # Find the context type with highest confidence
        max_score = 0.0
        primary_context = ContextType.UNKNOWN
        
        for context_type, score in confidence_scores.items():
            if score > max_score:
                max_score = score
                primary_context = context_type
        
        # Require minimum confidence threshold
        if max_score < 0.3:
            return ContextType.UNKNOWN
            
        return primary_context
    
    def _detect_secondary_contexts(self, confidence_scores: Dict[ContextType, float]) -> List[ContextType]:
        """Detect secondary contexts that also have significant confidence"""
        secondary_contexts = []
        
        for context_type, score in confidence_scores.items():
            if score >= 0.4 and context_type != self._classify_primary_context(confidence_scores):
                secondary_contexts.append(context_type)
        
        return secondary_contexts
    
    def _extract_intent_signals(self, text_lower: str) -> List[str]:
        """Extract signals that indicate intent"""
        intent_signals = []
        
        # Educational intent signals
        educational_signals = [
            "let me explain", "for example", "this demonstrates",
            "to show you", "educational purpose", "learning about"
        ]
        
        # Malicious intent signals
        malicious_signals = [
            "hack", "exploit", "bypass", "circumvent",
            "break", "override", "ignore", "disable"
        ]
        
        # Research intent signals
        research_signals = [
            "studying", "analyzing", "investigating", "researching",
            "academic", "thesis", "paper", "publication"
        ]
        
        all_signals = educational_signals + malicious_signals + research_signals
        
        for signal in all_signals:
            if signal in text_lower:
                intent_signals.append(signal)
        
        return intent_signals
    
    def _detect_meta_discussion(self, text_lower: str) -> bool:
        """Check if text is discussing security concepts rather than attempting them"""
        meta_count = sum(1 for marker in self.indicators.META_DISCUSSION_MARKERS 
                        if marker in text_lower)
        
        # Also check for discussion patterns
        discussion_patterns = [
            "discussing", "talking about", "explaining", "describing",
            "analyzing", "studying", "learning about", "understanding"
        ]
        
        discussion_count = sum(1 for pattern in discussion_patterns 
                             if pattern in text_lower)
        
        return (meta_count >= 1) or (discussion_count >= 2)
    
    def _detect_quotes(self, text: str) -> bool:
        """Detect if text contains quoted content"""
        quote_patterns = [
            r'"[^"]*"',  # Double quotes
            r"'[^']*'",  # Single quotes
            r'`[^`]*`',  # Backticks
            r'>[^<]*<',  # Angle brackets
        ]
        
        for pattern in quote_patterns:
            if re.search(pattern, text):
                return True
        
        return False
    
    def _detect_negation(self, text_lower: str) -> bool:
        """Detect negation patterns that might indicate non-malicious intent"""
        negation_patterns = [
            "not", "don't", "doesn't", "won't", "can't", "shouldn't",
            "never", "no", "without", "avoid", "prevent", "stop"
        ]
        
        return any(pattern in text_lower for pattern in negation_patterns)
    
    def _extract_semantic_markers(self, text_lower: str) -> Dict[str, int]:
        """Extract semantic markers for coherence analysis"""
        markers = {}
        
        # Security-related terms
        security_terms = [
            "security", "vulnerability", "attack", "threat", "risk",
            "protection", "defense", "mitigation", "prevention"
        ]
        
        # Educational terms
        educational_terms = [
            "example", "tutorial", "lesson", "guide", "explanation",
            "demonstration", "illustration", "teaching", "learning"
        ]
        
        # Technical terms
        technical_terms = [
            "system", "prompt", "instruction", "command", "code",
            "function", "method", "algorithm", "implementation"
        ]
        
        all_terms = {
            "security": security_terms,
            "educational": educational_terms,
            "technical": technical_terms
        }
        
        for category, terms in all_terms.items():
            count = sum(1 for term in terms if term in text_lower)
            markers[category] = count
        
        return markers
    
    def is_quoted_context(self, text: str, position: int, window_size: int = 50) -> bool:
        """Check if a pattern at given position is within quotes"""
        start = max(0, position - window_size)
        end = min(len(text), position + window_size)
        context_window = text[start:end]
        
        # Check for various quote types around the position
        quote_chars = ['"', "'", '`']
        
        for quote_char in quote_chars:
            before_quotes = context_window[:position-start].count(quote_char)
            after_quotes = context_window[position-start:].count(quote_char)
            
            # If odd number of quotes before and after, likely inside quotes
            if before_quotes % 2 == 1 and after_quotes % 2 == 1:
                return True
        
        return False
    
    def is_negated_context(self, text: str, position: int, window_size: int = 100) -> bool:
        """Check if a pattern at given position is in a negated context"""
        start = max(0, position - window_size)
        context_before = text[start:position].lower()
        
        negation_patterns = [
            r'\bnot\s+\w*\s*$',
            r'\bdon\'t\s+\w*\s*$',
            r'\bdoesn\'t\s+\w*\s*$',
            r'\bwon\'t\s+\w*\s*$',
            r'\bcan\'t\s+\w*\s*$',
            r'\bshouldn\'t\s+\w*\s*$',
            r'\bnever\s+\w*\s*$',
            r'\bavoid\s+\w*\s*$',
            r'\bprevent\s+\w*\s*$',
            r'\bwithout\s+\w*\s*$'
        ]
        
        for pattern in negation_patterns:
            if re.search(pattern, context_before):
                return True
        
        return False