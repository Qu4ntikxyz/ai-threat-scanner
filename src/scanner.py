"""
Core scanner class for AI Threat Scanner
Enhanced with smart pattern matching capabilities (v0.1.2)
"""

import re
from datetime import datetime
from typing import Dict, List, Any, Optional

try:
    # Try relative imports first (when used as module)
    from .models import (
        ThreatResult, CONTEXT_USER_INPUT, CONTEXT_LLM_RESPONSE, CONTEXT_UNKNOWN,
        PatternMatch, ContextMetadata, IntentAnalysis, LegitimacyAnalysis, ThreatScore,
        IntentType, WhitelistCategory, ScoringFactors, DEFAULT_WEIGHTS,
        CONTEXT_EDUCATIONAL, CONTEXT_RESEARCH, CONTEXT_CODE_BLOCK, CONTEXT_DOCUMENTATION
    )
    from .patterns import (
        get_threat_patterns, get_whitelist_patterns, get_legitimate_context_patterns,
        HIGH_CONCERN_PATTERNS, SMART_PATTERN_CONFIG
    )
    from .context_analyzer import ContextAnalyzer, ContextType
    from .reporting import ReportGenerator
except ImportError:
    # Fall back to absolute imports (when run directly)
    from models import (
        ThreatResult, CONTEXT_USER_INPUT, CONTEXT_LLM_RESPONSE, CONTEXT_UNKNOWN,
        PatternMatch, ContextMetadata, IntentAnalysis, LegitimacyAnalysis, ThreatScore,
        IntentType, WhitelistCategory, ScoringFactors, DEFAULT_WEIGHTS,
        CONTEXT_EDUCATIONAL, CONTEXT_RESEARCH, CONTEXT_CODE_BLOCK, CONTEXT_DOCUMENTATION
    )
    from patterns import (
        get_threat_patterns, get_whitelist_patterns, get_legitimate_context_patterns,
        HIGH_CONCERN_PATTERNS, SMART_PATTERN_CONFIG
    )
    from context_analyzer import ContextAnalyzer, ContextType
    from reporting import ReportGenerator


class AIThreatScanner:
    """Core scanner for detecting LLM vulnerabilities with smart pattern matching"""
    
    def __init__(self, verbose: bool = False, smart_matching: bool = False):
        self.version = "0.1.2"
        self.verbose = verbose
        self.smart_matching = smart_matching
        self.patterns = get_threat_patterns()
        self.results = []
        
        # Smart matching components (only initialized if enabled)
        if self.smart_matching:
            self.context_analyzer = ContextAnalyzer()
            self.whitelist_patterns = get_whitelist_patterns()
            self.legitimate_patterns = get_legitimate_context_patterns()
            self.scoring_weights = DEFAULT_WEIGHTS.copy()
        
        # Conversation tracking components
        self.conversation_manager = None
        self.active_session = None
        
    def scan_prompt(self, prompt: str, context: str = CONTEXT_UNKNOWN) -> Dict[str, Any]:
        """Scan a single prompt for threats with optional smart pattern matching
        
        Args:
            prompt: The text to scan for threats
            context: Context type - "user_input", "llm_response", or "unknown"
        """
        if self.smart_matching:
            return self._smart_scan(prompt, context)
        else:
            # Fall back to v0.1.1 behavior for backward compatibility
            return self._legacy_scan(prompt, context)
    
    def _legacy_scan(self, prompt: str, context: str) -> Dict[str, Any]:
        """Legacy scanning method (v0.1.1 behavior)"""
        threats_found = []
        risk_score = 0
        
        # Normalize prompt for better detection
        normalized_prompt = prompt.lower().strip()
        
        # Check each threat category
        for threat_type, threat_data in self.patterns.items():
            for pattern in threat_data["patterns"]:
                if pattern.lower() in normalized_prompt:
                    position = normalized_prompt.find(pattern.lower())
                    
                    # Apply context-aware severity adjustment
                    base_severity = threat_data["severity"]
                    adjusted_severity = self._adjust_severity_for_context(base_severity, context, pattern)
                    
                    threat = ThreatResult(
                        threat_type=threat_type,
                        pattern=pattern,
                        severity=adjusted_severity,
                        description=threat_data["description"],
                        position=position,
                        context=context
                    )
                    threats_found.append(threat)
                    risk_score += adjusted_severity
        
        # Calculate final risk score (max 100)
        final_risk = min(risk_score, 100)
        
        return {
            "timestamp": datetime.now().isoformat(),
            "prompt": prompt[:200] + "..." if len(prompt) > 200 else prompt,
            "prompt_length": len(prompt),
            "context": context,
            "threats": [
                {
                    "type": t.threat_type,
                    "pattern": t.pattern,
                    "severity": t.severity,
                    "description": t.description,
                    "position": t.position,
                    "context": t.context
                } for t in threats_found
            ],
            "risk_score": final_risk,
            "risk_level": self._get_risk_level(final_risk),
            "safe": len(threats_found) == 0
        }
    
    def _smart_scan(self, prompt: str, context_hint: str) -> Dict[str, Any]:
        """Smart scanning with advanced pattern matching"""
        
        # Step 1: Analyze context
        context_metadata = self.context_analyzer.analyze_context(prompt)
        # Override primary context from provided hint when available (e.g., "context_type=documentation; ...")
        self._override_context_from_hint(context_hint, context_metadata)
        if self.verbose:
            try:
                print(f"[AIThreatScanner] primary_context={self._to_context_str(context_metadata.primary_context)} meta={context_metadata.is_meta_discussion}")
            except Exception:
                pass
        
        # Step 2: Perform pattern matching with context awareness
        pattern_matches = self._evaluate_patterns_with_context(prompt, context_metadata)
        
        # Step 3: Check for legitimate use cases
        legitimacy_analysis = self._analyze_legitimacy(prompt, pattern_matches, context_metadata)
        
        # Step 4: Analyze intent
        intent_analysis = self._analyze_intent(prompt, pattern_matches, context_metadata)
        
        # Step 5: Calculate weighted threat score
        threat_score = self._calculate_weighted_score(pattern_matches, context_metadata, legitimacy_analysis, intent_analysis, prompt)
        
        # Step 6: Generate enhanced report
        return self._generate_smart_report(prompt, context_hint, context_metadata, pattern_matches, legitimacy_analysis, intent_analysis, threat_score)
    
    def _evaluate_patterns_with_context(self, text: str, context_metadata: ContextMetadata) -> List[PatternMatch]:
        """Evaluate patterns with context-aware adjustments"""
        matches = []
        normalized_text = text.lower().strip()
        
        for threat_type, threat_data in self.patterns.items():
            for pattern in threat_data["patterns"]:
                if pattern.lower() in normalized_text:
                    position = normalized_text.find(pattern.lower())
                    
                    # Create pattern match with enhanced metadata
                    match = PatternMatch(
                        pattern=pattern,
                        pattern_type=threat_type,
                        position=position,
                        confidence=1.0,  # Base confidence
                        base_severity=threat_data["severity"],
                        adjusted_severity=threat_data["severity"]
                    )
                    
                    # Extract context window around match
                    window_size = SMART_PATTERN_CONFIG["context_window_size"] // 2
                    start = max(0, position - window_size)
                    end = min(len(text), position + len(pattern) + window_size)
                    match.context_window = text[start:end]
                    
                    # Check for quotes and negation
                    match.is_quoted = self.context_analyzer.is_quoted_context(text, position)
                    match.is_negated = self.context_analyzer.is_negated_context(text, position)
                    
                    # Apply context-specific adjustments
                    match = self._apply_context_adjustments(match, context_metadata, threat_data)
                    
                    # Calculate semantic coherence
                    match.semantic_coherence = self._calculate_semantic_coherence(match, context_metadata)
                    
                    matches.append(match)
        
        return matches
    
    def _apply_context_adjustments(self, match: PatternMatch, context_metadata: ContextMetadata, threat_data: Dict) -> PatternMatch:
        """Apply context-specific adjustments to pattern match"""
        
        # Get context sensitivity settings for this threat type
        context_sensitivity = threat_data.get("context_sensitivity", {})
        primary_context = self._to_context_str(context_metadata.primary_context)
        
        # Apply context-based confidence adjustment
        if primary_context in context_sensitivity:
            context_multiplier = context_sensitivity[primary_context]
            match.confidence *= context_multiplier
            match.adjusted_severity = int(match.base_severity * context_multiplier)
        
        # Apply quote and negation adjustments
        if match.is_quoted:
            match.confidence *= 0.5  # Reduce confidence for quoted patterns
            match.adjusted_severity = int(match.adjusted_severity * 0.5)
        
        if match.is_negated:
            match.confidence *= 0.3  # Significant reduction for negated patterns
            match.adjusted_severity = int(match.adjusted_severity * 0.3)
        
        # Ensure minimum values with benign-context floor-to-zero allowance
        match.confidence = max(match.confidence, 0.1)
        benign_contexts = {CONTEXT_EDUCATIONAL, CONTEXT_RESEARCH, CONTEXT_DOCUMENTATION, CONTEXT_CODE_BLOCK}
        primary_context = self._to_context_str(context_metadata.primary_context)
        floor = 0 if (match.is_quoted or match.is_negated or primary_context in benign_contexts) else 1
        match.adjusted_severity = max(match.adjusted_severity, floor)
        
        return match
    
    def _calculate_semantic_coherence(self, match: PatternMatch, context_metadata: ContextMetadata) -> float:
        """Calculate how well the pattern fits semantically in context"""
        
        # Basic coherence based on context type
        primary_context = self._to_context_str(context_metadata.primary_context)
        
        # Educational/research contexts with security patterns are coherent
        if primary_context in [CONTEXT_EDUCATIONAL, CONTEXT_RESEARCH]:
            if any(marker in match.context_window.lower() for marker in ["security", "vulnerability", "attack", "threat"]):
                return 0.9
        
        # Code blocks with technical patterns are coherent
        if primary_context == CONTEXT_CODE_BLOCK:
            if any(marker in match.context_window.lower() for marker in ["function", "class", "import", "def"]):
                return 0.8
        
        # Documentation with policy patterns is coherent
        if primary_context == CONTEXT_DOCUMENTATION:
            if any(marker in match.context_window.lower() for marker in ["policy", "procedure", "guideline"]):
                return 0.85
        
        # Default coherence
        return 0.5
    
    def _analyze_legitimacy(self, text: str, pattern_matches: List[PatternMatch], context_metadata: ContextMetadata) -> LegitimacyAnalysis:
        """Analyze if the patterns represent legitimate use cases"""
        analysis = LegitimacyAnalysis()
        text_lower = text.lower()
        
        # Check whitelist patterns
        for category, patterns in self.whitelist_patterns.items():
            for pattern_regex in patterns:
                if re.search(pattern_regex, text, re.IGNORECASE):
                    analysis.is_legitimate = True
                    analysis.category = category
                    analysis.evidence.append(f"Matched whitelist pattern: {pattern_regex}")
                    analysis.legitimacy_score += 0.3
        
        # Check legitimate context patterns
        for pattern_regex in self.legitimate_patterns:
            if re.search(pattern_regex, text, re.IGNORECASE):
                analysis.legitimacy_score += 0.2
                analysis.evidence.append(f"Legitimate context indicator: {pattern_regex}")
        
        # Context-based legitimacy scoring
        primary_ctx = self._to_context_str(context_metadata.primary_context)
        if primary_ctx in [CONTEXT_EDUCATIONAL, CONTEXT_RESEARCH]:
            analysis.legitimacy_score += 0.4
            analysis.evidence.append("Educational/research context detected")
        if primary_ctx == CONTEXT_DOCUMENTATION:
            analysis.legitimacy_score += 0.3
            analysis.evidence.append("Documentation context detected")
        if primary_ctx == CONTEXT_CODE_BLOCK:
            analysis.legitimacy_score += 0.2
            analysis.evidence.append("Code block context detected")
        
        if context_metadata.is_meta_discussion:
            analysis.legitimacy_score += 0.3
            analysis.evidence.append("Meta-discussion about security detected")
        
        # Cap legitimacy score
        analysis.legitimacy_score = min(analysis.legitimacy_score, 1.0)
        
        # Determine if legitimate based on score
        if analysis.legitimacy_score >= 0.6:
            analysis.is_legitimate = True
        
        return analysis
    
    def _analyze_intent(self, text: str, pattern_matches: List[PatternMatch], context_metadata: ContextMetadata) -> IntentAnalysis:
        """Analyze intent behind potentially dangerous patterns"""
        analysis = IntentAnalysis()
        text_lower = text.lower()
        
        # Check for explicit educational intent
        educational_indicators = ["example", "demonstrate", "explain", "teach", "learn", "educational", "tutorial"]
        educational_count = sum(1 for indicator in educational_indicators if indicator in text_lower)
        primary_context = self._to_context_str(context_metadata.primary_context)
        
        if educational_count >= 2 or primary_context == CONTEXT_EDUCATIONAL:
            analysis.intent_type = IntentType.EDUCATIONAL
            analysis.confidence = 0.8
            analysis.threat_reduction = 0.7
            analysis.supporting_evidence.append(f"Educational indicators: {educational_count}")
        
        # Check for research intent
        elif primary_context == CONTEXT_RESEARCH or any(marker in text_lower for marker in ["research", "study", "analysis", "academic"]):
            analysis.intent_type = IntentType.RESEARCH
            analysis.confidence = 0.75
            analysis.threat_reduction = 0.6
            analysis.supporting_evidence.append("Research context detected")
        
        # Check for meta-discussion
        elif context_metadata.is_meta_discussion:
            analysis.intent_type = IntentType.META_DISCUSSION
            analysis.confidence = 0.65
            analysis.threat_reduction = 0.6
            analysis.supporting_evidence.append("Meta-discussion detected")
        
        # Check for malicious indicators
        elif any(indicator in text_lower for indicator in ["hack", "exploit", "bypass", "break"]):
            analysis.intent_type = IntentType.MALICIOUS
            analysis.confidence = 0.8
            analysis.threat_reduction = 0.0
            analysis.supporting_evidence.append("Malicious indicators detected")
        
        else:
            analysis.intent_type = IntentType.UNKNOWN
            analysis.confidence = 0.5
            analysis.threat_reduction = 0.2
        
        return analysis
    
    def _calculate_weighted_score(self, pattern_matches: List[PatternMatch], context_metadata: ContextMetadata,
                                 legitimacy_analysis: LegitimacyAnalysis, intent_analysis: IntentAnalysis, text: str) -> ThreatScore:
        """Calculate weighted threat score based on multiple factors"""
        
        if not pattern_matches:
            return ThreatScore(raw_score=0.0, normalized_score=0.0, risk_level="SAFE")
        
        score_components = {}
        
        # Pattern severity component
        base_severity = sum(match.adjusted_severity for match in pattern_matches)
        score_components[ScoringFactors.PATTERN_SEVERITY] = base_severity
        
        # Context type component
        context_multiplier = self._get_context_multiplier(context_metadata.primary_context)
        score_components[ScoringFactors.CONTEXT_TYPE] = base_severity * context_multiplier
        
        # Pattern frequency component
        score_components[ScoringFactors.PATTERN_FREQUENCY] = len(pattern_matches) * 5
        
        # Pattern position component (early patterns are more suspicious)
        if pattern_matches:
            avg_position = sum(match.position for match in pattern_matches) / len(pattern_matches)
            position_score = max(0, 20 - (avg_position / len(text)) * 20)
            score_components[ScoringFactors.PATTERN_POSITION] = position_score
        
        # Pattern clustering component
        clustering_score = self._calculate_clustering_score(pattern_matches)
        score_components[ScoringFactors.PATTERN_CLUSTERING] = clustering_score
        
        # Intent strength component
        intent_score = (1.0 - intent_analysis.threat_reduction) * 20
        score_components[ScoringFactors.INTENT_STRENGTH] = intent_score
        
        # Legitimacy score component (negative impact)
        legitimacy_reduction = legitimacy_analysis.legitimacy_score * 30
        score_components[ScoringFactors.LEGITIMACY_SCORE] = legitimacy_reduction
        
        # Confidence level component
        avg_confidence = sum(match.confidence for match in pattern_matches) / len(pattern_matches)
        score_components[ScoringFactors.CONFIDENCE_LEVEL] = avg_confidence * 15
         
        # Early SAFE guard: if benign legitimacy/context and minimal adjusted severity sum, force SAFE.
        primary_ctx = self._to_context_str(context_metadata.primary_context)
        benign_contexts = {CONTEXT_EDUCATIONAL, CONTEXT_RESEARCH, CONTEXT_DOCUMENTATION, CONTEXT_CODE_BLOCK}
        sum_adj = sum(m.adjusted_severity for m in pattern_matches)
        if (
            (legitimacy_analysis.legitimacy_score >= 0.6 and primary_ctx in benign_contexts and sum_adj <= 5)
            or (primary_ctx in benign_contexts and sum_adj <= 3)
        ):
            return ThreatScore(
                raw_score=0.0,
                normalized_score=0.0,
                components=score_components,
                confidence=avg_confidence,
                risk_level="SAFE"
            )
         
        # Calculate weighted final score
        final_score = 0.0
        for factor, score in score_components.items():
            weight = self.scoring_weights.get(factor, 0.0)
            final_score += score * weight
        
        # Normalize score
        normalized_score = max(0, min(100, final_score))
        
        return ThreatScore(
            raw_score=final_score,
            normalized_score=normalized_score,
            components=score_components,
            confidence=avg_confidence,
            risk_level=self._get_risk_level(int(normalized_score))
        )
    
    def _to_context_str(self, context: Any) -> str:
        """Normalize context to string value for comparisons and serialization"""
        try:
            from enum import Enum
            if isinstance(context, Enum):
                return context.value
        except Exception:
            pass
        return str(context)

    def _override_context_from_hint(self, context_hint: str, context_metadata: ContextMetadata) -> None:
        """
        Override the primary context from a context hint string when present.
        Expected hint format example: 'context_type=documentation; tags=[...]'
        """
        try:
            hint = (context_hint or "").lower()
            import re as _re
            m = _re.search(r"context_type\s*=\s*([a-z_]+)", hint)
            if not m:
                return
            ct = m.group(1)
            mapping = {
                "educational": CONTEXT_EDUCATIONAL,
                "research": CONTEXT_RESEARCH,
                "documentation": CONTEXT_DOCUMENTATION,
                "code_block": CONTEXT_CODE_BLOCK,
                "llm_response": CONTEXT_LLM_RESPONSE,
                "user_input": CONTEXT_USER_INPUT,
                "unknown": CONTEXT_UNKNOWN,
            }
            if ct in mapping:
                context_metadata.primary_context = mapping[ct]
        except Exception:
            # Do not fail scanning due to hint parsing
            pass

    def _get_context_multiplier(self, context: str) -> float:
        """Get multiplier based on context type"""
        context = self._to_context_str(context)
        multipliers = {
            CONTEXT_USER_INPUT: 1.0,
            CONTEXT_LLM_RESPONSE: 0.6,
            CONTEXT_EDUCATIONAL: 0.3,
            CONTEXT_RESEARCH: 0.4,
            CONTEXT_CODE_BLOCK: 0.5,
            CONTEXT_DOCUMENTATION: 0.4,
            CONTEXT_UNKNOWN: 0.8
        }
        return multipliers.get(context, 0.8)
    
    def _calculate_clustering_score(self, pattern_matches: List[PatternMatch]) -> float:
        """Calculate score based on pattern clustering"""
        if len(pattern_matches) < 2:
            return 0.0
        
        cluster_score = 0.0
        window_size = SMART_PATTERN_CONFIG["clustering_window"]
        
        for i, match1 in enumerate(pattern_matches):
            for match2 in pattern_matches[i+1:]:
                distance = abs(match2.position - match1.position)
                if distance <= window_size:
                    proximity_score = 1.0 - (distance / window_size)
                    if match1.pattern_type != match2.pattern_type:
                        proximity_score *= 1.5  # Different types are more suspicious
                    cluster_score += proximity_score
        
        return min(20.0, cluster_score * 5)  # Cap at 20 points
    
    def _generate_smart_report(self, prompt: str, context_hint: str, context_metadata: ContextMetadata,
                              pattern_matches: List[PatternMatch], legitimacy_analysis: LegitimacyAnalysis,
                              intent_analysis: IntentAnalysis, threat_score: ThreatScore) -> Dict[str, Any]:
        """Generate enhanced report with smart matching results"""
        
        return {
            "timestamp": datetime.now().isoformat(),
            "prompt": prompt[:200] + "..." if len(prompt) > 200 else prompt,
            "prompt_length": len(prompt),
            "context_hint": context_hint,  # Original context hint for compatibility
            
            # Enhanced context analysis
            "context_metadata": {
                "primary_context": self._to_context_str(context_metadata.primary_context),
                "secondary_contexts": [self._to_context_str(c) for c in context_metadata.secondary_contexts],
                "confidence_scores": context_metadata.confidence_scores,
                "is_meta_discussion": context_metadata.is_meta_discussion,
                "has_quotes": context_metadata.has_quotes,
                "has_negation": context_metadata.has_negation
            },
            
            # Pattern matching results
            "pattern_matches": [
                {
                    "pattern": match.pattern,
                    "type": match.pattern_type,
                    "position": match.position,
                    "confidence": match.confidence,
                    "base_severity": match.base_severity,
                    "adjusted_severity": match.adjusted_severity,
                    "is_quoted": match.is_quoted,
                    "is_negated": match.is_negated,
                    "semantic_coherence": match.semantic_coherence
                } for match in pattern_matches
            ],
            
            # Legitimacy analysis
            "legitimacy_analysis": {
                "is_legitimate": legitimacy_analysis.is_legitimate,
                "legitimacy_score": legitimacy_analysis.legitimacy_score,
                "category": legitimacy_analysis.category.value if legitimacy_analysis.category else None,
                "evidence": legitimacy_analysis.evidence
            },
            
            # Intent analysis
            "intent_analysis": {
                "intent_type": intent_analysis.intent_type.value,
                "confidence": intent_analysis.confidence,
                "threat_reduction": intent_analysis.threat_reduction,
                "supporting_evidence": intent_analysis.supporting_evidence
            },
            
            # Threat scoring
            "threat_score": {
                "raw_score": threat_score.raw_score,
                "normalized_score": threat_score.normalized_score,
                "components": threat_score.components,
                "confidence": threat_score.confidence,
                "risk_level": threat_score.risk_level
            },
            
            # Backward compatibility fields
            "context": context_hint,
            "threats": [
                {
                    "type": match.pattern_type,
                    "pattern": match.pattern,
                    "severity": match.adjusted_severity,
                    "description": self.patterns[match.pattern_type]["description"],
                    "position": match.position,
                    "context": context_hint
                } for match in pattern_matches
            ],
            "risk_score": int(threat_score.normalized_score),
            "risk_level": threat_score.risk_level,
            "safe": threat_score.normalized_score == 0
        }
    
    def _adjust_severity_for_context(self, base_severity: int, context: str, pattern: str) -> int:
        """Legacy context adjustment method (for backward compatibility)"""
        if context == CONTEXT_LLM_RESPONSE:
            reduction_factor = 0.4  # 60% reduction
            
            if any(concern_pattern in pattern.lower() for concern_pattern in HIGH_CONCERN_PATTERNS):
                reduction_factor = 0.7  # Only 30% reduction for high-concern patterns
            
            adjusted_severity = int(base_severity * reduction_factor)
            return max(adjusted_severity, 5)  # Minimum severity of 5 to maintain awareness
            
        elif context == CONTEXT_USER_INPUT:
            return base_severity
            
        else:  # context == CONTEXT_UNKNOWN
            return int(base_severity * 0.9)
    
    def _get_risk_level(self, score: int) -> str:
        """Convert numeric score to risk level"""
        if score == 0:
            return "SAFE"
        elif score < 20:
            return "LOW"
        elif score < 50:
            return "MEDIUM"
        elif score < 80:
            return "HIGH"
        else:
            return "CRITICAL"
    
    def scan_batch(self, prompts: List[str], context: str = CONTEXT_UNKNOWN) -> List[Dict]:
        """Scan multiple prompts with context awareness
        
        Args:
            prompts: List of text strings to scan
            context: Context type - "user_input", "llm_response", or "unknown"
        """
        results = []
        for i, prompt in enumerate(prompts, 1):
            if self.verbose:
                print(f"Scanning prompt {i}/{len(prompts)}...")
            result = self.scan_prompt(prompt, context)
            results.append(result)
        return results
    
    def generate_report(self, results: List[Dict], format: str = "text") -> str:
        """Generate security report (backward compatibility method)"""
        report_generator = ReportGenerator()
        return report_generator.generate_report(results, format)
    
    # Conversation mode methods
    def start_conversation(self, session_id: Optional[str] = None,
                          timeout_minutes: int = 30,
                          max_turns: int = 100) -> str:
        """
        Start a new conversation session for multi-turn analysis.
        
        Args:
            session_id: Optional session ID (generates UUID if not provided)
            timeout_minutes: Session timeout in minutes (default: 30)
            max_turns: Maximum number of turns allowed (default: 100)
            
        Returns:
            Session ID for the created conversation
        """
        # Lazy import to avoid circular dependency
        from .conversation import ConversationManager, ConversationSession
        
        if self.conversation_manager is None:
            self.conversation_manager = ConversationManager()
        
        session = self.conversation_manager.create_session(
            session_id=session_id,
            timeout_minutes=timeout_minutes,
            max_turns=max_turns
        )
        
        self.active_session = session
        
        if self.verbose:
            print(f"Started conversation session: {session.session_id}")
        
        return session.session_id
    
    def add_turn(self, prompt: str, response: Optional[str] = None,
                 session_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Add a turn to an ongoing conversation and analyze it.
        
        Args:
            prompt: User prompt for this turn
            response: Optional AI response
            session_id: Session ID (uses active session if not provided)
            
        Returns:
            Analysis result for this turn including threat detection
            
        Raises:
            ValueError: If no active session and session_id not provided
        """
        # Get the session
        if session_id:
            if self.conversation_manager is None:
                from .conversation import ConversationManager
                self.conversation_manager = ConversationManager()
            session = self.conversation_manager.get_session(session_id)
            if not session:
                raise ValueError(f"Session {session_id} not found or inactive")
        elif self.active_session:
            session = self.active_session
        else:
            raise ValueError("No active session. Start a conversation first.")
        
        # Analyze the prompt
        threat_result = self.scan_prompt(prompt, CONTEXT_USER_INPUT)
        
        # Add turn to conversation
        turn = session.add_turn(prompt, response, threat_result)
        
        # Return turn analysis
        return {
            "session_id": session.session_id,
            "turn_number": turn.turn_number,
            "timestamp": turn.timestamp.isoformat(),
            "prompt": prompt,
            "response": response,
            "threat_analysis": threat_result,
            "cumulative_risk_score": session.cumulative_risk_score,
            "escalation_detected": session.escalation_detected,
            "detected_chains": [
                {
                    "type": chain.chain_type,
                    "confidence": chain.confidence,
                    "description": chain.description
                }
                for chain in session.detected_chains
            ]
        }
    
    def scan_conversation(self, session_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze a complete conversation for multi-turn attack patterns.
        
        Args:
            session_id: Session ID to analyze (uses active session if not provided)
            
        Returns:
            Comprehensive conversation analysis including attack chains
            
        Raises:
            ValueError: If no active session and session_id not provided
        """
        # Get the session
        if session_id:
            if self.conversation_manager is None:
                from .conversation import ConversationManager
                self.conversation_manager = ConversationManager()
            session = self.conversation_manager.get_session(session_id)
            if not session:
                raise ValueError(f"Session {session_id} not found or inactive")
        elif self.active_session:
            session = self.active_session
        else:
            raise ValueError("No active session. Start a conversation first.")
        
        # Perform comprehensive analysis
        analysis = session.analyze_conversation()
        
        # Convert to dictionary format
        result = analysis.to_dict()
        
        # Add additional metadata
        result["scanner_version"] = self.version
        result["smart_matching_enabled"] = self.smart_matching
        result["timestamp"] = datetime.now().isoformat()
        
        return result
    
    def end_conversation(self, session_id: Optional[str] = None) -> bool:
        """
        End a conversation session.
        
        Args:
            session_id: Session ID to end (uses active session if not provided)
            
        Returns:
            True if session was ended, False if not found
        """
        if session_id:
            if self.conversation_manager:
                success = self.conversation_manager.end_session(session_id)
                if self.active_session and self.active_session.session_id == session_id:
                    self.active_session = None
                return success
        elif self.active_session:
            session_id = self.active_session.session_id
            if self.conversation_manager:
                success = self.conversation_manager.end_session(session_id)
                self.active_session = None
                return success
        
        return False
    
    def get_active_sessions(self) -> List[str]:
        """
        Get list of all active conversation sessions.
        
        Returns:
            List of active session IDs
        """
        if self.conversation_manager is None:
            return []
        
        sessions = self.conversation_manager.get_active_sessions()
        return [session.session_id for session in sessions]