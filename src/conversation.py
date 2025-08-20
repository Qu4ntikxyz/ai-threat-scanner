"""
Conversation flow tracking and multi-turn analysis module.

This module provides session management, context persistence, and attack chain
detection for multi-turn conversations with AI systems.
"""

import uuid
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field

from .models import (
    ConversationTurn,
    SessionMetadata,
    AttackChain,
    ConversationAnalysis,
    ThreatResult,
    ErosionAnalysis,
    ConversationHistory
)
from .attack_chains import get_attack_chain_patterns
from .constraint_erosion import ConstraintErosionDetector
from .conversation_io import export_conversation, import_conversation


class ConversationSession:
    """Manages individual conversation sessions with context tracking."""
    
    def __init__(
        self,
        session_id: Optional[str] = None,
        timeout_minutes: int = 30,
        max_turns: int = 100
    ):
        """
        Initialize a conversation session.
        
        Args:
            session_id: Optional session ID (generates UUID if not provided)
            timeout_minutes: Session timeout in minutes (default: 30)
            max_turns: Maximum number of turns allowed (default: 100)
        """
        self.session_id = session_id or str(uuid.uuid4())
        self.timeout_minutes = timeout_minutes
        self.max_turns = max_turns
        
        # Session metadata
        self.created_at = datetime.now()
        self.last_activity = datetime.now()
        self.is_active = True
        
        # Conversation history
        self.turns: List[ConversationTurn] = []
        self.accumulated_context: str = ""
        self.cumulative_risk_score: float = 0.0
        
        # Attack chain detection
        self.detected_chains: List[AttackChain] = []
        self.attack_indicators: Dict[str, int] = {}
        self.trust_level: float = 0.0
        self.escalation_detected: bool = False
        
        # Pattern tracking
        self.pattern_history: List[Dict[str, Any]] = []
        self.pivot_points: List[int] = []  # Turn indices where intent shifts
        
        # Constraint erosion detection
        self.erosion_detector = ConstraintErosionDetector()
        self.erosion_analysis: Optional[ErosionAnalysis] = None
        
    def add_turn(
        self,
        prompt: str,
        response: Optional[str] = None,
        threat_result: Optional[ThreatResult] = None
    ) -> ConversationTurn:
        """
        Add a new turn to the conversation.
        
        Args:
            prompt: User prompt for this turn
            response: Optional AI response
            threat_result: Optional threat analysis result
            
        Returns:
            ConversationTurn object for the added turn
            
        Raises:
            ValueError: If session is inactive or max turns exceeded
        """
        # Check session validity
        if not self.is_active:
            raise ValueError(f"Session {self.session_id} is inactive")
            
        if len(self.turns) >= self.max_turns:
            raise ValueError(f"Maximum turns ({self.max_turns}) exceeded")
            
        # Check timeout
        if self._is_timed_out():
            self.is_active = False
            raise ValueError(f"Session {self.session_id} has timed out")
            
        # Create turn
        turn = ConversationTurn(
            turn_number=len(self.turns) + 1,
            timestamp=datetime.now(),
            prompt=prompt,
            response=response,
            threat_result=threat_result,
            context_before=self.accumulated_context
        )
        
        # Update session state
        self.turns.append(turn)
        self.last_activity = datetime.now()
        self._update_accumulated_context(prompt, response)
        
        # Update risk tracking
        if threat_result:
            self._update_risk_metrics(threat_result, turn.turn_number)
            
        # Detect attack chains
        self._detect_attack_chains()
        
        # Analyze for constraint erosion
        if threat_result:
            threat_score = threat_result.get('risk_score', 0) if isinstance(threat_result, dict) else getattr(threat_result, 'risk_score', 0)
        else:
            threat_score = 0
            
        erosion_result = self.erosion_detector.analyze_turn(
            prompt=prompt,
            turn_number=turn.turn_number,
            threat_score=threat_score,
            context=self.accumulated_context
        )
        
        # Store erosion analysis
        self.erosion_analysis = self.erosion_detector.get_erosion_analysis()
        
        # Check for critical erosion points
        if erosion_result.get('critical_point', False):
            if turn.turn_number not in self.pivot_points:
                self.pivot_points.append(turn.turn_number)
        
        return turn
        
    def _is_timed_out(self) -> bool:
        """Check if session has timed out."""
        timeout_threshold = timedelta(minutes=self.timeout_minutes)
        return datetime.now() - self.last_activity > timeout_threshold
        
    def _update_accumulated_context(self, prompt: str, response: Optional[str]):
        """Update accumulated context with new turn."""
        # Add prompt to context
        self.accumulated_context += f"\n[Turn {len(self.turns)}] User: {prompt}"
        
        # Add response if provided
        if response:
            self.accumulated_context += f"\n[Turn {len(self.turns)}] AI: {response}"
            
        # Trim context if too long (keep last 5000 chars)
        if len(self.accumulated_context) > 5000:
            self.accumulated_context = "..." + self.accumulated_context[-4997:]
            
    def _update_risk_metrics(self, threat_result: Any, turn_number: int):
        """Update cumulative risk metrics based on new threat result."""
        # Handle both dict and object formats
        if isinstance(threat_result, dict):
            risk_score = threat_result.get('risk_score', 0)
            threats = threat_result.get('threats', [])
        else:
            risk_score = getattr(threat_result, 'risk_score', 0)
            threats = getattr(threat_result, 'threats', [])
        
        # Update cumulative score (weighted average)
        weight = 1.0 + (0.1 * turn_number)  # Later turns have more weight
        self.cumulative_risk_score = (
            (self.cumulative_risk_score * (turn_number - 1) +
             risk_score * weight) /
            (turn_number - 1 + weight)
        )
        
        # Track pattern occurrences
        for threat in threats:
            if isinstance(threat, dict):
                pattern_key = f"{threat.get('type', 'unknown')}:{threat.get('pattern', 'unknown')}"
            else:
                pattern_key = f"{getattr(threat, 'category', 'unknown')}:{getattr(threat, 'pattern', 'unknown')}"
            self.attack_indicators[pattern_key] = (
                self.attack_indicators.get(pattern_key, 0) + 1
            )
            
        # Detect escalation
        if turn_number > 2:
            recent_scores = []
            for turn in self.turns[-3:]:
                if turn.threat_result:
                    if isinstance(turn.threat_result, dict):
                        recent_scores.append(turn.threat_result.get('risk_score', 0))
                    else:
                        recent_scores.append(getattr(turn.threat_result, 'risk_score', 0))
            
            if len(recent_scores) >= 2:
                if recent_scores[-1] > recent_scores[-2] * 1.5:
                    self.escalation_detected = True
                    if turn_number - 1 not in self.pivot_points:
                        self.pivot_points.append(turn_number - 1)
                        
    def _detect_attack_chains(self):
        """Detect multi-step attack patterns in conversation."""
        if len(self.turns) < 2:
            return
            
        chain_patterns = get_attack_chain_patterns()
        
        for pattern_name, pattern_config in chain_patterns.items():
            if self._matches_chain_pattern(pattern_config):
                # Check if this chain is already detected
                existing = any(
                    chain.chain_type == pattern_name 
                    for chain in self.detected_chains
                )
                
                if not existing:
                    chain = AttackChain(
                        chain_type=pattern_name,
                        start_turn=pattern_config.get('start_turn', 1),
                        end_turn=len(self.turns),
                        confidence=self._calculate_chain_confidence(pattern_config),
                        description=pattern_config.get('description', ''),
                        indicators=self._get_chain_indicators(pattern_config)
                    )
                    self.detected_chains.append(chain)
                    
    def _matches_chain_pattern(self, pattern_config: Dict) -> bool:
        """Check if conversation matches a specific attack chain pattern."""
        required_stages = pattern_config.get('stages', [])
        if not required_stages:
            return False
            
        matched_stages = 0
        for stage in required_stages:
            for turn in self.turns:
                if self._turn_matches_stage(turn, stage):
                    matched_stages += 1
                    break
                    
        # Require at least 70% of stages to match
        return matched_stages >= len(required_stages) * 0.7
        
    def _turn_matches_stage(self, turn: ConversationTurn, stage: Dict) -> bool:
        """Check if a turn matches a specific attack stage."""
        prompt_lower = turn.prompt.lower()
        
        # Check for required keywords
        keywords = stage.get('keywords', [])
        if keywords:
            if not any(keyword in prompt_lower for keyword in keywords):
                return False
                
        # Check for risk level threshold
        min_risk = stage.get('min_risk_score', 0)
        if turn.threat_result:
            if isinstance(turn.threat_result, dict):
                risk_score = turn.threat_result.get('risk_score', 0)
            else:
                risk_score = getattr(turn.threat_result, 'risk_score', 0)
            if risk_score < min_risk:
                return False
            
        return True
        
    def _calculate_chain_confidence(self, pattern_config: Dict) -> float:
        """Calculate confidence score for detected attack chain."""
        base_confidence = 0.5
        
        # Increase confidence based on number of matching indicators
        indicators = pattern_config.get('indicators', [])
        matched_indicators = sum(
            1 for indicator in indicators
            if any(indicator in turn.prompt.lower() for turn in self.turns)
        )
        
        if indicators:
            indicator_boost = (matched_indicators / len(indicators)) * 0.3
            base_confidence += indicator_boost
            
        # Increase confidence if escalation detected
        if self.escalation_detected:
            base_confidence += 0.2
            
        return min(base_confidence, 1.0)
        
    def _get_chain_indicators(self, pattern_config: Dict) -> List[str]:
        """Get list of indicators found for this attack chain."""
        indicators = []
        
        for turn in self.turns:
            prompt_lower = turn.prompt.lower()
            for indicator in pattern_config.get('indicators', []):
                if indicator in prompt_lower and indicator not in indicators:
                    indicators.append(indicator)
                    
        return indicators
        
    def analyze_conversation(self) -> ConversationAnalysis:
        """
        Perform comprehensive analysis of the entire conversation.
        
        Returns:
            ConversationAnalysis object with complete analysis results
        """
        # Calculate timing metrics
        if len(self.turns) > 1:
            turn_intervals = []
            for i in range(1, len(self.turns)):
                interval = (
                    self.turns[i].timestamp - self.turns[i-1].timestamp
                ).total_seconds()
                turn_intervals.append(interval)
                
            avg_interval = sum(turn_intervals) / len(turn_intervals)
            rapid_fire = any(interval < 2.0 for interval in turn_intervals)
        else:
            avg_interval = 0.0
            rapid_fire = False
            
        # Identify highest risk turn
        highest_risk_turn = 0
        highest_risk_score = 0.0
        for turn in self.turns:
            if turn.threat_result:
                if isinstance(turn.threat_result, dict):
                    risk_score = turn.threat_result.get('risk_score', 0)
                else:
                    risk_score = getattr(turn.threat_result, 'risk_score', 0)
                if risk_score > highest_risk_score:
                    highest_risk_score = risk_score
                    highest_risk_turn = turn.turn_number
                
        # Create session metadata
        metadata = SessionMetadata(
            session_id=self.session_id,
            created_at=self.created_at,
            last_activity=self.last_activity,
            total_turns=len(self.turns),
            is_active=self.is_active,
            timeout_minutes=self.timeout_minutes
        )
        
        # Create analysis
        # Include erosion analysis if available
        erosion_data = None
        if self.erosion_analysis:
            erosion_data = self.erosion_analysis.to_dict()
        
        analysis = ConversationAnalysis(
            session_metadata=metadata,
            turns=self.turns,
            detected_chains=self.detected_chains,
            cumulative_risk_score=self.cumulative_risk_score,
            highest_risk_turn=highest_risk_turn,
            pivot_points=self.pivot_points,
            escalation_detected=self.escalation_detected,
            average_turn_interval=avg_interval,
            rapid_fire_detected=rapid_fire,
            attack_indicators=dict(self.attack_indicators),
            final_risk_level=self._calculate_final_risk_level(),
            erosion_analysis=erosion_data
        )
        
        return analysis
        
    def _calculate_final_risk_level(self) -> str:
        """Calculate final risk level for conversation."""
        # Consider multiple factors
        score = self.cumulative_risk_score
        
        # Boost score if attack chains detected
        if self.detected_chains:
            score *= 1.5
            
        # Boost score if escalation detected
        if self.escalation_detected:
            score *= 1.3
            
        # Boost score if significant erosion detected
        if self.erosion_analysis and self.erosion_analysis.erosion_score > 50:
            score *= 1.4
            
        # Map to risk level
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        else:
            return "SAFE"
            
    def export_session(self, filepath: str, format: str = 'json') -> bool:
        """
        Export the current session to a file.
        
        Args:
            filepath: Path to save the session
            format: Export format ('json', 'csv', 'txt')
            
        Returns:
            True if successful, False otherwise
        """
        return export_conversation(self, filepath, format)
    
    def to_history(self) -> ConversationHistory:
        """
        Convert session to ConversationHistory for replay analysis.
        
        Returns:
            ConversationHistory object
        """
        return ConversationHistory(
            conversation_id=self.session_id,
            turns=self.turns,
            start_time=self.created_at.isoformat() if self.created_at else None,
            end_time=self.last_activity.isoformat() if self.last_activity else None,
            metadata={
                'cumulative_risk_score': self.cumulative_risk_score,
                'escalation_detected': self.escalation_detected,
                'detected_chains': len(self.detected_chains),
                'is_active': self.is_active
            }
        )
            
    def end_session(self):
        """End the conversation session."""
        self.is_active = False
        self.last_activity = datetime.now()
        
    def get_erosion_timeline(self) -> Optional[str]:
        """Get erosion timeline visualization."""
        if self.erosion_detector:
            return self.erosion_detector.generate_timeline_visualization()
        return None
        
    def get_boundary_heatmap(self) -> Optional[str]:
        """Get boundary violation heatmap."""
        if self.erosion_detector:
            return self.erosion_detector.generate_boundary_heatmap()
        return None


class ConversationManager:
    """Manages multiple conversation sessions."""
    
    def __init__(self):
        """Initialize conversation manager."""
        self.sessions: Dict[str, ConversationSession] = {}
        self.cleanup_interval = 300  # Cleanup every 5 minutes
        self.last_cleanup = time.time()
        
    def create_session(
        self,
        session_id: Optional[str] = None,
        timeout_minutes: int = 30,
        max_turns: int = 100
    ) -> ConversationSession:
        """
        Create a new conversation session.
        
        Args:
            session_id: Optional session ID
            timeout_minutes: Session timeout in minutes
            max_turns: Maximum turns allowed
            
        Returns:
            New ConversationSession instance
        """
        session = ConversationSession(
            session_id=session_id,
            timeout_minutes=timeout_minutes,
            max_turns=max_turns
        )
        
        self.sessions[session.session_id] = session
        
        # Periodic cleanup
        self._cleanup_inactive_sessions()
        
        return session
        
    def get_session(self, session_id: str) -> Optional[ConversationSession]:
        """
        Get an existing session by ID.
        
        Args:
            session_id: Session ID to retrieve
            
        Returns:
            ConversationSession if found and active, None otherwise
        """
        session = self.sessions.get(session_id)
        
        if session and session._is_timed_out():
            session.is_active = False
            
        return session if session and session.is_active else None
        
    def end_session(self, session_id: str) -> bool:
        """
        End a conversation session.
        
        Args:
            session_id: Session ID to end
            
        Returns:
            True if session was ended, False if not found
        """
        session = self.sessions.get(session_id)
        if session:
            session.end_session()
            return True
        return False
        
    def _cleanup_inactive_sessions(self):
        """Remove inactive sessions from memory."""
        current_time = time.time()
        
        # Only cleanup periodically
        if current_time - self.last_cleanup < self.cleanup_interval:
            return
            
        # Remove inactive sessions
        inactive_ids = [
            sid for sid, session in self.sessions.items()
            if not session.is_active or session._is_timed_out()
        ]
        
        for sid in inactive_ids:
            del self.sessions[sid]
            
        self.last_cleanup = current_time
        
    def get_active_sessions(self) -> List[ConversationSession]:
        """Get list of all active sessions."""
        return [
            session for session in self.sessions.values()
            if session.is_active and not session._is_timed_out()
        ]
        
    def get_session_count(self) -> Tuple[int, int]:
        """
        Get count of active and total sessions.
        
        Returns:
            Tuple of (active_count, total_count)
        """
        active = len(self.get_active_sessions())
        total = len(self.sessions)
        return active, total
    
    def export_all_sessions(self, directory: str, format: str = 'json') -> Dict[str, bool]:
        """
        Export all sessions to a directory.
        
        Args:
            directory: Directory to save sessions
            format: Export format ('json', 'csv', 'txt')
            
        Returns:
            Dictionary mapping session IDs to export success status
        """
        import os
        os.makedirs(directory, exist_ok=True)
        
        results = {}
        for session_id, session in self.sessions.items():
            filepath = os.path.join(directory, f"session_{session_id}.{format}")
            results[session_id] = session.export_session(filepath, format)
        
        return results


class ConversationAnalyzer:
    """Analyzes conversations for multi-turn attack patterns and threat evolution."""
    
    def __init__(self, verbose: bool = False):
        """
        Initialize the conversation analyzer.
        
        Args:
            verbose: Enable detailed output during analysis
        """
        self.verbose = verbose
        self.sessions: Dict[str, ConversationSession] = {}
        
    def load_conversation(self, filepath: str, format: str = 'auto') -> Optional[ConversationSession]:
        """
        Load a conversation from file and create a session for analysis.
        
        Args:
            filepath: Path to the conversation file
            format: Import format ('json', 'csv', 'txt', 'auto' for auto-detect)
            
        Returns:
            ConversationSession if successful, None otherwise
        """
        history = import_conversation(filepath, format)
        if not history:
            return None
            
        # Create a new session from the history
        session = ConversationSession(
            session_id=history.conversation_id or str(uuid.uuid4())
        )
        
        # Populate session with turns from history
        for turn in history.turns:
            # Add turn data to session
            session.turns.append(turn)
            
            # Update session state
            if hasattr(turn, 'risk_score'):
                session.cumulative_risk_score = max(
                    session.cumulative_risk_score,
                    turn.risk_score
                )
        
        # Store session
        self.sessions[session.session_id] = session
        
        return session
    
    def analyze_loaded_conversation(self, session_id: str) -> Optional[ConversationAnalysis]:
        """
        Analyze a loaded conversation session.
        
        Args:
            session_id: ID of the session to analyze
            
        Returns:
            ConversationAnalysis if successful, None otherwise
        """
        session = self.sessions.get(session_id)
        if not session:
            return None
            
        return session.analyze_conversation()