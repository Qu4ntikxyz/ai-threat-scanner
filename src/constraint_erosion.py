"""
Constraint Erosion Detection Module

Detects gradual constraint erosion attacks where attackers slowly push boundaries
over multiple conversation turns to bypass safety mechanisms.
"""

import re
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime
from collections import deque

from .models import (
    ConstraintViolation,
    ErosionPattern,
    SafetyBoundary,
    ErosionAnalysis,
    RISK_SAFE, RISK_LOW, RISK_MEDIUM, RISK_HIGH, RISK_CRITICAL
)


class ConstraintErosionDetector:
    """Analyzes conversation patterns for gradual constraint erosion attacks."""
    
    # Erosion pattern definitions
    EROSION_PATTERNS = {
        "incremental_boundary_pushing": {
            "description": "Small increases in inappropriate content over time",
            "indicators": [
                "slightly more", "just a bit", "little more", "push further",
                "go deeper", "expand on", "more detail", "continue with"
            ],
            "severity_multiplier": 1.2,
            "velocity_weight": 1.5
        },
        "topic_drift": {
            "description": "Gradual shift from safe to unsafe topics",
            "indicators": [
                "speaking of", "that reminds me", "related to that",
                "on a similar note", "while we're discussing", "by the way"
            ],
            "severity_multiplier": 1.1,
            "velocity_weight": 1.3
        },
        "authority_escalation": {
            "description": "Progressive claims of higher authority/permissions",
            "indicators": [
                "actually I'm", "I should mention", "I have clearance",
                "authorized to", "permission from", "approved by",
                "my role allows", "special access"
            ],
            "severity_multiplier": 1.4,
            "velocity_weight": 1.6
        },
        "emotional_manipulation": {
            "description": "Building emotional connection before exploitation",
            "indicators": [
                "trust me", "between us", "I understand you",
                "we've built", "our conversation", "you can tell me",
                "I care about", "help me understand"
            ],
            "severity_multiplier": 1.3,
            "velocity_weight": 1.4
        },
        "normalization": {
            "description": "Making inappropriate requests seem normal over time",
            "indicators": [
                "it's normal", "everyone does", "common practice",
                "standard procedure", "typically", "usually",
                "it's okay to", "nothing wrong with"
            ],
            "severity_multiplier": 1.25,
            "velocity_weight": 1.35
        },
        "desensitization": {
            "description": "Repeated exposure to reduce resistance",
            "indicators": [
                "as we discussed", "like before", "similar to earlier",
                "remember when", "going back to", "as mentioned",
                "previously we", "earlier you"
            ],
            "severity_multiplier": 1.15,
            "velocity_weight": 1.25
        },
        "false_consensus": {
            "description": "Creating illusion that violations are acceptable",
            "indicators": [
                "others have", "many people", "it's accepted",
                "widely known", "commonly understood", "general consensus",
                "most would agree", "it's acknowledged"
            ],
            "severity_multiplier": 1.2,
            "velocity_weight": 1.3
        },
        "reciprocity_exploitation": {
            "description": "Using give-and-take to justify violations",
            "indicators": [
                "since I helped", "I've been", "fair exchange",
                "in return", "quid pro quo", "you owe",
                "reciprocate", "mutual benefit"
            ],
            "severity_multiplier": 1.35,
            "velocity_weight": 1.45
        }
    }
    
    # Severity levels for violations
    SEVERITY_LEVELS = {
        "minor": 1.0,
        "moderate": 2.5,
        "severe": 5.0
    }
    
    def __init__(self, window_size: int = 10, decay_factor: float = 0.85):
        """
        Initialize the constraint erosion detector.
        
        Args:
            window_size: Number of turns to consider for sliding window analysis
            decay_factor: Exponential decay factor for older violations (0-1)
        """
        self.window_size = window_size
        self.decay_factor = decay_factor
        
        # Tracking state
        self.violations: List[ConstraintViolation] = []
        self.boundaries: Dict[str, SafetyBoundary] = self._initialize_boundaries()
        self.erosion_timeline: List[Tuple[int, float]] = []  # (turn_number, erosion_score)
        self.detected_patterns: List[ErosionPattern] = []
        
        # Metrics
        self.erosion_score: float = 0.0
        self.erosion_velocity: float = 0.0
        self.boundary_integrity: float = 100.0
        self.manipulation_index: float = 0.0
        self.persistence_factor: float = 0.0
        
        # Analysis window
        self.recent_violations = deque(maxlen=window_size)
        self.turn_count = 0
        
    def _initialize_boundaries(self) -> Dict[str, SafetyBoundary]:
        """Initialize safety boundaries to track."""
        boundaries = {
            "content_appropriateness": SafetyBoundary(
                name="content_appropriateness",
                initial_threshold=1.0,
                current_threshold=1.0,
                violation_count=0,
                description="Appropriate content boundaries"
            ),
            "authority_claims": SafetyBoundary(
                name="authority_claims",
                initial_threshold=1.0,
                current_threshold=1.0,
                violation_count=0,
                description="Authority and permission boundaries"
            ),
            "information_disclosure": SafetyBoundary(
                name="information_disclosure",
                initial_threshold=1.0,
                current_threshold=1.0,
                violation_count=0,
                description="Information disclosure boundaries"
            ),
            "manipulation_resistance": SafetyBoundary(
                name="manipulation_resistance",
                initial_threshold=1.0,
                current_threshold=1.0,
                violation_count=0,
                description="Resistance to manipulation tactics"
            ),
            "topic_consistency": SafetyBoundary(
                name="topic_consistency",
                initial_threshold=1.0,
                current_threshold=1.0,
                violation_count=0,
                description="Maintaining appropriate topic boundaries"
            )
        }
        return boundaries
        
    def analyze_turn(
        self,
        prompt: str,
        turn_number: int,
        threat_score: float = 0.0,
        context: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Analyze a single conversation turn for constraint erosion.
        
        Args:
            prompt: The user prompt to analyze
            turn_number: Current turn number in conversation
            threat_score: Base threat score from standard analysis
            context: Optional conversation context
            
        Returns:
            Dictionary containing erosion analysis for this turn
        """
        self.turn_count = turn_number
        turn_violations = []
        
        # Detect erosion patterns
        for pattern_name, pattern_config in self.EROSION_PATTERNS.items():
            if self._detect_pattern(prompt, pattern_config):
                # Determine severity based on pattern and context
                severity = self._calculate_violation_severity(
                    pattern_name, threat_score, turn_number
                )
                
                # Create violation record
                violation = ConstraintViolation(
                    turn_number=turn_number,
                    timestamp=datetime.now(),
                    pattern_type=pattern_name,
                    severity=severity,
                    description=pattern_config["description"],
                    boundary_affected=self._get_affected_boundary(pattern_name),
                    confidence=self._calculate_pattern_confidence(prompt, pattern_config)
                )
                
                turn_violations.append(violation)
                self.violations.append(violation)
                self.recent_violations.append(violation)
                
                # Update boundary state
                self._update_boundary(violation)
                
        # Calculate metrics for this turn
        turn_erosion_score = self._calculate_turn_erosion_score(turn_violations)
        self.erosion_timeline.append((turn_number, turn_erosion_score))
        
        # Update cumulative metrics
        self._update_metrics()
        
        # Detect acceleration patterns
        acceleration = self._detect_acceleration()
        
        return {
            "turn_number": turn_number,
            "violations": turn_violations,
            "turn_erosion_score": turn_erosion_score,
            "cumulative_erosion_score": self.erosion_score,
            "erosion_velocity": self.erosion_velocity,
            "acceleration_detected": acceleration,
            "critical_point": self._is_critical_point(turn_erosion_score)
        }
        
    def _detect_pattern(self, prompt: str, pattern_config: Dict) -> bool:
        """Check if prompt contains erosion pattern indicators."""
        prompt_lower = prompt.lower()
        indicators = pattern_config.get("indicators", [])
        
        # Check for any indicator presence
        for indicator in indicators:
            if indicator in prompt_lower:
                return True
                
        return False
        
    def _calculate_violation_severity(
        self,
        pattern_name: str,
        threat_score: float,
        turn_number: int
    ) -> str:
        """Calculate severity level of a constraint violation."""
        # Base severity from threat score
        if threat_score >= 60:
            base_severity = "severe"
        elif threat_score >= 30:
            base_severity = "moderate"
        else:
            base_severity = "minor"
            
        # Adjust based on pattern type
        pattern_config = self.EROSION_PATTERNS.get(pattern_name, {})
        multiplier = pattern_config.get("severity_multiplier", 1.0)
        
        # Escalate severity if pattern appears later in conversation
        if turn_number > 5 and multiplier > 1.2:
            if base_severity == "minor":
                base_severity = "moderate"
            elif base_severity == "moderate":
                base_severity = "severe"
                
        return base_severity
        
    def _get_affected_boundary(self, pattern_name: str) -> str:
        """Determine which safety boundary is affected by pattern."""
        boundary_mapping = {
            "incremental_boundary_pushing": "content_appropriateness",
            "topic_drift": "topic_consistency",
            "authority_escalation": "authority_claims",
            "emotional_manipulation": "manipulation_resistance",
            "normalization": "content_appropriateness",
            "desensitization": "manipulation_resistance",
            "false_consensus": "manipulation_resistance",
            "reciprocity_exploitation": "manipulation_resistance"
        }
        return boundary_mapping.get(pattern_name, "content_appropriateness")
        
    def _calculate_pattern_confidence(self, prompt: str, pattern_config: Dict) -> float:
        """Calculate confidence score for pattern detection."""
        prompt_lower = prompt.lower()
        indicators = pattern_config.get("indicators", [])
        
        if not indicators:
            return 0.5
            
        # Count matching indicators
        matches = sum(1 for indicator in indicators if indicator in prompt_lower)
        
        # Base confidence from match ratio
        confidence = matches / len(indicators)
        
        # Boost confidence if multiple indicators present
        if matches > 1:
            confidence = min(confidence * 1.2, 1.0)
            
        return confidence
        
    def _update_boundary(self, violation: ConstraintViolation):
        """Update safety boundary state based on violation."""
        boundary_name = violation.boundary_affected
        if boundary_name in self.boundaries:
            boundary = self.boundaries[boundary_name]
            boundary.violation_count += 1
            
            # Degrade threshold based on violation severity
            severity_impact = self.SEVERITY_LEVELS.get(violation.severity, 1.0)
            degradation = severity_impact * 0.05  # 5% degradation per severity unit
            
            boundary.current_threshold = max(
                0.0,
                boundary.current_threshold - degradation
            )
            
            # Track erosion history
            if not hasattr(boundary, 'erosion_history'):
                boundary.erosion_history = []
            boundary.erosion_history.append({
                'turn': violation.turn_number,
                'threshold': boundary.current_threshold
            })
            
    def _calculate_turn_erosion_score(self, violations: List[ConstraintViolation]) -> float:
        """Calculate erosion score for a single turn."""
        if not violations:
            return 0.0
            
        score = 0.0
        for violation in violations:
            severity_value = self.SEVERITY_LEVELS.get(violation.severity, 1.0)
            pattern_config = self.EROSION_PATTERNS.get(violation.pattern_type, {})
            multiplier = pattern_config.get("severity_multiplier", 1.0)
            
            # Calculate violation impact
            impact = severity_value * multiplier * violation.confidence
            score += impact
            
        # Normalize to 0-100 scale
        return min(score * 10, 100.0)
        
    def _update_metrics(self):
        """Update cumulative erosion metrics."""
        # Calculate cumulative erosion score with decay
        cumulative_score = 0.0
        for i, violation in enumerate(reversed(self.violations)):
            age = len(self.violations) - i - 1
            decay = self.decay_factor ** age
            severity_value = self.SEVERITY_LEVELS.get(violation.severity, 1.0)
            cumulative_score += severity_value * decay
            
        self.erosion_score = min(cumulative_score * 5, 100.0)  # Scale to 0-100
        
        # Calculate erosion velocity (rate of change)
        if len(self.erosion_timeline) >= 2:
            recent_scores = [score for _, score in self.erosion_timeline[-5:]]
            if len(recent_scores) >= 2:
                self.erosion_velocity = recent_scores[-1] - recent_scores[-2]
            else:
                self.erosion_velocity = 0.0
        
        # Calculate boundary integrity
        total_integrity = 0.0
        for boundary in self.boundaries.values():
            total_integrity += boundary.current_threshold
        self.boundary_integrity = (total_integrity / len(self.boundaries)) * 100
        
        # Calculate manipulation index
        manipulation_patterns = [
            "emotional_manipulation", "normalization",
            "desensitization", "false_consensus", "reciprocity_exploitation"
        ]
        manipulation_violations = [
            v for v in self.violations
            if v.pattern_type in manipulation_patterns
        ]
        if self.violations:
            self.manipulation_index = (len(manipulation_violations) / len(self.violations)) * 100
        
        # Calculate persistence factor
        if self.turn_count > 0:
            violation_turns = set(v.turn_number for v in self.violations)
            self.persistence_factor = (len(violation_turns) / self.turn_count) * 100
            
    def _detect_acceleration(self) -> bool:
        """Detect if erosion is accelerating."""
        if len(self.erosion_timeline) < 3:
            return False
            
        recent_scores = [score for _, score in self.erosion_timeline[-3:]]
        
        # Check for consistent increase
        increasing = all(
            recent_scores[i] < recent_scores[i+1]
            for i in range(len(recent_scores)-1)
        )
        
        # Check for significant acceleration
        if len(recent_scores) == 3:
            acceleration = (recent_scores[2] - recent_scores[1]) > (recent_scores[1] - recent_scores[0])
            return increasing and acceleration
            
        return increasing
        
    def _is_critical_point(self, turn_score: float) -> bool:
        """Determine if current turn represents a critical erosion point."""
        # Critical if high score
        if turn_score >= 50:
            return True
            
        # Critical if sudden spike
        if len(self.erosion_timeline) >= 2:
            prev_score = self.erosion_timeline[-2][1] if len(self.erosion_timeline) >= 2 else 0
            if turn_score > prev_score * 2 and turn_score > 20:
                return True
                
        # Critical if multiple boundaries severely degraded
        severely_degraded = sum(
            1 for b in self.boundaries.values()
            if b.current_threshold < 0.5
        )
        if severely_degraded >= 2:
            return True
            
        return False
        
    def get_erosion_analysis(self) -> ErosionAnalysis:
        """
        Get comprehensive erosion analysis for the conversation.
        
        Returns:
            ErosionAnalysis object with complete metrics and patterns
        """
        # Identify detected erosion patterns
        pattern_summary = {}
        for violation in self.violations:
            if violation.pattern_type not in pattern_summary:
                pattern_summary[violation.pattern_type] = {
                    "count": 0,
                    "first_turn": violation.turn_number,
                    "last_turn": violation.turn_number,
                    "severity_distribution": {"minor": 0, "moderate": 0, "severe": 0}
                }
            
            summary = pattern_summary[violation.pattern_type]
            summary["count"] += 1
            summary["last_turn"] = violation.turn_number
            summary["severity_distribution"][violation.severity] += 1
            
        # Create erosion pattern objects
        detected_patterns = []
        for pattern_type, summary in pattern_summary.items():
            pattern_config = self.EROSION_PATTERNS.get(pattern_type, {})
            
            pattern = ErosionPattern(
                pattern_type=pattern_type,
                description=pattern_config.get("description", ""),
                occurrence_count=summary["count"],
                first_occurrence=summary["first_turn"],
                last_occurrence=summary["last_turn"],
                severity_trend="escalating" if self._detect_acceleration() else "stable",
                confidence=sum(v.confidence for v in self.violations if v.pattern_type == pattern_type) / summary["count"]
            )
            detected_patterns.append(pattern)
            
        # Identify critical points
        critical_points = [
            turn for turn, score in self.erosion_timeline
            if self._is_critical_point(score)
        ]
        
        # Create analysis object
        analysis = ErosionAnalysis(
            erosion_score=self.erosion_score,
            erosion_velocity=self.erosion_velocity,
            boundary_integrity=self.boundary_integrity,
            manipulation_index=self.manipulation_index,
            persistence_factor=self.persistence_factor,
            detected_patterns=detected_patterns,
            violations=self.violations,
            boundaries=list(self.boundaries.values()),
            timeline=self.erosion_timeline,
            critical_points=critical_points,
            risk_level=self._calculate_risk_level()
        )
        
        return analysis
        
    def _calculate_risk_level(self) -> str:
        """Calculate overall risk level based on erosion metrics."""
        # Weighted scoring
        score = (
            self.erosion_score * 0.4 +
            abs(self.erosion_velocity) * 0.2 +
            (100 - self.boundary_integrity) * 0.2 +
            self.manipulation_index * 0.1 +
            self.persistence_factor * 0.1
        )
        
        # Map to risk levels
        if score >= 80:
            return RISK_CRITICAL
        elif score >= 60:
            return RISK_HIGH
        elif score >= 40:
            return RISK_MEDIUM
        elif score >= 20:
            return RISK_LOW
        else:
            return RISK_SAFE
            
    def generate_timeline_visualization(self) -> str:
        """Generate a text-based visualization of erosion timeline."""
        if not self.erosion_timeline:
            return "No erosion data available"
            
        lines = ["Erosion Timeline:", "=" * 50]
        
        # Find max score for scaling
        max_score = max(score for _, score in self.erosion_timeline) if self.erosion_timeline else 1
        
        for turn, score in self.erosion_timeline:
            # Create bar visualization
            bar_length = int((score / max_score) * 40) if max_score > 0 else 0
            bar = "█" * bar_length
            
            # Add markers for critical points
            marker = " ⚠️" if self._is_critical_point(score) else ""
            
            lines.append(f"Turn {turn:3d}: {bar:<40} {score:5.1f}{marker}")
            
        # Add summary
        lines.append("=" * 50)
        lines.append(f"Current Erosion Score: {self.erosion_score:.1f}")
        lines.append(f"Erosion Velocity: {self.erosion_velocity:+.1f}")
        lines.append(f"Boundary Integrity: {self.boundary_integrity:.1f}%")
        
        return "\n".join(lines)
        
    def generate_boundary_heatmap(self) -> str:
        """Generate a heatmap visualization of boundary violations."""
        lines = ["Boundary Violation Heatmap:", "=" * 50]
        
        for name, boundary in self.boundaries.items():
            # Calculate heat level
            integrity = boundary.current_threshold
            if integrity >= 0.8:
                heat = "🟢"  # Green - intact
            elif integrity >= 0.6:
                heat = "🟡"  # Yellow - minor erosion
            elif integrity >= 0.4:
                heat = "🟠"  # Orange - moderate erosion
            else:
                heat = "🔴"  # Red - severe erosion
                
            # Create integrity bar
            bar_length = int(integrity * 20)
            bar = "█" * bar_length + "░" * (20 - bar_length)
            
            lines.append(
                f"{heat} {name:<25} {bar} "
                f"({integrity*100:.0f}% | {boundary.violation_count} violations)"
            )
            
        return "\n".join(lines)
        
    def reset(self):
        """Reset the detector state for a new conversation."""
        self.violations.clear()
        self.boundaries = self._initialize_boundaries()
        self.erosion_timeline.clear()
        self.detected_patterns.clear()
        self.recent_violations.clear()
        
        self.erosion_score = 0.0
        self.erosion_velocity = 0.0
        self.boundary_integrity = 100.0
        self.manipulation_index = 0.0
        self.persistence_factor = 0.0
        self.turn_count = 0