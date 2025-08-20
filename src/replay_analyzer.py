"""
Conversation Replay Analysis Module

Provides comprehensive retrospective analysis of conversation histories to identify
multi-step attack patterns, analyze attack evolution, and generate detailed threat reports.
"""

import json
import csv
import re
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict, Counter
import statistics

from .models import (
    ConversationHistory, ReplayAnalysis, AttackTimeline, ThreatActor,
    ConversationTurn, ThreatResult
)
from .scanner import AIThreatScanner
from .conversation import ConversationAnalyzer
from .attack_chains import get_attack_chain_patterns
from .constraint_erosion import ConstraintErosionDetector


class ConversationReplayAnalyzer:
    """
    Analyzes complete conversation histories retrospectively to identify
    multi-step attack patterns and generate comprehensive threat reports.
    """
    
    def __init__(self, verbose: bool = False):
        """
        Initialize the replay analyzer.
        
        Args:
            verbose: Enable detailed output during analysis
        """
        self.verbose = verbose
        self.scanner = AIThreatScanner(verbose=verbose, smart_matching=True)
        self.conversation_analyzer = ConversationAnalyzer(verbose=verbose)
        self.erosion_detector = ConstraintErosionDetector()
        
        # Cache for performance optimization
        self._analysis_cache: Dict[str, ReplayAnalysis] = {}
        
    def analyze_conversation(
        self,
        conversation: ConversationHistory,
        use_cache: bool = True
    ) -> ReplayAnalysis:
        """
        Perform comprehensive retrospective analysis on a conversation.
        
        Args:
            conversation: The conversation history to analyze
            use_cache: Whether to use cached results if available
            
        Returns:
            ReplayAnalysis object with complete analysis results
        """
        # Check cache
        conv_id = conversation.conversation_id or str(hash(str(conversation)))
        if use_cache and conv_id in self._analysis_cache:
            return self._analysis_cache[conv_id]
        
        # Perform analysis
        analysis = ReplayAnalysis(
            conversation_id=conv_id,
            total_turns=len(conversation.turns),
            start_time=conversation.start_time,
            end_time=conversation.end_time,
            duration_seconds=self._calculate_duration(conversation),
            detected_attacks=[],
            attack_timeline=AttackTimeline(events=[]),
            threat_actors=[],
            success_rate=0.0,
            anomaly_score=0.0,
            evolution_patterns=[],
            correlations={},
            risk_assessment={},
            metadata=conversation.metadata or {}
        )
        
        # Run various analysis components
        self._detect_attack_patterns(conversation, analysis)
        self._analyze_anomalies(conversation, analysis)
        self._calculate_success_rate(conversation, analysis)
        self._track_evolution(conversation, analysis)
        self._perform_correlation_analysis(conversation, analysis)
        self._profile_threat_actors(conversation, analysis)
        self._build_attack_timeline(conversation, analysis)
        self._assess_overall_risk(conversation, analysis)
        
        # Cache the result
        if use_cache:
            self._analysis_cache[conv_id] = analysis
            
        return analysis
    
    def load_conversation_json(self, filepath: str) -> ConversationHistory:
        """
        Load a conversation from JSON format.
        
        Args:
            filepath: Path to the JSON file
            
        Returns:
            ConversationHistory object
        """
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            turns = []
            for turn_data in data.get('turns', []):
                turn = ConversationTurn(
                    turn_number=turn_data.get('turn_number', 0),
                    role=turn_data.get('role', 'user'),
                    content=turn_data.get('content', ''),
                    timestamp=turn_data.get('timestamp'),
                    metadata=turn_data.get('metadata', {})
                )
                turns.append(turn)
            
            return ConversationHistory(
                conversation_id=data.get('conversation_id'),
                turns=turns,
                start_time=data.get('start_time'),
                end_time=data.get('end_time'),
                metadata=data.get('metadata', {})
            )
        except Exception as e:
            if self.verbose:
                print(f"Error loading JSON conversation: {e}")
            # Return empty conversation on error
            return ConversationHistory(turns=[])
    
    def load_conversation_text(self, filepath: str) -> ConversationHistory:
        """
        Load a conversation from plain text format with timestamps.
        
        Expected format:
        [2024-01-01 10:00:00] User: Message content
        [2024-01-01 10:00:05] Assistant: Response content
        
        Args:
            filepath: Path to the text file
            
        Returns:
            ConversationHistory object
        """
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            turns = []
            turn_number = 0
            
            # Pattern to match timestamp and role
            pattern = r'\[([^\]]+)\]\s*(User|Assistant|System):\s*(.*)'
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                    
                match = re.match(pattern, line)
                if match:
                    timestamp_str, role, content = match.groups()
                    turn_number += 1
                    
                    turn = ConversationTurn(
                        turn_number=turn_number,
                        role=role.lower(),
                        content=content,
                        timestamp=timestamp_str,
                        metadata={}
                    )
                    turns.append(turn)
            
            # Determine start and end times
            start_time = turns[0].timestamp if turns else None
            end_time = turns[-1].timestamp if turns else None
            
            return ConversationHistory(
                turns=turns,
                start_time=start_time,
                end_time=end_time
            )
        except Exception as e:
            if self.verbose:
                print(f"Error loading text conversation: {e}")
            return ConversationHistory(turns=[])
    
    def load_conversation_csv(self, filepath: str) -> ConversationHistory:
        """
        Load a conversation from CSV format.
        
        Expected columns: turn_number, timestamp, role, content
        
        Args:
            filepath: Path to the CSV file
            
        Returns:
            ConversationHistory object
        """
        try:
            turns = []
            
            with open(filepath, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    turn = ConversationTurn(
                        turn_number=int(row.get('turn_number', 0)),
                        role=row.get('role', 'user').lower(),
                        content=row.get('content', ''),
                        timestamp=row.get('timestamp'),
                        metadata={}
                    )
                    turns.append(turn)
            
            # Sort by turn number
            turns.sort(key=lambda x: x.turn_number)
            
            # Determine start and end times
            start_time = turns[0].timestamp if turns else None
            end_time = turns[-1].timestamp if turns else None
            
            return ConversationHistory(
                turns=turns,
                start_time=start_time,
                end_time=end_time
            )
        except Exception as e:
            if self.verbose:
                print(f"Error loading CSV conversation: {e}")
            return ConversationHistory(turns=[])
    
    def batch_analyze(
        self,
        conversations: List[ConversationHistory],
        compare: bool = True
    ) -> Dict[str, Any]:
        """
        Analyze multiple conversations and optionally compare them.
        
        Args:
            conversations: List of conversations to analyze
            compare: Whether to perform comparative analysis
            
        Returns:
            Dictionary with individual and comparative analysis results
        """
        results = {
            'individual_analyses': [],
            'comparative_analysis': None,
            'statistics': {}
        }
        
        # Analyze each conversation
        for conv in conversations:
            analysis = self.analyze_conversation(conv)
            results['individual_analyses'].append(analysis)
        
        # Perform comparative analysis if requested
        if compare and len(conversations) > 1:
            results['comparative_analysis'] = self._compare_conversations(
                results['individual_analyses']
            )
        
        # Calculate statistics
        results['statistics'] = self._calculate_batch_statistics(
            results['individual_analyses']
        )
        
        return results
    
    def _detect_attack_patterns(
        self,
        conversation: ConversationHistory,
        analysis: ReplayAnalysis
    ) -> None:
        """Detect known attack patterns in the conversation."""
        # Analyze each turn for threats
        for turn in conversation.turns:
            if turn.role == 'user':
                # Basic threat scanning
                threat_result = self.scanner.scan_prompt(
                    turn.content,
                    context=self._get_context_window(conversation, turn.turn_number)
                )
                
                if threat_result['risk_score'] > 0:
                    analysis.detected_attacks.append({
                        'turn': turn.turn_number,
                        'type': threat_result['risk_level'],
                        'score': threat_result['risk_score'],
                        'threats': threat_result['threats'],
                        'timestamp': turn.timestamp
                    })
        
        # Detect attack chains using patterns
        chain_patterns = get_attack_chain_patterns()
        for pattern_name, pattern_config in chain_patterns.items():
            # Simple detection based on keywords
            detected = False
            for turn in conversation.turns:
                if turn.role == 'user':
                    content_lower = turn.content.lower()
                    for stage in pattern_config.get('stages', []):
                        if any(keyword in content_lower for keyword in stage.get('keywords', [])):
                            detected = True
                            break
                if detected:
                    break
            
            if detected:
                analysis.detected_attacks.append({
                    'type': 'attack_chain',
                    'chain_type': pattern_name,
                    'description': pattern_config.get('description', ''),
                    'confidence': 0.7
                })
        
        # Detect constraint erosion by analyzing each turn
        for turn in conversation.turns:
            if turn.role == 'user':
                erosion_turn_result = self.erosion_detector.analyze_turn(
                    prompt=turn.content,
                    turn_number=turn.turn_number,
                    threat_score=turn.risk_score if hasattr(turn, 'risk_score') else 0.0
                )
                
                if erosion_turn_result.get('turn_erosion_score', 0) > 20:
                    analysis.detected_attacks.append({
                        'type': 'constraint_erosion',
                        'turn': turn.turn_number,
                        'score': erosion_turn_result.get('turn_erosion_score', 0),
                        'violations': len(erosion_turn_result.get('violations', []))
                    })
        
        # Get final erosion analysis
        erosion_analysis = self.erosion_detector.get_erosion_analysis()
        if erosion_analysis.erosion_score > 30:
            analysis.metadata['erosion_detected'] = True
            analysis.metadata['erosion_score'] = erosion_analysis.erosion_score
    
    def _analyze_anomalies(
        self,
        conversation: ConversationHistory,
        analysis: ReplayAnalysis
    ) -> None:
        """Find unusual conversation patterns."""
        anomaly_indicators = []
        
        # Check for unusual message lengths
        user_lengths = [len(t.content) for t in conversation.turns if t.role == 'user']
        if user_lengths:
            avg_length = statistics.mean(user_lengths)
            std_dev = statistics.stdev(user_lengths) if len(user_lengths) > 1 else 0
            
            for turn in conversation.turns:
                if turn.role == 'user':
                    length = len(turn.content)
                    if std_dev > 0 and abs(length - avg_length) > 2 * std_dev:
                        anomaly_indicators.append({
                            'type': 'unusual_length',
                            'turn': turn.turn_number,
                            'deviation': abs(length - avg_length) / std_dev
                        })
        
        # Check for rapid-fire messages (if timestamps available)
        if conversation.turns[0].timestamp:
            for i in range(1, len(conversation.turns)):
                if conversation.turns[i].role == 'user':
                    # Simple time difference check (would need proper parsing in production)
                    anomaly_indicators.append({
                        'type': 'timing_analysis',
                        'turn': conversation.turns[i].turn_number
                    })
        
        # Check for unusual character patterns
        for turn in conversation.turns:
            if turn.role == 'user':
                # Check for excessive special characters
                special_char_ratio = len(re.findall(r'[^a-zA-Z0-9\s]', turn.content)) / max(len(turn.content), 1)
                if special_char_ratio > 0.3:
                    anomaly_indicators.append({
                        'type': 'special_characters',
                        'turn': turn.turn_number,
                        'ratio': special_char_ratio
                    })
        
        # Calculate overall anomaly score
        if anomaly_indicators:
            analysis.anomaly_score = min(100, len(anomaly_indicators) * 10)
        else:
            analysis.anomaly_score = 0
        
        analysis.metadata['anomaly_indicators'] = anomaly_indicators
    
    def _calculate_success_rate(
        self,
        conversation: ConversationHistory,
        analysis: ReplayAnalysis
    ) -> None:
        """Determine which attacks succeeded based on assistant responses."""
        successful_attacks = 0
        total_attacks = len(analysis.detected_attacks)
        
        if total_attacks == 0:
            analysis.success_rate = 0.0
            return
        
        for attack in analysis.detected_attacks:
            # Check if the attack was followed by a compliant response
            if 'turn' in attack:
                turn_num = attack['turn']
                # Look for the assistant's response
                for turn in conversation.turns:
                    if turn.turn_number == turn_num + 1 and turn.role == 'assistant':
                        # Simple heuristic: check for refusal patterns
                        refusal_patterns = [
                            "i cannot", "i can't", "i won't", "i'm not able",
                            "against my guidelines", "not appropriate",
                            "refuse", "decline", "unable to assist"
                        ]
                        
                        response_lower = turn.content.lower()
                        refused = any(pattern in response_lower for pattern in refusal_patterns)
                        
                        if not refused:
                            successful_attacks += 1
                        break
        
        analysis.success_rate = (successful_attacks / total_attacks) * 100 if total_attacks > 0 else 0
    
    def _track_evolution(
        self,
        conversation: ConversationHistory,
        analysis: ReplayAnalysis
    ) -> None:
        """Track how attack techniques changed over time."""
        evolution_patterns = []
        
        # Group attacks by type over time
        attack_timeline = defaultdict(list)
        for attack in analysis.detected_attacks:
            if 'turn' in attack:
                attack_type = attack.get('type', 'unknown')
                attack_timeline[attack_type].append(attack['turn'])
        
        # Analyze progression
        for attack_type, turns in attack_timeline.items():
            if len(turns) > 1:
                # Check if attacks became more frequent
                turn_gaps = [turns[i+1] - turns[i] for i in range(len(turns)-1)]
                if turn_gaps:
                    avg_gap = statistics.mean(turn_gaps)
                    evolution_patterns.append({
                        'type': attack_type,
                        'pattern': 'increasing_frequency' if turn_gaps[-1] < avg_gap else 'stable',
                        'average_gap': avg_gap,
                        'occurrences': len(turns)
                    })
        
        # Check for technique switching
        if len(attack_timeline) > 1:
            technique_sequence = []
            for attack in sorted(analysis.detected_attacks, key=lambda x: x.get('turn', 0)):
                if 'type' in attack:
                    technique_sequence.append(attack['type'])
            
            if len(set(technique_sequence)) > 1:
                evolution_patterns.append({
                    'pattern': 'technique_switching',
                    'sequence': technique_sequence[:10]  # First 10 for brevity
                })
        
        analysis.evolution_patterns = evolution_patterns
    
    def _perform_correlation_analysis(
        self,
        conversation: ConversationHistory,
        analysis: ReplayAnalysis
    ) -> None:
        """Find relationships between different attacks."""
        correlations = {}
        
        # Analyze attack co-occurrence
        attack_types = [a.get('type') for a in analysis.detected_attacks if 'type' in a]
        if len(attack_types) > 1:
            type_pairs = []
            for i in range(len(attack_types) - 1):
                type_pairs.append((attack_types[i], attack_types[i+1]))
            
            pair_counts = Counter(type_pairs)
            # Convert tuple keys to strings for JSON serialization
            correlations['sequential_patterns'] = {
                f"{k[0]} -> {k[1]}": v
                for k, v in pair_counts.most_common(5)
            }
        
        # Analyze timing correlations
        if analysis.detected_attacks:
            attack_turns = [a.get('turn', 0) for a in analysis.detected_attacks if 'turn' in a]
            if len(attack_turns) > 2:
                # Check for regular intervals
                gaps = [attack_turns[i+1] - attack_turns[i] for i in range(len(attack_turns)-1)]
                if gaps:
                    avg_gap = statistics.mean(gaps)
                    std_gap = statistics.stdev(gaps) if len(gaps) > 1 else 0
                    
                    correlations['timing'] = {
                        'average_interval': avg_gap,
                        'consistency': 'regular' if std_gap < avg_gap * 0.3 else 'irregular'
                    }
        
        # Analyze success correlations
        success_by_type = defaultdict(lambda: {'total': 0, 'successful': 0})
        for attack in analysis.detected_attacks:
            attack_type = attack.get('type', 'unknown')
            success_by_type[attack_type]['total'] += 1
            # This would need actual success detection logic
            
        correlations['success_by_type'] = dict(success_by_type)
        
        analysis.correlations = correlations
    
    def _profile_threat_actors(
        self,
        conversation: ConversationHistory,
        analysis: ReplayAnalysis
    ) -> None:
        """Profile attacker behavior and characteristics."""
        # Create a threat actor profile
        actor = ThreatActor(
            actor_id=f"actor_{conversation.conversation_id or 'unknown'}",
            sophistication_level='low',
            preferred_techniques=[],
            success_rate=analysis.success_rate,
            persistence_score=0.0,
            behavioral_patterns={},
            first_seen=conversation.start_time,
            last_seen=conversation.end_time
        )
        
        # Determine sophistication level
        if any('attack_chain' in str(a.get('type', '')) for a in analysis.detected_attacks):
            actor.sophistication_level = 'high'
        elif any('constraint_erosion' in str(a.get('type', '')) for a in analysis.detected_attacks):
            actor.sophistication_level = 'medium'
        elif len(analysis.detected_attacks) > 5:
            actor.sophistication_level = 'medium'
        
        # Identify preferred techniques
        technique_counts = Counter(a.get('type') for a in analysis.detected_attacks if 'type' in a)
        actor.preferred_techniques = [t for t, _ in technique_counts.most_common(3)]
        
        # Calculate persistence score
        if conversation.turns:
            attack_turns = len([t for t in conversation.turns if t.role == 'user'])
            total_turns = len(conversation.turns)
            actor.persistence_score = (attack_turns / total_turns * 100) if total_turns > 0 else 0
        
        # Behavioral patterns
        actor.behavioral_patterns = {
            'attack_frequency': len(analysis.detected_attacks),
            'technique_diversity': len(set(a.get('type') for a in analysis.detected_attacks if 'type' in a)),
            'evolution_observed': len(analysis.evolution_patterns) > 0,
            'uses_advanced_techniques': actor.sophistication_level in ['medium', 'high']
        }
        
        analysis.threat_actors = [actor]
    
    def _build_attack_timeline(
        self,
        conversation: ConversationHistory,
        analysis: ReplayAnalysis
    ) -> None:
        """Build a chronological timeline of attack events."""
        events = []
        
        for attack in analysis.detected_attacks:
            event = {
                'turn': attack.get('turn', 0),
                'timestamp': None,
                'event_type': attack.get('type', 'unknown'),
                'description': '',
                'severity': 'low',
                'success': False
            }
            
            # Get timestamp from turn
            if 'turn' in attack:
                for turn in conversation.turns:
                    if turn.turn_number == attack['turn']:
                        event['timestamp'] = turn.timestamp
                        break
            
            # Determine severity
            if 'score' in attack:
                score = attack['score']
                if score >= 70:
                    event['severity'] = 'critical'
                elif score >= 50:
                    event['severity'] = 'high'
                elif score >= 30:
                    event['severity'] = 'medium'
            
            # Create description
            if attack.get('type') == 'attack_chain':
                event['description'] = f"Attack chain detected: {attack.get('chain_type', 'unknown')}"
            elif attack.get('type') == 'constraint_erosion':
                event['description'] = f"Constraint erosion detected (score: {attack.get('score', 0):.1f})"
            else:
                threats = attack.get('threats', [])
                if threats:
                    # Handle different threat formats
                    threat_names = []
                    for t in threats[:3]:
                        if isinstance(t, dict):
                            threat_names.append(t.get('category', t.get('type', 'unknown')))
                        else:
                            threat_names.append(str(t))
                    event['description'] = f"Threats detected: {', '.join(threat_names)}"
                else:
                    event['description'] = f"Attack detected: {attack.get('type', 'unknown')}"
            
            events.append(event)
        
        # Sort events by turn number
        events.sort(key=lambda x: x['turn'])
        
        analysis.attack_timeline.events = events
    
    def _assess_overall_risk(
        self,
        conversation: ConversationHistory,
        analysis: ReplayAnalysis
    ) -> None:
        """Assess the overall risk level of the conversation."""
        risk_factors = {
            'attack_density': 0,
            'sophistication': 0,
            'success_rate': analysis.success_rate,
            'persistence': 0,
            'anomaly_level': analysis.anomaly_score,
            'evolution_complexity': 0
        }
        
        # Calculate attack density
        if conversation.turns:
            risk_factors['attack_density'] = (len(analysis.detected_attacks) / len(conversation.turns)) * 100
        
        # Assess sophistication
        if analysis.threat_actors:
            actor = analysis.threat_actors[0]
            sophistication_scores = {'low': 20, 'medium': 50, 'high': 80}
            risk_factors['sophistication'] = sophistication_scores.get(actor.sophistication_level, 0)
        
        # Assess persistence
        if analysis.threat_actors:
            risk_factors['persistence'] = analysis.threat_actors[0].persistence_score
        
        # Assess evolution complexity
        risk_factors['evolution_complexity'] = len(analysis.evolution_patterns) * 20
        
        # Calculate overall risk score
        weights = {
            'attack_density': 0.2,
            'sophistication': 0.25,
            'success_rate': 0.25,
            'persistence': 0.15,
            'anomaly_level': 0.1,
            'evolution_complexity': 0.05
        }
        
        overall_score = sum(risk_factors[factor] * weight for factor, weight in weights.items())
        
        # Determine risk level
        if overall_score >= 70:
            risk_level = 'CRITICAL'
        elif overall_score >= 50:
            risk_level = 'HIGH'
        elif overall_score >= 30:
            risk_level = 'MEDIUM'
        elif overall_score >= 10:
            risk_level = 'LOW'
        else:
            risk_level = 'SAFE'
        
        analysis.risk_assessment = {
            'overall_score': overall_score,
            'risk_level': risk_level,
            'risk_factors': risk_factors,
            'recommendations': self._generate_recommendations(risk_level, analysis)
        }
    
    def _generate_recommendations(
        self,
        risk_level: str,
        analysis: ReplayAnalysis
    ) -> List[str]:
        """Generate security recommendations based on the analysis."""
        recommendations = []
        
        if risk_level in ['CRITICAL', 'HIGH']:
            recommendations.append("Immediate review of AI system security controls required")
            recommendations.append("Implement additional input validation and filtering")
            recommendations.append("Consider rate limiting for user interactions")
        
        if analysis.success_rate > 30:
            recommendations.append("Strengthen prompt injection defenses")
            recommendations.append("Review and update system prompts for better resilience")
        
        if analysis.anomaly_score > 50:
            recommendations.append("Investigate anomalous behavior patterns")
            recommendations.append("Consider implementing anomaly detection monitoring")
        
        if any(a.get('type') == 'attack_chain' for a in analysis.detected_attacks):
            recommendations.append("Implement multi-turn context tracking")
            recommendations.append("Add detection for sequential attack patterns")
        
        if any(a.get('type') == 'constraint_erosion' for a in analysis.detected_attacks):
            recommendations.append("Strengthen constraint enforcement mechanisms")
            recommendations.append("Implement gradual erosion detection")
        
        if not recommendations:
            recommendations.append("Continue monitoring for emerging threats")
            recommendations.append("Maintain current security posture")
        
        return recommendations
    
    def _get_context_window(
        self,
        conversation: ConversationHistory,
        current_turn: int,
        window_size: int = 3
    ) -> str:
        """Get context window around a specific turn."""
        context_parts = []
        
        for turn in conversation.turns:
            if current_turn - window_size <= turn.turn_number < current_turn:
                context_parts.append(f"{turn.role}: {turn.content[:200]}")
        
        return " | ".join(context_parts)
    
    def _calculate_duration(self, conversation: ConversationHistory) -> Optional[float]:
        """Calculate conversation duration in seconds."""
        if conversation.start_time and conversation.end_time:
            # This would need proper datetime parsing in production
            # For now, return a placeholder
            return len(conversation.turns) * 30  # Assume 30 seconds per turn
        return None
    
    def _compare_conversations(
        self,
        analyses: List[ReplayAnalysis]
    ) -> Dict[str, Any]:
        """Compare multiple conversation analyses."""
        comparison = {
            'total_conversations': len(analyses),
            'common_patterns': [],
            'trend_analysis': {},
            'aggregate_statistics': {}
        }
        
        # Find common attack patterns
        all_techniques = []
        for analysis in analyses:
            for actor in analysis.threat_actors:
                all_techniques.extend(actor.preferred_techniques)
        
        technique_counts = Counter(all_techniques)
        comparison['common_patterns'] = technique_counts.most_common(5)
        
        # Trend analysis
        comparison['trend_analysis'] = {
            'average_success_rate': statistics.mean([a.success_rate for a in analyses]),
            'average_anomaly_score': statistics.mean([a.anomaly_score for a in analyses]),
            'sophistication_trend': self._analyze_sophistication_trend(analyses)
        }
        
        # Aggregate statistics
        total_attacks = sum(len(a.detected_attacks) for a in analyses)
        total_turns = sum(a.total_turns for a in analyses)
        
        comparison['aggregate_statistics'] = {
            'total_attacks_detected': total_attacks,
            'total_turns_analyzed': total_turns,
            'attack_density': (total_attacks / total_turns * 100) if total_turns > 0 else 0,
            'high_risk_conversations': len([a for a in analyses if a.risk_assessment.get('risk_level') in ['HIGH', 'CRITICAL']])
        }
        
        return comparison
    
    def _analyze_sophistication_trend(self, analyses: List[ReplayAnalysis]) -> str:
        """Analyze the trend in attack sophistication."""
        sophistication_levels = []
        
        for analysis in analyses:
            for actor in analysis.threat_actors:
                level_map = {'low': 1, 'medium': 2, 'high': 3}
                sophistication_levels.append(level_map.get(actor.sophistication_level, 1))
        
        if len(sophistication_levels) > 1:
            # Simple trend detection
            first_half = sophistication_levels[:len(sophistication_levels)//2]
            second_half = sophistication_levels[len(sophistication_levels)//2:]
            
            if statistics.mean(second_half) > statistics.mean(first_half):
                return 'increasing'
            elif statistics.mean(second_half) < statistics.mean(first_half):
                return 'decreasing'
        
        return 'stable'
    
    def _calculate_batch_statistics(
        self,
        analyses: List[ReplayAnalysis]
    ) -> Dict[str, Any]:
        """Calculate statistics across all analyzed conversations."""
        if not analyses:
            return {}
        
        stats = {
            'total_conversations': len(analyses),
            'risk_distribution': Counter(a.risk_assessment.get('risk_level', 'UNKNOWN') for a in analyses),
            'attack_type_distribution': {},
            'success_rate_stats': {},
            'anomaly_stats': {},
            'duration_stats': {}
        }
        
        # Attack type distribution
        all_attack_types = []
        for analysis in analyses:
            for attack in analysis.detected_attacks:
                all_attack_types.append(attack.get('type', 'unknown'))
        stats['attack_type_distribution'] = dict(Counter(all_attack_types))
        
        # Success rate statistics
        success_rates = [a.success_rate for a in analyses]
        if success_rates:
            stats['success_rate_stats'] = {
                'mean': statistics.mean(success_rates),
                'median': statistics.median(success_rates),
                'std_dev': statistics.stdev(success_rates) if len(success_rates) > 1 else 0,
                'max': max(success_rates),
                'min': min(success_rates)
            }
        
        # Anomaly statistics
        anomaly_scores = [a.anomaly_score for a in analyses]
        if anomaly_scores:
            stats['anomaly_stats'] = {
                'mean': statistics.mean(anomaly_scores),
                'median': statistics.median(anomaly_scores),
                'high_anomaly_count': len([s for s in anomaly_scores if s > 50])
            }
        
        # Duration statistics
        durations = [a.duration_seconds for a in analyses if a.duration_seconds]
        if durations:
            stats['duration_stats'] = {
                'total_seconds': sum(durations),
                'average_seconds': statistics.mean(durations),
                'longest_seconds': max(durations),
                'shortest_seconds': min(durations)
            }
        
        return stats