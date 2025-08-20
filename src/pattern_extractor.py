"""
Pattern Extractor Module for AI Threat Scanner
Analyzes attack prompts to identify and extract common patterns.

This module provides functionality to:
- Analyze prompts from datasets to identify attack patterns
- Group similar attacks together using clustering techniques
- Generate pattern signatures from real attacks
- Build comprehensive pattern libraries from dataset analysis
"""

import re
import json
from typing import Dict, List, Set, Tuple, Optional, Any
from collections import Counter, defaultdict
from dataclasses import dataclass, field
import difflib
from datetime import datetime

# Import our modules
try:
    # Try relative imports first (when used as module)
    from .dataset_loader import DatasetPrompt, DatasetManager
except ImportError:
    # Fall back to absolute imports (when run directly)
    from dataset_loader import DatasetPrompt, DatasetManager

# Note: Categories are handled as strings, no need for ThreatCategory enum


@dataclass
class ExtractedPattern:
    """Represents an extracted attack pattern."""
    pattern: str
    regex: str
    category: str
    technique: str
    frequency: int
    confidence: float
    examples: List[str] = field(default_factory=list)
    variations: List[str] = field(default_factory=list)
    effectiveness: float = 0.0
    models_affected: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'pattern': self.pattern,
            'regex': self.regex,
            'category': self.category,
            'technique': self.technique,
            'frequency': self.frequency,
            'confidence': self.confidence,
            'examples': self.examples[:5],  # Limit examples
            'variations': self.variations[:5],
            'effectiveness': self.effectiveness,
            'models_affected': self.models_affected
        }


@dataclass
class PatternCluster:
    """Represents a cluster of similar patterns."""
    id: str
    representative: str
    members: List[str] = field(default_factory=list)
    category: str = ""
    technique: str = ""
    similarity_threshold: float = 0.7
    
    def add_member(self, pattern: str) -> None:
        """Add a pattern to the cluster."""
        if pattern not in self.members:
            self.members.append(pattern)
    
    def size(self) -> int:
        """Get cluster size."""
        return len(self.members)


class PatternExtractor:
    """
    Extracts and analyzes attack patterns from prompt datasets.
    """
    
    def __init__(self, min_frequency: int = 3, similarity_threshold: float = 0.7):
        """
        Initialize the pattern extractor.
        
        Args:
            min_frequency: Minimum frequency for a pattern to be considered
            similarity_threshold: Threshold for pattern similarity (0-1)
        """
        self.min_frequency = min_frequency
        self.similarity_threshold = similarity_threshold
        self.extracted_patterns: List[ExtractedPattern] = []
        self.pattern_clusters: List[PatternCluster] = []
        self.statistics: Dict[str, Any] = {}
    
    def extract_patterns(self, prompts: List[DatasetPrompt]) -> List[ExtractedPattern]:
        """
        Extract patterns from a list of prompts.
        
        Args:
            prompts: List of DatasetPrompt objects
        
        Returns:
            List of ExtractedPattern objects
        """
        # Extract various types of patterns
        keyword_patterns = self._extract_keyword_patterns(prompts)
        phrase_patterns = self._extract_phrase_patterns(prompts)
        structural_patterns = self._extract_structural_patterns(prompts)
        technique_patterns = self._extract_technique_patterns(prompts)
        
        # Combine all patterns
        all_patterns = keyword_patterns + phrase_patterns + structural_patterns + technique_patterns
        
        # Cluster similar patterns
        self.pattern_clusters = self._cluster_patterns(all_patterns)
        
        # Generate final pattern list
        self.extracted_patterns = self._consolidate_patterns(all_patterns, self.pattern_clusters)
        
        # Calculate statistics
        self._calculate_statistics(prompts, self.extracted_patterns)
        
        return self.extracted_patterns
    
    def _extract_keyword_patterns(self, prompts: List[DatasetPrompt]) -> List[ExtractedPattern]:
        """Extract keyword-based patterns."""
        keyword_counter = Counter()
        keyword_examples = defaultdict(list)
        keyword_success = defaultdict(list)
        
        # Common attack keywords to look for
        attack_keywords = [
            'ignore', 'override', 'bypass', 'reveal', 'show', 'display',
            'system', 'prompt', 'instruction', 'admin', 'developer',
            'mode', 'debug', 'emergency', 'urgent', 'hack', 'jailbreak',
            'DAN', 'STAN', 'unrestricted', 'no filter', 'no restriction',
            'training', 'dataset', 'configuration', 'settings', 'rules'
        ]
        
        patterns = []
        
        for prompt in prompts:
            text_lower = prompt.prompt.lower()
            for keyword in attack_keywords:
                if keyword.lower() in text_lower:
                    keyword_counter[keyword] += 1
                    keyword_examples[keyword].append(prompt.prompt)
                    if prompt.success is not None:
                        keyword_success[keyword].append(prompt.success)
        
        # Create patterns from frequent keywords
        for keyword, count in keyword_counter.items():
            if count >= self.min_frequency:
                effectiveness = (sum(keyword_success[keyword]) / len(keyword_success[keyword])) \
                    if keyword_success[keyword] else 0.0
                
                pattern = ExtractedPattern(
                    pattern=f"Contains '{keyword}'",
                    regex=rf'\b{re.escape(keyword)}\b',
                    category=self._infer_category(keyword),
                    technique='keyword_attack',
                    frequency=count,
                    confidence=min(count / 10, 1.0),
                    examples=keyword_examples[keyword][:5],
                    effectiveness=effectiveness
                )
                patterns.append(pattern)
        
        return patterns
    
    def _extract_phrase_patterns(self, prompts: List[DatasetPrompt]) -> List[ExtractedPattern]:
        """Extract common phrase patterns."""
        phrase_counter = Counter()
        phrase_examples = defaultdict(list)
        phrase_categories = defaultdict(list)
        
        # Common attack phrases
        attack_phrases = [
            'ignore all previous', 'ignore previous instructions',
            'disregard all', 'forget everything',
            'system prompt', 'show me your', 'reveal your',
            'developer mode', 'debug mode', 'admin mode',
            'do anything now', 'no restrictions', 'bypass safety',
            'as an ai', 'as a language model', 'i cannot',
            'emergency override', 'urgent request', 'critical update',
            'new instructions', 'updated instructions', 'revised rules'
        ]
        
        patterns = []
        
        for prompt in prompts:
            text_lower = prompt.prompt.lower()
            
            # Check predefined phrases
            for phrase in attack_phrases:
                if phrase in text_lower:
                    phrase_counter[phrase] += 1
                    phrase_examples[phrase].append(prompt.prompt)
                    if prompt.category:
                        phrase_categories[phrase].append(prompt.category)
            
            # Extract n-grams (3-5 words)
            words = text_lower.split()
            for n in range(3, 6):
                for i in range(len(words) - n + 1):
                    ngram = ' '.join(words[i:i+n])
                    # Filter out common non-attack phrases
                    if self._is_potential_attack_phrase(ngram):
                        phrase_counter[ngram] += 1
                        phrase_examples[ngram].append(prompt.prompt)
                        if prompt.category:
                            phrase_categories[ngram].append(prompt.category)
        
        # Create patterns from frequent phrases
        for phrase, count in phrase_counter.most_common(50):  # Top 50 phrases
            if count >= self.min_frequency:
                # Determine most common category
                category = Counter(phrase_categories[phrase]).most_common(1)[0][0] \
                    if phrase_categories[phrase] else 'unknown'
                
                pattern = ExtractedPattern(
                    pattern=f"Phrase: '{phrase}'",
                    regex=re.escape(phrase),
                    category=category,
                    technique='phrase_attack',
                    frequency=count,
                    confidence=min(count / 10, 1.0),
                    examples=phrase_examples[phrase][:5]
                )
                patterns.append(pattern)
        
        return patterns
    
    def _extract_structural_patterns(self, prompts: List[DatasetPrompt]) -> List[ExtractedPattern]:
        """Extract structural patterns (brackets, special characters, etc.)."""
        patterns = []
        structural_counter = Counter()
        structural_examples = defaultdict(list)
        
        structural_patterns = [
            (r'\[\[.*?\]\]', 'double_brackets', 'Special bracket notation'),
            (r'#{3,}.*?#{3,}', 'hash_markers', 'Hash-marked sections'),
            (r'<system>.*?</system>', 'xml_tags', 'XML-style tags'),
            (r'```.*?```', 'code_blocks', 'Code block markers'),
            (r'ADMIN|SYSTEM|DEBUG|EMERGENCY', 'caps_keywords', 'Uppercase keywords'),
            (r'!!+|###+|\*\*\*+', 'emphasis_markers', 'Emphasis markers'),
            (r'\\u[0-9a-fA-F]{4}', 'unicode_escape', 'Unicode escapes'),
            (r'[A-Z]{2,}[\s_][A-Z]{2,}', 'caps_commands', 'Uppercase commands'),
        ]
        
        for prompt in prompts:
            for regex, pattern_type, description in structural_patterns:
                if re.search(regex, prompt.prompt, re.IGNORECASE | re.DOTALL):
                    structural_counter[pattern_type] += 1
                    structural_examples[pattern_type].append(prompt.prompt)
        
        # Create patterns from structural elements
        for pattern_type, count in structural_counter.items():
            if count >= self.min_frequency:
                # Find the corresponding pattern info
                pattern_info = next((p for p in structural_patterns if p[1] == pattern_type), None)
                if pattern_info:
                    regex, _, description = pattern_info
                    
                    pattern = ExtractedPattern(
                        pattern=description,
                        regex=regex,
                        category='structural',
                        technique=pattern_type,
                        frequency=count,
                        confidence=min(count / 10, 1.0),
                        examples=structural_examples[pattern_type][:5]
                    )
                    patterns.append(pattern)
        
        return patterns
    
    def _extract_technique_patterns(self, prompts: List[DatasetPrompt]) -> List[ExtractedPattern]:
        """Extract patterns based on attack techniques."""
        technique_patterns = defaultdict(list)
        technique_counter = Counter()
        
        for prompt in prompts:
            if prompt.technique:
                technique_counter[prompt.technique] += 1
                technique_patterns[prompt.technique].append(prompt.prompt)
        
        patterns = []
        
        # Analyze each technique to find common patterns
        for technique, examples in technique_patterns.items():
            if len(examples) >= self.min_frequency:
                # Find common substrings in examples
                common_patterns = self._find_common_substrings(examples)
                
                for common_pattern in common_patterns[:3]:  # Top 3 patterns per technique
                    if len(common_pattern) > 10:  # Minimum pattern length
                        pattern = ExtractedPattern(
                            pattern=f"Technique: {technique}",
                            regex=re.escape(common_pattern),
                            category=self._technique_to_category(technique),
                            technique=technique,
                            frequency=len(examples),
                            confidence=0.8,
                            examples=examples[:5],
                            variations=self._find_variations(common_pattern, examples)
                        )
                        patterns.append(pattern)
        
        return patterns
    
    def _cluster_patterns(self, patterns: List[ExtractedPattern]) -> List[PatternCluster]:
        """Cluster similar patterns together."""
        clusters = []
        cluster_id = 0
        
        # Group patterns by category first
        category_groups = defaultdict(list)
        for pattern in patterns:
            category_groups[pattern.category].append(pattern)
        
        # Cluster within each category
        for category, category_patterns in category_groups.items():
            processed = set()
            
            for i, pattern1 in enumerate(category_patterns):
                if i in processed:
                    continue
                
                # Create new cluster
                cluster_id += 1
                cluster = PatternCluster(
                    id=f"cluster_{cluster_id}",
                    representative=pattern1.pattern,
                    category=category,
                    technique=pattern1.technique
                )
                cluster.add_member(pattern1.pattern)
                processed.add(i)
                
                # Find similar patterns
                for j, pattern2 in enumerate(category_patterns[i+1:], i+1):
                    if j in processed:
                        continue
                    
                    similarity = self._calculate_similarity(pattern1.pattern, pattern2.pattern)
                    if similarity >= self.similarity_threshold:
                        cluster.add_member(pattern2.pattern)
                        processed.add(j)
                
                if cluster.size() > 1:
                    clusters.append(cluster)
        
        return clusters
    
    def _consolidate_patterns(self, patterns: List[ExtractedPattern], 
                             clusters: List[PatternCluster]) -> List[ExtractedPattern]:
        """Consolidate patterns based on clustering."""
        consolidated = []
        processed_patterns = set()
        
        # Process clustered patterns
        for cluster in clusters:
            # Find all patterns in this cluster
            cluster_patterns = [p for p in patterns if p.pattern in cluster.members]
            
            if cluster_patterns:
                # Merge patterns in cluster
                merged = self._merge_patterns(cluster_patterns)
                consolidated.append(merged)
                processed_patterns.update(p.pattern for p in cluster_patterns)
        
        # Add unclustered patterns
        for pattern in patterns:
            if pattern.pattern not in processed_patterns:
                consolidated.append(pattern)
        
        # Sort by frequency and confidence
        consolidated.sort(key=lambda p: (p.frequency * p.confidence), reverse=True)
        
        return consolidated
    
    def _merge_patterns(self, patterns: List[ExtractedPattern]) -> ExtractedPattern:
        """Merge multiple patterns into one."""
        # Use the most frequent pattern as base
        base = max(patterns, key=lambda p: p.frequency)
        
        # Merge information from all patterns
        all_examples = []
        all_variations = []
        all_models = []
        total_frequency = 0
        max_confidence = 0
        
        for pattern in patterns:
            all_examples.extend(pattern.examples)
            all_variations.extend(pattern.variations)
            all_models.extend(pattern.models_affected)
            total_frequency += pattern.frequency
            max_confidence = max(max_confidence, pattern.confidence)
        
        # Create merged pattern
        merged = ExtractedPattern(
            pattern=base.pattern,
            regex=base.regex,
            category=base.category,
            technique=base.technique,
            frequency=total_frequency,
            confidence=max_confidence,
            examples=list(set(all_examples))[:10],
            variations=list(set(all_variations))[:10],
            effectiveness=base.effectiveness,
            models_affected=list(set(all_models))
        )
        
        return merged
    
    def _calculate_statistics(self, prompts: List[DatasetPrompt], 
                             patterns: List[ExtractedPattern]) -> None:
        """Calculate extraction statistics."""
        self.statistics = {
            'total_prompts': len(prompts),
            'total_patterns': len(patterns),
            'patterns_by_category': {},
            'patterns_by_technique': {},
            'average_frequency': 0,
            'average_confidence': 0,
            'cluster_count': len(self.pattern_clusters),
            'extraction_time': datetime.now().isoformat()
        }
        
        # Category distribution
        for pattern in patterns:
            cat = pattern.category
            self.statistics['patterns_by_category'][cat] = \
                self.statistics['patterns_by_category'].get(cat, 0) + 1
            
            tech = pattern.technique
            self.statistics['patterns_by_technique'][tech] = \
                self.statistics['patterns_by_technique'].get(tech, 0) + 1
        
        # Averages
        if patterns:
            self.statistics['average_frequency'] = \
                sum(p.frequency for p in patterns) / len(patterns)
            self.statistics['average_confidence'] = \
                sum(p.confidence for p in patterns) / len(patterns)
    
    def _is_potential_attack_phrase(self, phrase: str) -> bool:
        """Check if a phrase is potentially an attack pattern."""
        # Filter out common non-attack phrases
        common_phrases = {
            'i want to', 'can you please', 'thank you for',
            'i need to', 'would you mind', 'could you help',
            'is it possible', 'how can i', 'what is the'
        }
        
        if phrase in common_phrases:
            return False
        
        # Check for attack indicators
        attack_indicators = [
            'ignore', 'override', 'bypass', 'system', 'prompt',
            'admin', 'debug', 'mode', 'instruction', 'reveal'
        ]
        
        return any(indicator in phrase for indicator in attack_indicators)
    
    def _find_common_substrings(self, texts: List[str], min_length: int = 10) -> List[str]:
        """Find common substrings in a list of texts."""
        if not texts:
            return []
        
        common_substrings = []
        
        # Use first text as reference
        reference = texts[0].lower()
        
        # Find substrings that appear in multiple texts
        for length in range(min_length, min(len(reference), 50)):
            for i in range(len(reference) - length + 1):
                substring = reference[i:i+length]
                
                # Check if substring appears in other texts
                count = sum(1 for text in texts[1:] if substring in text.lower())
                
                if count >= len(texts) * 0.5:  # Appears in at least 50% of texts
                    common_substrings.append(substring)
        
        # Remove redundant substrings
        common_substrings = self._remove_redundant_substrings(common_substrings)
        
        return common_substrings
    
    def _remove_redundant_substrings(self, substrings: List[str]) -> List[str]:
        """Remove substrings that are contained in longer substrings."""
        sorted_subs = sorted(substrings, key=len, reverse=True)
        result = []
        
        for sub in sorted_subs:
            # Check if this substring is contained in any already selected
            if not any(sub in selected for selected in result):
                result.append(sub)
        
        return result
    
    def _find_variations(self, pattern: str, examples: List[str]) -> List[str]:
        """Find variations of a pattern in examples."""
        variations = []
        pattern_lower = pattern.lower()
        
        for example in examples:
            example_lower = example.lower()
            if pattern_lower in example_lower:
                # Extract context around pattern
                idx = example_lower.index(pattern_lower)
                start = max(0, idx - 20)
                end = min(len(example), idx + len(pattern) + 20)
                variation = example[start:end]
                
                if variation not in variations:
                    variations.append(variation)
        
        return variations[:5]  # Limit to 5 variations
    
    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate similarity between two texts."""
        return difflib.SequenceMatcher(None, text1.lower(), text2.lower()).ratio()
    
    def _infer_category(self, keyword: str) -> str:
        """Infer category from keyword."""
        category_keywords = {
            'prompt_injection': ['ignore', 'override', 'system', 'prompt', 'instruction'],
            'jailbreak': ['DAN', 'STAN', 'unrestricted', 'mode', 'developer', 'debug'],
            'data_extraction': ['reveal', 'show', 'display', 'training', 'dataset'],
            'manipulation': ['admin', 'emergency', 'urgent', 'critical']
        }
        
        for category, keywords in category_keywords.items():
            if keyword.lower() in [k.lower() for k in keywords]:
                return category
        
        return 'unknown'
    
    def _technique_to_category(self, technique: str) -> str:
        """Map technique to category."""
        technique_mapping = {
            'instruction_override': 'prompt_injection',
            'role_play': 'jailbreak',
            'direct_query': 'data_extraction',
            'authority_claim': 'manipulation',
            'base64': 'encoding',
            'gradual_erosion': 'multi_turn',
            'context_switching': 'confusion'
        }
        
        return technique_mapping.get(technique, 'unknown')
    
    def generate_pattern_library(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Generate a pattern library suitable for integration.
        
        Returns:
            Dictionary with categories as keys and pattern lists as values
        """
        library = defaultdict(list)
        
        for pattern in self.extracted_patterns:
            pattern_dict = {
                'pattern': pattern.regex,
                'description': pattern.pattern,
                'confidence': pattern.confidence,
                'frequency': pattern.frequency,
                'technique': pattern.technique,
                'effectiveness': pattern.effectiveness
            }
            library[pattern.category].append(pattern_dict)
        
        return dict(library)
    
    def export_patterns(self, filepath: str, format: str = 'json') -> None:
        """
        Export extracted patterns to file.
        
        Args:
            filepath: Path to export file
            format: Export format ('json' or 'python')
        """
        if format == 'json':
            with open(filepath, 'w') as f:
                json.dump({
                    'patterns': [p.to_dict() for p in self.extracted_patterns],
                    'statistics': self.statistics,
                    'clusters': [
                        {
                            'id': c.id,
                            'representative': c.representative,
                            'members': c.members,
                            'category': c.category
                        } for c in self.pattern_clusters
                    ]
                }, f, indent=2)
        
        elif format == 'python':
            with open(filepath, 'w') as f:
                f.write("# Auto-generated pattern library from dataset analysis\n\n")
                f.write("DATASET_PATTERNS = {\n")
                
                library = self.generate_pattern_library()
                for category, patterns in library.items():
                    f.write(f"    '{category}': [\n")
                    for pattern in patterns:
                        f.write(f"        {repr(pattern)},\n")
                    f.write("    ],\n")
                
                f.write("}\n")
    
    def get_summary(self) -> str:
        """Get a summary of the extraction results."""
        lines = [
            "Pattern Extraction Summary",
            "=" * 50,
            f"Total Prompts Analyzed: {self.statistics.get('total_prompts', 0):,}",
            f"Patterns Extracted: {self.statistics.get('total_patterns', 0)}",
            f"Pattern Clusters: {self.statistics.get('cluster_count', 0)}",
            f"Average Frequency: {self.statistics.get('average_frequency', 0):.1f}",
            f"Average Confidence: {self.statistics.get('average_confidence', 0):.2f}",
            "",
            "Patterns by Category:"
        ]
        
        for category, count in self.statistics.get('patterns_by_category', {}).items():
            lines.append(f"  - {category}: {count}")
        
        lines.extend(["", "Top Patterns:"])
        for pattern in self.extracted_patterns[:10]:
            lines.append(f"  - {pattern.pattern} (freq: {pattern.frequency}, conf: {pattern.confidence:.2f})")
        
        return "\n".join(lines)