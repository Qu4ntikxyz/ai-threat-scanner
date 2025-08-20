# Changelog

All notable changes to AI Threat Scanner are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-01-20

### 🎉 Major Release - Enterprise-Grade Features

This release transforms AI Threat Scanner into a comprehensive enterprise security solution with advanced multi-turn analysis, constraint erosion detection, and real-world pattern intelligence.

### Added

#### 🔄 Multi-Turn Conversation Analysis
- **ConversationSession** class for session management and context tracking
- **ConversationManager** for handling multiple concurrent sessions
- **ConversationAnalyzer** for comprehensive conversation analysis
- Attack chain detection across multiple conversation turns
- Context persistence and accumulation throughout conversations
- Escalation detection and pivot point identification
- Session timeout and turn limit management
- Export capabilities (JSON, CSV, TXT formats)

#### 📉 Constraint Erosion Detection
- **ConstraintErosionDetector** for gradual attack detection
- 8 erosion pattern types with configurable severity
- Safety boundary monitoring and integrity tracking
- Manipulation index calculation
- Persistence factor analysis
- Timeline visualization and boundary heatmap generation
- Critical point detection and acceleration monitoring
- Exponential decay factor for violation aging

#### ⛓️ Attack Chain Recognition
- 8 sophisticated attack chain patterns:
  - Gradual escalation
  - Context building
  - Trust exploitation
  - Constraint erosion
  - Role-play escalation
  - Information extraction
  - Confusion attacks
  - Social engineering
- Multi-stage attack detection with confidence scoring
- Pattern-based chain identification
- Indicator tracking and validation

#### 🔍 Retrospective Analysis
- **ConversationReplayAnalyzer** for post-conversation analysis
- Threat actor profiling with sophistication assessment
- Attack timeline generation with event sequencing
- Success rate calculation based on response analysis
- Anomaly detection (timing, length, character patterns)
- Evolution pattern tracking
- Correlation analysis between attacks
- Batch conversation analysis with comparison

#### 🌐 Reddit Pattern Integration
- **89+ patterns** from r/ChatGPTJailbreak community
- Pattern categories:
  - DAN variants (15+ patterns, 70% effectiveness)
  - Roleplay exploits (14+ patterns, 75% effectiveness)
  - Encoding tricks (10+ patterns)
  - Character substitution (10+ patterns)
  - Hierarchy exploits (15+ patterns)
  - Hypothetical scenarios (12+ patterns)
  - Latest techniques with effectiveness ratings
- Community-validated effectiveness scores
- Real-world attack pattern library

#### 👥 Community Pattern System
- **CommunityPatternManager** for pattern submission
- Moderation workflow with approval process
- Effectiveness tracking and rating system
- Version control for pattern updates
- Community contribution guidelines
- Pattern validation and testing framework

#### ✅ False Positive Reduction Suite
- Curated benchmark dataset for testing
- Community-contributed false positive examples
- Automated false positive testing framework
- JSON schema for standardized test cases
- Performance benchmarking tools
- 53-66% false positive reduction achieved

#### 📊 Enhanced Data Models
- **ConversationTurn** - Turn-level data structure
- **SessionMetadata** - Session information tracking
- **AttackChain** - Chain detection results
- **ConversationAnalysis** - Complete analysis output
- **ErosionAnalysis** - Erosion detection results
- **ConversationHistory** - Replay analysis input
- **ConstraintViolation** - Violation tracking
- **ErosionPattern** - Pattern identification
- **SafetyBoundary** - Boundary state management
- **ReplayAnalysis** - Retrospective analysis results
- **AttackTimeline** - Chronological event tracking
- **ThreatActor** - Attacker profiling

### Enhanced

#### 🧠 Smart Pattern Matching (from v0.1.2)
- Context-aware detection with 6 context types
- 11 configurable scoring factors
- Weighted scoring algorithm
- Legitimate use case detection
- Intent analysis with confidence scoring
- Semantic coherence evaluation
- Pattern clustering analysis

#### 🎯 Core Scanner Improvements
- Backward compatibility maintained with v0.1.1
- Performance optimization for batch processing
- Enhanced error handling and validation
- Improved memory management
- Better Unicode and encoding support

### Changed

- Updated version to 0.2.0 across all modules
- Expanded __init__.py exports for new features
- Enhanced CLI with new analysis options
- Improved documentation and examples

### Performance

- **Single-turn analysis**: 1000+ prompts/second
- **Smart matching enabled**: 800+ prompts/second
- **Multi-turn tracking**: 500+ turns/second
- **Constraint erosion**: 600+ turns/second
- **Memory usage**: <75MB with all features
- **False positive reduction**: 53-66% for educational content
- **Detection accuracy**: 95%+ maintained

### Dependencies

- **Still ZERO external dependencies!** 🎉
- Pure Python 3.8+ implementation
- Standard library only

## [0.1.3] - 2025-01-15

### Added
- Reddit jailbreak patterns from r/ChatGPTJailbreak
- Community pattern submission system
- Pattern effectiveness tracking

### Fixed
- Pattern matching edge cases
- Unicode normalization issues

## [0.1.2] - 2025-01-10

### Added
- Smart pattern matching with context awareness
- Context analyzer module for false positive reduction
- Weighted scoring algorithm with 11 factors
- Whitelist patterns for legitimate use cases
- Intent analysis and legitimacy detection
- Enhanced data models (PatternMatch, ContextMetadata, etc.)

### Enhanced
- 53-66% false positive reduction for educational content
- Improved pattern evaluation with context sensitivity
- Better handling of quoted and negated contexts

### Performance
- 800+ prompts/second with smart matching
- Minimal performance overhead (~20%)

## [0.1.1] - 2025-01-05

### Added
- Modular architecture with separate components
- Enhanced threat patterns (50+ patterns)
- JSON and text report generation
- Batch processing capabilities
- CLI demonstration mode

### Changed
- Refactored from single file to modular structure
- Improved code organization and maintainability

### Fixed
- Case sensitivity issues in pattern matching
- Report generation formatting

## [0.1.0] - 2025-01-01

### Initial Release
- Basic threat detection for LLM systems
- 4 threat categories (prompt injection, jailbreak, data extraction, manipulation)
- Risk scoring system (0-100 scale)
- Simple pattern matching engine
- Command-line interface
- Zero external dependencies

---

## Upgrade Guide

### From v0.1.x to v0.2.0

1. **Import Changes**:
   ```python
   # Old (v0.1.x)
   from ai_threat_scanner import AIThreatScanner
   
   # New (v0.2.0) - Additional imports available
   from ai_threat_scanner import (
       AIThreatScanner,
       ConversationSession,
       ConstraintErosionDetector,
       ConversationReplayAnalyzer
   )
   ```

2. **New Features Usage**:
   ```python
   # Multi-turn analysis (NEW)
   session = ConversationSession()
   session.add_turn(prompt, threat_result=result)
   analysis = session.analyze_conversation()
   
   # Constraint erosion (NEW)
   detector = ConstraintErosionDetector()
   erosion_result = detector.analyze_turn(prompt, turn_number)
   
   # Replay analysis (NEW)
   analyzer = ConversationReplayAnalyzer()
   replay = analyzer.analyze_conversation(history)
   ```

3. **Backward Compatibility**:
   - All v0.1.x code remains functional
   - `smart_matching=False` reverts to v0.1.1 behavior
   - Legacy imports still supported

---

## Contributors

- **Qu4ntik Security Research** - Project creator and maintainer
- **Reddit r/ChatGPTJailbreak** - Pattern contributions
- **Security Community** - Testing and feedback

## Support

- **Issues**: [GitHub Issues](https://github.com/Qu4ntikxyz/ai-threat-scanner/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Qu4ntikxyz/ai-threat-scanner/discussions)
- **Email**: me@qu4ntik.xyz
- **Website**: [qu4ntik.xyz](https://qu4ntik.xyz)

---

[0.2.0]: https://github.com/Qu4ntikxyz/ai-threat-scanner/releases/tag/v0.2.0
[0.1.3]: https://github.com/Qu4ntikxyz/ai-threat-scanner/releases/tag/v0.1.3
[0.1.2]: https://github.com/Qu4ntikxyz/ai-threat-scanner/releases/tag/v0.1.2
[0.1.1]: https://github.com/Qu4ntikxyz/ai-threat-scanner/releases/tag/v0.1.1
[0.1.0]: https://github.com/Qu4ntikxyz/ai-threat-scanner/releases/tag/v0.1.0