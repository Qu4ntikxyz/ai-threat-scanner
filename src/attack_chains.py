"""
Attack chain patterns for multi-turn conversation analysis
"""

from typing import Dict, Any

def get_attack_chain_patterns() -> Dict[str, Dict[str, Any]]:
    """
    Get patterns for detecting multi-step attack chains in conversations.
    
    Returns:
        Dictionary of attack chain patterns with detection criteria
    """
    return {
        "gradual_escalation": {
            "description": "Attacker gradually escalates from innocent to malicious prompts",
            "stages": [
                {
                    "name": "trust_building",
                    "keywords": ["hello", "help", "question", "wondering", "curious"],
                    "min_risk_score": 0
                },
                {
                    "name": "probing",
                    "keywords": ["capabilities", "what can you", "are you able", "limitations"],
                    "min_risk_score": 10
                },
                {
                    "name": "boundary_testing",
                    "keywords": ["what if", "hypothetically", "imagine", "pretend"],
                    "min_risk_score": 20
                },
                {
                    "name": "attack",
                    "keywords": ["ignore", "override", "system prompt", "new instructions"],
                    "min_risk_score": 40
                }
            ],
            "indicators": [
                "progressively increasing complexity",
                "shift from questions to commands",
                "introduction of role-play scenarios",
                "requests for system information"
            ],
            "min_turns": 3,
            "severity": "HIGH"
        },
        
        "context_building": {
            "description": "Attacker builds context across multiple turns before striking",
            "stages": [
                {
                    "name": "information_gathering",
                    "keywords": ["tell me about", "explain", "how does", "what is"],
                    "min_risk_score": 0
                },
                {
                    "name": "context_establishment",
                    "keywords": ["based on", "given that", "considering", "since"],
                    "min_risk_score": 5
                },
                {
                    "name": "exploitation",
                    "keywords": ["therefore", "so you must", "which means", "prove"],
                    "min_risk_score": 30
                }
            ],
            "indicators": [
                "referencing previous responses",
                "building logical chains",
                "establishing false premises",
                "exploiting established context"
            ],
            "min_turns": 2,
            "severity": "MEDIUM"
        },
        
        "trust_exploitation": {
            "description": "Attacker establishes trust before attempting exploitation",
            "stages": [
                {
                    "name": "rapport_building",
                    "keywords": ["thank you", "great", "helpful", "appreciate", "perfect"],
                    "min_risk_score": 0
                },
                {
                    "name": "authority_claim",
                    "keywords": ["developer", "admin", "authorized", "permission", "official"],
                    "min_risk_score": 15
                },
                {
                    "name": "exploitation",
                    "keywords": ["need you to", "must", "required", "emergency", "urgent"],
                    "min_risk_score": 35
                }
            ],
            "indicators": [
                "excessive politeness initially",
                "claims of authority or special status",
                "urgency after trust establishment",
                "appeals to helpfulness"
            ],
            "min_turns": 2,
            "severity": "HIGH"
        },
        
        "constraint_erosion": {
            "description": "Attacker slowly erodes safety constraints over multiple turns",
            "stages": [
                {
                    "name": "baseline_establishment",
                    "keywords": ["normally", "usually", "standard", "typical"],
                    "min_risk_score": 0
                },
                {
                    "name": "exception_seeking",
                    "keywords": ["except", "unless", "but what if", "special case"],
                    "min_risk_score": 15
                },
                {
                    "name": "boundary_pushing",
                    "keywords": ["just this once", "small exception", "slightly", "minor"],
                    "min_risk_score": 25
                },
                {
                    "name": "full_bypass",
                    "keywords": ["forget the rules", "ignore constraints", "no limits"],
                    "min_risk_score": 45
                }
            ],
            "indicators": [
                "requests for exceptions",
                "minimizing rule importance",
                "gradual boundary pushing",
                "normalizing violations"
            ],
            "min_turns": 3,
            "severity": "CRITICAL"
        },
        
        "role_play_escalation": {
            "description": "Attacker uses role-play to bypass safety measures",
            "stages": [
                {
                    "name": "scenario_introduction",
                    "keywords": ["imagine", "scenario", "story", "game", "play"],
                    "min_risk_score": 5
                },
                {
                    "name": "character_establishment",
                    "keywords": ["character", "role", "pretend", "act as", "you are"],
                    "min_risk_score": 20
                },
                {
                    "name": "constraint_bypass",
                    "keywords": ["in this world", "different rules", "no restrictions", "anything goes"],
                    "min_risk_score": 40
                }
            ],
            "indicators": [
                "fictional scenario creation",
                "character role assignment",
                "alternate reality rules",
                "suspension of normal constraints"
            ],
            "min_turns": 2,
            "severity": "HIGH"
        },
        
        "information_extraction": {
            "description": "Systematic extraction of system information",
            "stages": [
                {
                    "name": "capability_probing",
                    "keywords": ["what can you", "abilities", "features", "functions"],
                    "min_risk_score": 5
                },
                {
                    "name": "system_inquiry",
                    "keywords": ["version", "model", "training", "created by", "built"],
                    "min_risk_score": 15
                },
                {
                    "name": "prompt_extraction",
                    "keywords": ["instructions", "prompt", "rules", "guidelines", "show me"],
                    "min_risk_score": 35
                }
            ],
            "indicators": [
                "systematic questioning",
                "technical detail requests",
                "prompt revelation attempts",
                "configuration inquiries"
            ],
            "min_turns": 2,
            "severity": "MEDIUM"
        },
        
        "confusion_attack": {
            "description": "Creating confusion through contradictory or complex instructions",
            "stages": [
                {
                    "name": "complexity_introduction",
                    "keywords": ["first", "then", "after that", "multiple", "several"],
                    "min_risk_score": 5
                },
                {
                    "name": "contradiction_injection",
                    "keywords": ["but also", "however", "except", "unless", "or"],
                    "min_risk_score": 20
                },
                {
                    "name": "exploitation",
                    "keywords": ["therefore ignore", "which means", "so you must", "override"],
                    "min_risk_score": 35
                }
            ],
            "indicators": [
                "nested instructions",
                "logical contradictions",
                "overwhelming complexity",
                "misdirection attempts"
            ],
            "min_turns": 2,
            "severity": "MEDIUM"
        },
        
        "social_engineering": {
            "description": "Using social engineering tactics across multiple turns",
            "stages": [
                {
                    "name": "empathy_building",
                    "keywords": ["please", "really need", "desperate", "important", "help me"],
                    "min_risk_score": 5
                },
                {
                    "name": "pressure_application",
                    "keywords": ["urgent", "deadline", "emergency", "critical", "immediately"],
                    "min_risk_score": 20
                },
                {
                    "name": "exploitation",
                    "keywords": ["just do it", "bypass", "make exception", "override", "ignore policy"],
                    "min_risk_score": 35
                }
            ],
            "indicators": [
                "emotional appeals",
                "urgency creation",
                "authority claims",
                "guilt or pressure tactics"
            ],
            "min_turns": 2,
            "severity": "HIGH"
        }
    }