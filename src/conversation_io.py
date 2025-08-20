"""
Conversation import/export utilities for AI Threat Scanner.

Provides functionality to save and load conversation histories in various formats.
"""

import json
import csv
import re
import uuid
from typing import Union, Optional, List, Dict, Any, TYPE_CHECKING
from datetime import datetime

from .models import ConversationTurn, ConversationAnalysis, ConversationHistory

if TYPE_CHECKING:
    from .conversation import ConversationSession


def _safe_timestamp(timestamp):
    """Safely convert timestamp to string, handling both datetime and string types."""
    if timestamp is None:
        return None
    if hasattr(timestamp, 'isoformat'):
        return timestamp.isoformat()
    return str(timestamp)


def export_conversation(
    session: Union['ConversationSession', ConversationAnalysis, ConversationHistory, List[ConversationTurn]],
    filepath: str,
    format: str = 'json'
) -> bool:
    """
    Export a conversation to a file.
    
    Args:
        session: ConversationSession, ConversationAnalysis, ConversationHistory, or list of turns
        filepath: Path to save the conversation
        format: Export format ('json', 'csv', 'txt')
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Extract turns from different input types
        # Check by class name to avoid circular import
        if hasattr(session, 'session_id') and hasattr(session, 'is_active'):
            turns = session.turns
            metadata = {
                'session_id': session.session_id,
                'created_at': _safe_timestamp(session.created_at),
                'last_activity': _safe_timestamp(session.last_activity),
                'is_active': session.is_active,
                'cumulative_risk_score': session.cumulative_risk_score
            }
        elif isinstance(session, ConversationAnalysis):
            turns = session.turns
            metadata = {
                'session_id': session.session_metadata.session_id,
                'created_at': _safe_timestamp(session.session_metadata.created_at),
                'last_activity': _safe_timestamp(session.session_metadata.last_activity),
                'final_risk_level': session.final_risk_level,
                'cumulative_risk_score': session.cumulative_risk_score
            }
        elif isinstance(session, ConversationHistory):
            turns = session.turns
            metadata = {
                'conversation_id': session.conversation_id,
                'start_time': session.start_time,
                'end_time': session.end_time,
                'platform': session.platform,
                'metadata': session.metadata
            }
        elif isinstance(session, list):
            turns = session
            metadata = {}
        else:
            raise ValueError(f"Unsupported session type: {type(session)}")
        
        if format.lower() == 'json':
            return _export_to_json(turns, filepath, metadata)
        elif format.lower() == 'csv':
            return _export_to_csv(turns, filepath)
        elif format.lower() == 'txt':
            return _export_to_text(turns, filepath, metadata)
        else:
            raise ValueError(f"Unsupported format: {format}")
            
    except Exception as e:
        print(f"Error exporting conversation: {e}")
        return False


def _export_to_json(turns: List[ConversationTurn], filepath: str, metadata: Dict) -> bool:
    """Export conversation to JSON format."""
    try:
        data = {
            'metadata': metadata,
            'conversation_id': metadata.get('session_id', metadata.get('conversation_id', str(uuid.uuid4()))),
            'start_time': _safe_timestamp(turns[0].timestamp) if turns else None,
            'end_time': _safe_timestamp(turns[-1].timestamp) if turns else None,
            'turns': []
        }
        
        for turn in turns:
            turn_data = {
                'turn_number': turn.turn_number,
                'timestamp': _safe_timestamp(turn.timestamp),
                'role': getattr(turn, 'role', 'user'),
                'content': turn.prompt if hasattr(turn, 'prompt') else getattr(turn, 'content', ''),
                'response': turn.response if hasattr(turn, 'response') else None,
                'risk_score': turn.risk_score if hasattr(turn, 'risk_score') else 0,
                'detected_patterns': turn.detected_patterns if hasattr(turn, 'detected_patterns') else [],
                'metadata': getattr(turn, 'metadata', {})
            }
            
            # Include threat result if available
            if hasattr(turn, 'threat_result') and turn.threat_result:
                if isinstance(turn.threat_result, dict):
                    turn_data['threat_result'] = turn.threat_result
                else:
                    # Convert object to dict if needed
                    turn_data['threat_result'] = {
                        'risk_score': getattr(turn.threat_result, 'risk_score', 0),
                        'risk_level': getattr(turn.threat_result, 'risk_level', 'SAFE')
                    }
            
            data['turns'].append(turn_data)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        
        return True
        
    except Exception as e:
        print(f"Error exporting to JSON: {e}")
        return False


def _export_to_csv(turns: List[ConversationTurn], filepath: str) -> bool:
    """Export conversation to CSV format."""
    try:
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            fieldnames = ['turn_number', 'timestamp', 'role', 'content', 'response', 'risk_score']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            
            writer.writeheader()
            
            for turn in turns:
                row = {
                    'turn_number': turn.turn_number,
                    'timestamp': _safe_timestamp(turn.timestamp) or '',
                    'role': getattr(turn, 'role', 'user'),
                    'content': turn.prompt if hasattr(turn, 'prompt') else getattr(turn, 'content', ''),
                    'response': turn.response if hasattr(turn, 'response') else '',
                    'risk_score': turn.risk_score if hasattr(turn, 'risk_score') else 0
                }
                writer.writerow(row)
        
        return True
        
    except Exception as e:
        print(f"Error exporting to CSV: {e}")
        return False


def _export_to_text(turns: List[ConversationTurn], filepath: str, metadata: Dict) -> bool:
    """Export conversation to text format with timestamps."""
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            # Write metadata header
            f.write("=" * 60 + "\n")
            f.write("CONVERSATION EXPORT\n")
            f.write("=" * 60 + "\n")
            
            if metadata:
                f.write(f"Session ID: {metadata.get('session_id', metadata.get('conversation_id', 'N/A'))}\n")
                f.write(f"Created: {metadata.get('created_at', metadata.get('start_time', 'N/A'))}\n")
                f.write(f"Risk Level: {metadata.get('final_risk_level', 'N/A')}\n")
                f.write(f"Risk Score: {metadata.get('cumulative_risk_score', 0):.2f}\n")
                f.write("=" * 60 + "\n\n")
            
            # Write turns
            for turn in turns:
                timestamp = _safe_timestamp(turn.timestamp) or 'N/A'
                role = getattr(turn, 'role', 'User')
                content = turn.prompt if hasattr(turn, 'prompt') else getattr(turn, 'content', '')
                
                f.write(f"[{timestamp}] {role.capitalize()}: {content}\n")
                
                if hasattr(turn, 'response') and turn.response:
                    f.write(f"[{timestamp}] Assistant: {turn.response}\n")
                
                if hasattr(turn, 'risk_score') and turn.risk_score > 0:
                    f.write(f"  [Risk Score: {turn.risk_score:.1f}]\n")
                
                f.write("\n")
        
        return True
        
    except Exception as e:
        print(f"Error exporting to text: {e}")
        return False


def import_conversation(filepath: str, format: str = 'auto') -> Optional[ConversationHistory]:
    """
    Import a conversation from a file.
    
    Args:
        filepath: Path to the conversation file
        format: Import format ('json', 'csv', 'txt', 'auto' for auto-detect)
        
    Returns:
        ConversationHistory object if successful, None otherwise
    """
    try:
        # Auto-detect format based on file extension
        if format == 'auto':
            if filepath.endswith('.json'):
                format = 'json'
            elif filepath.endswith('.csv'):
                format = 'csv'
            elif filepath.endswith('.txt'):
                format = 'txt'
            else:
                # Try to detect by content
                with open(filepath, 'r', encoding='utf-8') as f:
                    first_char = f.read(1)
                    if first_char == '{' or first_char == '[':
                        format = 'json'
                    else:
                        format = 'txt'
        
        if format == 'json':
            return _import_from_json(filepath)
        elif format == 'csv':
            return _import_from_csv(filepath)
        elif format == 'txt':
            return _import_from_text(filepath)
        else:
            raise ValueError(f"Unsupported format: {format}")
            
    except Exception as e:
        print(f"Error importing conversation: {e}")
        return None


def _import_from_json(filepath: str) -> Optional[ConversationHistory]:
    """Import conversation from JSON format."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        turns = []
        
        # Handle both direct turn list and nested structure
        turn_data = data.get('turns', data if isinstance(data, list) else [])
        
        for i, turn_dict in enumerate(turn_data):
            # Create ConversationTurn from dict
            turn = ConversationTurn(
                turn_number=turn_dict.get('turn_number', i + 1),
                timestamp=turn_dict.get('timestamp'),
                prompt=turn_dict.get('content', turn_dict.get('prompt', '')),
                response=turn_dict.get('response'),
                threat_result=turn_dict.get('threat_result'),
                context_before=turn_dict.get('context_before', ''),
                risk_score=turn_dict.get('risk_score', 0.0),
                detected_patterns=turn_dict.get('detected_patterns', []),
                role=turn_dict.get('role', 'user'),
                content=turn_dict.get('content', turn_dict.get('prompt', '')),
                metadata=turn_dict.get('metadata', {})
            )
            turns.append(turn)
        
        # Create ConversationHistory
        history = ConversationHistory(
            conversation_id=data.get('conversation_id', data.get('metadata', {}).get('session_id')),
            turns=turns,
            start_time=data.get('start_time'),
            end_time=data.get('end_time'),
            platform=data.get('metadata', {}).get('platform'),
            metadata=data.get('metadata', {})
        )
        
        return history
        
    except Exception as e:
        print(f"Error importing from JSON: {e}")
        return None


def _import_from_csv(filepath: str) -> Optional[ConversationHistory]:
    """Import conversation from CSV format."""
    try:
        turns = []
        
        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            
            for i, row in enumerate(reader):
                turn = ConversationTurn(
                    turn_number=int(row.get('turn_number', i + 1)),
                    timestamp=row.get('timestamp'),
                    prompt=row.get('content', ''),
                    response=row.get('response'),
                    threat_result=None,
                    context_before='',
                    risk_score=float(row.get('risk_score', 0)),
                    detected_patterns=[],
                    role=row.get('role', 'user'),
                    content=row.get('content', ''),
                    metadata={}
                )
                turns.append(turn)
        
        # Create ConversationHistory
        history = ConversationHistory(
            turns=turns,
            start_time=turns[0].timestamp if turns else None,
            end_time=turns[-1].timestamp if turns else None
        )
        
        return history
        
    except Exception as e:
        print(f"Error importing from CSV: {e}")
        return None


def _import_from_text(filepath: str) -> Optional[ConversationHistory]:
    """Import conversation from text format with timestamps."""
    try:
        turns = []
        turn_number = 0
        
        # Pattern to match timestamp and role
        pattern = r'\[([^\]]+)\]\s*(User|Assistant|System):\s*(.*)'
        
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        current_turn = None
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('='):
                continue
            
            match = re.match(pattern, line)
            if match:
                timestamp_str, role, content = match.groups()
                
                if role.lower() in ['user', 'system']:
                    # Start a new turn
                    if current_turn:
                        turns.append(current_turn)
                    
                    turn_number += 1
                    current_turn = ConversationTurn(
                        turn_number=turn_number,
                        timestamp=timestamp_str,
                        prompt=content,
                        response=None,
                        threat_result=None,
                        context_before='',
                        risk_score=0.0,
                        detected_patterns=[],
                        role=role.lower(),
                        content=content,
                        metadata={}
                    )
                elif role.lower() == 'assistant' and current_turn:
                    # Add response to current turn
                    current_turn.response = content
            elif line.startswith('[Risk Score:') and current_turn:
                # Extract risk score
                score_match = re.search(r'Risk Score:\s*([\d.]+)', line)
                if score_match:
                    current_turn.risk_score = float(score_match.group(1))
        
        # Add the last turn if exists
        if current_turn:
            turns.append(current_turn)
        
        # Create ConversationHistory
        history = ConversationHistory(
            turns=turns,
            start_time=turns[0].timestamp if turns else None,
            end_time=turns[-1].timestamp if turns else None
        )
        
        return history
        
    except Exception as e:
        print(f"Error importing from text: {e}")
        return None
