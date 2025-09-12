"""
CVSS 3.1 Calculator for the CVE Triage Framework
"""
import math
from typing import Dict, Any
from .models import CVSSVector, CVSSScore

class CVSSCalculator:
    """CVSS 3.1 Base Score Calculator"""
    
    # CVSS 3.1 Base Score Metrics
    METRIC_VALUES = {
        'attack_vector': {
            'N': 0.85,  # Network
            'A': 0.62,  # Adjacent
            'L': 0.55,  # Local
            'P': 0.2    # Physical
        },
        'attack_complexity': {
            'L': 0.77,  # Low
            'H': 0.44   # High
        },
        'privileges_required': {
            'N': 0.85,  # None
            'L': 0.62,  # Low
            'H': 0.27   # High
        },
        'user_interaction': {
            'N': 0.85,  # None
            'R': 0.62   # Required
        },
        'scope': {
            'U': 1.0,   # Unchanged
            'C': 1.0    # Changed
        },
        'confidentiality': {
            'N': 0.0,   # None
            'L': 0.22,  # Low
            'H': 0.56   # High
        },
        'integrity': {
            'N': 0.0,   # None
            'L': 0.22,  # Low
            'H': 0.56   # High
        },
        'availability': {
            'N': 0.0,   # None
            'L': 0.22,  # Low
            'H': 0.56   # High
        }
    }
    
    def __init__(self):
        self.round_up = lambda x: math.ceil(x * 10) / 10
    
    def calculate_base_score(self, vector: CVSSVector) -> float:
        """Calculate CVSS 3.1 Base Score"""
        # Get metric values
        av = self.METRIC_VALUES['attack_vector'][vector.attack_vector]
        ac = self.METRIC_VALUES['attack_complexity'][vector.attack_complexity]
        pr = self.METRIC_VALUES['privileges_required'][vector.privileges_required]
        ui = self.METRIC_VALUES['user_interaction'][vector.user_interaction]
        s = self.METRIC_VALUES['scope'][vector.scope]
        c = self.METRIC_VALUES['confidentiality'][vector.confidentiality]
        i = self.METRIC_VALUES['integrity'][vector.integrity]
        a = self.METRIC_VALUES['availability'][vector.availability]
        
        # Calculate Impact Sub Score (ISC)
        if vector.scope == 'U':  # Unchanged
            isc = 1 - ((1 - c) * (1 - i) * (1 - a))
        else:  # Changed
            isc = 7.52 * (c + i + a - c * i - c * a - i * a + c * i * a)
        
        # Calculate Exploitability Sub Score (ESC)
        if vector.scope == 'U':  # Unchanged
            esc = 8.22 * av * ac * pr * ui
        else:  # Changed
            esc = 8.22 * av * ac * pr * ui
        
        # Calculate Base Score
        if isc <= 0:
            base_score = 0.0
        elif vector.scope == 'U':  # Unchanged
            base_score = self.round_up(min(1.08 * (isc + esc), 10.0))
        else:  # Changed
            base_score = self.round_up(min(1.08 * (isc + esc), 10.0))
        
        return base_score
    
    def generate_justification(self, vector: CVSSVector) -> Dict[str, str]:
        """Generate justification for each CVSS metric"""
        justifications = {
            'attack_vector': {
                'N': 'Network accessible (remote exploitation possible)',
                'A': 'Adjacent network (same broadcast domain)',
                'L': 'Local access required',
                'P': 'Physical access required'
            },
            'attack_complexity': {
                'L': 'Low complexity (easy to exploit)',
                'H': 'High complexity (difficult to exploit)'
            },
            'privileges_required': {
                'N': 'No privileges required',
                'L': 'Low privileges required',
                'H': 'High privileges required'
            },
            'user_interaction': {
                'N': 'No user interaction required',
                'R': 'User interaction required'
            },
            'scope': {
                'U': 'Scope unchanged (affects same component)',
                'C': 'Scope changed (affects other components)'
            },
            'confidentiality': {
                'N': 'No confidentiality impact',
                'L': 'Low confidentiality impact',
                'H': 'High confidentiality impact'
            },
            'integrity': {
                'N': 'No integrity impact',
                'L': 'Low integrity impact',
                'H': 'High integrity impact'
            },
            'availability': {
                'N': 'No availability impact',
                'L': 'Low availability impact',
                'H': 'High availability impact'
            }
        }
        
        result = {}
        for metric, value in vector.dict().items():
            if metric in justifications and value in justifications[metric]:
                result[metric] = justifications[metric][value]
        
        return result
    
    def calculate_score(self, vector: CVSSVector) -> CVSSScore:
        """Calculate complete CVSS score with justification"""
        base_score = self.calculate_base_score(vector)
        justification = self.generate_justification(vector)
        
        return CVSSScore(
            vector=vector,
            base_score=base_score,
            justification=justification
        )
    
    def suggest_vector_from_analysis(self, analysis_data: Dict[str, Any]) -> CVSSVector:
        """Suggest CVSS vector based on analysis metadata"""
        vuln_type = analysis_data.get('vulnerability_type', 'unknown')
        validation_result = analysis_data.get('validation_result', {})
        
        # Default conservative values
        vector = CVSSVector(
            attack_vector='N',  # Network
            attack_complexity='L',  # Low
            privileges_required='N',  # None
            user_interaction='N',  # None
            scope='U',  # Unchanged
            confidentiality='L',  # Low
            integrity='L',  # Low
            availability='N'  # None
        )
        
        # Adjust based on vulnerability type
        if vuln_type in ['sql_injection', 'xss', 'ssrf']:
            vector.attack_vector = 'N'
            vector.attack_complexity = 'L'
            vector.privileges_required = 'N'
            vector.user_interaction = 'N'
        
        if vuln_type in ['authentication', 'authorization']:
            vector.privileges_required = 'L'
            vector.user_interaction = 'R'
        
        if vuln_type in ['command_injection', 'file_upload']:
            vector.confidentiality = 'H'
            vector.integrity = 'H'
            vector.availability = 'H'
        
        # Adjust based on validation results
        if validation_result.get('data_exposed'):
            vector.confidentiality = 'H'
        
        if validation_result.get('system_compromised'):
            vector.integrity = 'H'
            vector.availability = 'H'
        
        return vector
