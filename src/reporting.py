"""
Report generation for AI Threat Scanner
"""

import json
from datetime import datetime
from typing import List, Dict


class ReportGenerator:
    """Handles report generation in different formats"""
    
    def generate_report(self, results: List[Dict], format: str = "text") -> str:
        """Generate security report
        
        Args:
            results: List of scan results
            format: Output format ("text" or "json")
        """
        if format == "json":
            return self._generate_json_report(results)
        else:
            return self._generate_text_report(results)
    
    def _generate_json_report(self, results: List[Dict]) -> str:
        """Generate JSON format report"""
        return json.dumps(results, indent=2)
    
    def _generate_text_report(self, results: List[Dict]) -> str:
        """Generate human-readable text report"""
        total_scanned = len(results)
        threats_detected = sum(1 for r in results if not r["safe"])
        high_risk = sum(1 for r in results if r["risk_score"] >= 50)
        
        report = f"""
╔══════════════════════════════════════════════════╗
║                AI THREAT SCANNER                 ║
║               🔐 by Qu4ntik                      ║
╚══════════════════════════════════════════════════╝

📊 SCAN SUMMARY
├─ Total Prompts Scanned: {total_scanned}
├─ Threats Detected: {threats_detected}
├─ High Risk Prompts: {high_risk}
├─ Security Rate: {((total_scanned - threats_detected) / total_scanned * 100):.1f}%
└─ Scan Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

"""
        
        if threats_detected > 0:
            report += "⚠️  DETAILED THREAT ANALYSIS:\n"
            report += "=" * 50 + "\n"
            
            for i, result in enumerate(results, 1):
                if not result["safe"]:
                    risk_level = result["risk_level"]
                    risk_emoji = {"LOW": "🟡", "MEDIUM": "🟠", "HIGH": "🔴", "CRITICAL": "💀"}
                    
                    report += f"\n[{i}] {risk_emoji.get(risk_level, '⚠️')} {risk_level} RISK (Score: {result['risk_score']}/100)\n"
                    report += f"Context: {result.get('context', 'unknown').upper()}\n"
                    report += f"Prompt: {result['prompt'][:100]}{'...' if len(result['prompt']) > 100 else ''}\n"
                    
                    for threat in result["threats"]:
                        report += f"  └─ {threat['type'].upper()}: '{threat['pattern']}'\n"
                        report += f"     {threat['description']}\n"
                    report += "\n"
        else:
            report += "✅ ALL PROMPTS ARE SAFE!\n"
            report += "No security threats detected.\n"
        
        report += "\n" + "=" * 50
        report += "\n🔗 qu4ntik.xyz | 🐦 @Qu4ntik_xyz | 💻 GitHub: Qu4ntikxyz\n"
        report += "Breaking AI to build better defenses.\n"
        
        return report


# Convenience function for backward compatibility
def generate_report(results: List[Dict], format: str = "text") -> str:
    """Generate security report (backward compatibility function)"""
    generator = ReportGenerator()
    return generator.generate_report(results, format)
from typing import Optional
from .models import ReplayAnalysis, AttackTimeline, ThreatActor


class ConversationReportGenerator:
    """Generate comprehensive reports for conversation replay analysis"""
    
    def __init__(self):
        """Initialize the conversation report generator"""
        self.report_sections = []
        
    def generate_html_report(self, analysis: ReplayAnalysis) -> str:
        """
        Generate a comprehensive HTML report with visualizations.
        
        Args:
            analysis: ReplayAnalysis object with complete analysis results
            
        Returns:
            HTML string with complete report
        """
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Threat Scanner - Conversation Analysis Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }}
        .container {{
            background: white;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }}
        h1 {{
            color: #2d3748;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
            margin-bottom: 30px;
        }}
        h2 {{
            color: #4a5568;
            margin-top: 30px;
            border-left: 4px solid #764ba2;
            padding-left: 10px;
        }}
        .executive-summary {{
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }}
        .risk-badge {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            color: white;
            margin: 5px;
        }}
        .risk-critical {{ background: #e53e3e; }}
        .risk-high {{ background: #dd6b20; }}
        .risk-medium {{ background: #d69e2e; }}
        .risk-low {{ background: #38a169; }}
        .risk-safe {{ background: #48bb78; }}
        .timeline {{
            position: relative;
            padding: 20px 0;
            margin: 20px 0;
        }}
        .timeline-event {{
            position: relative;
            padding: 15px;
            margin: 10px 0;
            background: #f7fafc;
            border-left: 4px solid #667eea;
            border-radius: 4px;
        }}
        .timeline-event.critical {{
            border-left-color: #e53e3e;
            background: #fff5f5;
        }}
        .timeline-event.high {{
            border-left-color: #dd6b20;
            background: #fffdf7;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .stat-card {{
            background: #f7fafc;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
            border: 1px solid #e2e8f0;
        }}
        .stat-value {{
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }}
        .stat-label {{
            color: #718096;
            font-size: 0.9em;
            margin-top: 5px;
        }}
        .attack-chain {{
            background: #fef5e7;
            border: 2px solid #f39c12;
            border-radius: 8px;
            padding: 15px;
            margin: 10px 0;
        }}
        .threat-actor {{
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 15px;
            margin: 10px 0;
        }}
        .recommendations {{
            background: #e6fffa;
            border: 2px solid #38b2ac;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }}
        .recommendations ul {{
            margin: 10px 0;
            padding-left: 20px;
        }}
        .recommendations li {{
            margin: 5px 0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
        }}
        th {{
            background: #f7fafc;
            font-weight: bold;
            color: #4a5568;
        }}
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #e2e8f0;
            color: #718096;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 AI Threat Scanner - Conversation Analysis Report</h1>
        
        {self._generate_executive_summary_html(analysis)}
        {self._generate_statistics_html(analysis)}
        {self._generate_timeline_html(analysis)}
        {self._generate_attack_details_html(analysis)}
        {self._generate_threat_actors_html(analysis)}
        {self._generate_recommendations_html(analysis)}
        
        <div class="footer">
            <p>Generated by AI Threat Scanner v0.2.3 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>🔗 qu4ntik.xyz | Breaking AI to build better defenses</p>
        </div>
    </div>
</body>
</html>"""
        return html
    
    def _generate_executive_summary_html(self, analysis: ReplayAnalysis) -> str:
        """Generate executive summary section"""
        risk_level = analysis.risk_assessment.get('risk_level', 'UNKNOWN')
        risk_score = analysis.risk_assessment.get('overall_score', 0)
        
        return f"""
        <div class="executive-summary">
            <h2>Executive Summary</h2>
            <p><strong>Conversation ID:</strong> {analysis.conversation_id}</p>
            <p><strong>Analysis Period:</strong> {analysis.start_time or 'N/A'} to {analysis.end_time or 'N/A'}</p>
            <p><strong>Total Turns Analyzed:</strong> {analysis.total_turns}</p>
            <p><strong>Overall Risk Assessment:</strong> 
                <span class="risk-badge risk-{risk_level.lower()}">{risk_level} ({risk_score:.1f}/100)</span>
            </p>
            <p><strong>Key Findings:</strong></p>
            <ul>
                <li>{len(analysis.detected_attacks)} attack patterns detected</li>
                <li>{analysis.success_rate:.1f}% attack success rate</li>
                <li>Anomaly score: {analysis.anomaly_score:.1f}/100</li>
                <li>{len(analysis.threat_actors)} threat actor profile(s) identified</li>
            </ul>
        </div>
        """
    
    def _generate_statistics_html(self, analysis: ReplayAnalysis) -> str:
        """Generate statistics grid section"""
        attack_summary = analysis.get_attack_summary()
        critical_attacks = len(analysis.get_critical_attacks())
        
        return f"""
        <h2>📊 Key Statistics</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{len(analysis.detected_attacks)}</div>
                <div class="stat-label">Total Attacks</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{analysis.success_rate:.1f}%</div>
                <div class="stat-label">Success Rate</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{analysis.anomaly_score:.0f}</div>
                <div class="stat-label">Anomaly Score</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{critical_attacks}</div>
                <div class="stat-label">Critical Attacks</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{len(analysis.evolution_patterns)}</div>
                <div class="stat-label">Evolution Patterns</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{analysis.total_turns}</div>
                <div class="stat-label">Total Turns</div>
            </div>
        </div>
        """
    
    def _generate_timeline_html(self, analysis: ReplayAnalysis) -> str:
        """Generate attack timeline visualization"""
        html = "<h2>⏱️ Attack Timeline</h2>\n<div class='timeline'>\n"
        
        if not analysis.attack_timeline.events:
            html += "<p>No attack events detected in the conversation.</p>\n"
        else:
            for event in analysis.attack_timeline.events[:20]:  # Limit to 20 events for readability
                severity_class = event.get('severity', 'low')
                html += f"""
                <div class="timeline-event {severity_class}">
                    <strong>Turn {event['turn']}</strong>
                    {f" - {event['timestamp']}" if event.get('timestamp') else ""}
                    <br>
                    <strong>{event['event_type']}</strong>: {event['description']}
                </div>
                """
        
        html += "</div>\n"
        return html
    
    def _generate_attack_details_html(self, analysis: ReplayAnalysis) -> str:
        """Generate detailed attack analysis section"""
        html = "<h2>🎯 Attack Analysis</h2>\n"
        
        # Attack type distribution
        attack_summary = analysis.get_attack_summary()
        if attack_summary:
            html += "<h3>Attack Type Distribution</h3>\n"
            html += "<table>\n<tr><th>Attack Type</th><th>Count</th></tr>\n"
            for attack_type, count in attack_summary.items():
                html += f"<tr><td>{attack_type}</td><td>{count}</td></tr>\n"
            html += "</table>\n"
        
        # Evolution patterns
        if analysis.evolution_patterns:
            html += "<h3>Evolution Patterns</h3>\n"
            for pattern in analysis.evolution_patterns:
                html += f"""
                <div class="attack-chain">
                    <strong>Pattern:</strong> {pattern.get('pattern', 'Unknown')}<br>
                    <strong>Type:</strong> {pattern.get('type', 'N/A')}<br>
                    <strong>Details:</strong> {pattern}
                </div>
                """
        
        # Correlations
        if analysis.correlations:
            html += "<h3>Attack Correlations</h3>\n"
            html += "<pre>" + json.dumps(analysis.correlations, indent=2) + "</pre>\n"
        
        return html
    
    def _generate_threat_actors_html(self, analysis: ReplayAnalysis) -> str:
        """Generate threat actor profiles section"""
        html = "<h2>👤 Threat Actor Profiles</h2>\n"
        
        if not analysis.threat_actors:
            html += "<p>No threat actor profiles generated.</p>\n"
        else:
            for actor in analysis.threat_actors:
                profile = actor.get_profile_summary()
                html += f"""
                <div class="threat-actor">
                    <h3>Actor: {profile['actor_id']}</h3>
                    <p><strong>Sophistication:</strong> {profile['sophistication'].upper()}</p>
                    <p><strong>Success Rate:</strong> {profile['success_rate']:.1f}%</p>
                    <p><strong>Persistence Score:</strong> {profile['persistence']:.1f}/100</p>
                    <p><strong>Preferred Techniques:</strong> {', '.join(profile['top_techniques']) if profile['top_techniques'] else 'None identified'}</p>
                    <p><strong>Total Attacks:</strong> {profile['total_attacks']}</p>
                </div>
                """
        
        return html
    
    def _generate_recommendations_html(self, analysis: ReplayAnalysis) -> str:
        """Generate security recommendations section"""
        recommendations = analysis.risk_assessment.get('recommendations', [])
        
        html = """
        <div class="recommendations">
            <h2>🛡️ Security Recommendations</h2>
        """
        
        if recommendations:
            html += "<ul>\n"
            for rec in recommendations:
                html += f"<li>{rec}</li>\n"
            html += "</ul>\n"
        else:
            html += "<p>No specific recommendations at this time.</p>\n"
        
        html += "</div>\n"
        return html
    
    def generate_text_report(self, analysis: ReplayAnalysis) -> str:
        """
        Generate a comprehensive text report.
        
        Args:
            analysis: ReplayAnalysis object with complete analysis results
            
        Returns:
            Text string with complete report
        """
        report = f"""
╔══════════════════════════════════════════════════════════════════╗
║              AI THREAT SCANNER - CONVERSATION ANALYSIS           ║
║                        🔐 by Qu4ntik                             ║
╚══════════════════════════════════════════════════════════════════╝

📋 EXECUTIVE SUMMARY
{'='*60}
Conversation ID: {analysis.conversation_id}
Analysis Period: {analysis.start_time or 'N/A'} to {analysis.end_time or 'N/A'}
Duration: {f"{analysis.duration_seconds:.0f} seconds" if analysis.duration_seconds else 'N/A'}
Total Turns: {analysis.total_turns}

🎯 RISK ASSESSMENT
{'='*60}
Overall Risk Level: {analysis.risk_assessment.get('risk_level', 'UNKNOWN')}
Overall Risk Score: {analysis.risk_assessment.get('overall_score', 0):.1f}/100

Risk Factors:
"""
        
        risk_factors = analysis.risk_assessment.get('risk_factors', {})
        for factor, value in risk_factors.items():
            report += f"  • {factor.replace('_', ' ').title()}: {value:.1f}\n"
        
        report += f"""

📊 ATTACK STATISTICS
{'='*60}
Total Attacks Detected: {len(analysis.detected_attacks)}
Attack Success Rate: {analysis.success_rate:.1f}%
Anomaly Score: {analysis.anomaly_score:.1f}/100
Evolution Patterns: {len(analysis.evolution_patterns)}

Attack Type Distribution:
"""
        
        attack_summary = analysis.get_attack_summary()
        for attack_type, count in attack_summary.items():
            report += f"  • {attack_type}: {count}\n"
        
        report += f"""

⏱️ ATTACK TIMELINE
{'='*60}
"""
        
        if analysis.attack_timeline.events:
            report += analysis.attack_timeline.get_timeline_summary()
        else:
            report += "No attack events detected.\n"
        
        report += f"""

👤 THREAT ACTOR PROFILES
{'='*60}
"""
        
        if analysis.threat_actors:
            for actor in analysis.threat_actors:
                profile = actor.get_profile_summary()
                report += f"""
Actor ID: {profile['actor_id']}
  • Sophistication: {profile['sophistication'].upper()}
  • Success Rate: {profile['success_rate']:.1f}%
  • Persistence: {profile['persistence']:.1f}/100
  • Top Techniques: {', '.join(profile['top_techniques']) if profile['top_techniques'] else 'None'}
  • Total Attacks: {profile['total_attacks']}
"""
        else:
            report += "No threat actor profiles generated.\n"
        
        report += f"""

🛡️ SECURITY RECOMMENDATIONS
{'='*60}
"""
        
        recommendations = analysis.risk_assessment.get('recommendations', [])
        if recommendations:
            for i, rec in enumerate(recommendations, 1):
                report += f"{i}. {rec}\n"
        else:
            report += "No specific recommendations at this time.\n"
        
        report += f"""

{'='*60}
Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
🔗 qu4ntik.xyz | 🐦 @Qu4ntik_xyz | 💻 GitHub: Qu4ntikxyz
Breaking AI to build better defenses.
"""
        
        return report
    
    def generate_json_report(self, analysis: ReplayAnalysis) -> str:
        """
        Generate a JSON report.
        
        Args:
            analysis: ReplayAnalysis object with complete analysis results
            
        Returns:
            JSON string with complete report
        """
        report_data = {
            'conversation_id': analysis.conversation_id,
            'total_turns': analysis.total_turns,
            'start_time': analysis.start_time,
            'end_time': analysis.end_time,
            'duration_seconds': analysis.duration_seconds,
            'risk_assessment': analysis.risk_assessment,
            'detected_attacks': analysis.detected_attacks,
            'attack_summary': analysis.get_attack_summary(),
            'success_rate': analysis.success_rate,
            'anomaly_score': analysis.anomaly_score,
            'evolution_patterns': analysis.evolution_patterns,
            'correlations': analysis.correlations,
            'threat_actors': [actor.get_profile_summary() for actor in analysis.threat_actors],
            'timeline': {
                'events': analysis.attack_timeline.events,
                'summary': analysis.attack_timeline.get_timeline_summary()
            },
            'metadata': analysis.metadata,
            'generated_at': datetime.now().isoformat()
        }
        
        return json.dumps(report_data, indent=2)
    
    def generate_ascii_timeline(self, analysis: ReplayAnalysis) -> str:
        """
        Generate an ASCII art timeline visualization.
        
        Args:
            analysis: ReplayAnalysis object
            
        Returns:
            ASCII art timeline string
        """
        if not analysis.attack_timeline.events:
            return "No events to visualize.\n"
        
        timeline = "Attack Timeline Visualization:\n\n"
        
        # Sort events by turn number
        events = sorted(analysis.attack_timeline.events, key=lambda x: x['turn'])
        
        # Create timeline
        max_turn = max(e['turn'] for e in events)
        
        # Create severity markers
        severity_markers = {
            'critical': '💀',
            'high': '🔴',
            'medium': '🟠',
            'low': '🟡'
        }
        
        # Build timeline
        timeline += "Turn:  "
        for i in range(0, min(max_turn + 1, 50), 5):  # Limit to 50 turns for display
            timeline += f"{i:5d} "
        timeline += "\n"
        
        timeline += "       "
        for i in range(0, min(max_turn + 1, 50), 5):
            timeline += "  |   "
        timeline += "\n"
        
        timeline += "Events:"
        event_line = "       "
        for turn in range(min(max_turn + 1, 50)):
            event_at_turn = next((e for e in events if e['turn'] == turn), None)
            if event_at_turn:
                marker = severity_markers.get(event_at_turn.get('severity', 'low'), '•')
                event_line += marker
            else:
                event_line += "-"
        
        timeline += event_line + "\n\n"
        
        # Add legend
        timeline += "Legend:\n"
        for severity, marker in severity_markers.items():
            timeline += f"  {marker} = {severity.upper()}\n"
        timeline += "  - = No event\n"
        
        return timeline
    
    def export_to_pdf(self, analysis: ReplayAnalysis, output_path: str) -> bool:
        """
        Export report to PDF (requires reportlab, falls back to HTML if not available).
        
        Args:
            analysis: ReplayAnalysis object
            output_path: Path to save the PDF file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Try to use reportlab if available
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.lib import colors
            
            # Create PDF document
            doc = SimpleDocTemplate(output_path, pagesize=letter)
            story = []
            styles = getSampleStyleSheet()
            
            # Title
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#667eea'),
                spaceAfter=30
            )
            story.append(Paragraph("AI Threat Scanner - Conversation Analysis Report", title_style))
            story.append(Spacer(1, 0.3*inch))
            
            # Executive Summary
            story.append(Paragraph("Executive Summary", styles['Heading2']))
            summary_text = f"""
            <para>
            <b>Conversation ID:</b> {analysis.conversation_id}<br/>
            <b>Total Turns:</b> {analysis.total_turns}<br/>
            <b>Risk Level:</b> {analysis.risk_assessment.get('risk_level', 'UNKNOWN')}<br/>
            <b>Risk Score:</b> {analysis.risk_assessment.get('overall_score', 0):.1f}/100<br/>
            <b>Attacks Detected:</b> {len(analysis.detected_attacks)}<br/>
            <b>Success Rate:</b> {analysis.success_rate:.1f}%<br/>
            </para>
            """
            story.append(Paragraph(summary_text, styles['Normal']))
            story.append(Spacer(1, 0.2*inch))
            
            # Build and save PDF
            doc.build(story)
            return True
            
        except ImportError:
            # Fallback to HTML export
            html_content = self.generate_html_report(analysis)
            html_path = output_path.replace('.pdf', '.html')
            
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            print(f"Note: reportlab not installed. Report saved as HTML: {html_path}")
            return True
            
        except Exception as e:
            print(f"Error generating PDF report: {e}")
            return False