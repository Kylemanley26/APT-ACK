import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from outputs.terminal_view import TerminalDashboard
from outputs.export import DataExporter
from storage.models import SeverityLevel

def main():
    dashboard = TerminalDashboard()
    exporter = DataExporter()
    
    if len(sys.argv) < 2:
        # Default: show summary and critical alerts
        dashboard.show_summary()
        dashboard.show_critical_alerts()
        return
    
    command = sys.argv[1]
    
    if command == 'summary':
        dashboard.show_summary()
    
    elif command == 'critical':
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 10
        dashboard.show_critical_alerts(limit)
    
    elif command == 'severity':
        if len(sys.argv) < 3:
            print("Usage: python scripts/dashboard.py severity [critical|high|medium|low|info]")
            return
        severity_map = {
            'critical': SeverityLevel.CRITICAL,
            'high': SeverityLevel.HIGH,
            'medium': SeverityLevel.MEDIUM,
            'low': SeverityLevel.LOW,
            'info': SeverityLevel.INFO
        }
        severity = severity_map.get(sys.argv[2].lower())
        if severity:
            dashboard.show_by_severity(severity)
    
    elif command == 'tag':
        if len(sys.argv) < 3:
            print("Usage: python scripts/dashboard.py tag [tag_name]")
            return
        dashboard.show_by_tag(sys.argv[2])
    
    elif command == 'recent':
        hours = int(sys.argv[2]) if len(sys.argv) > 2 else 24
        dashboard.show_recent(hours)
    
    elif command == 'export':
        export_type = sys.argv[2] if len(sys.argv) > 2 else 'json'
        if export_type == 'json':
            exporter.export_to_json()
        elif export_type == 'csv':
            exporter.export_to_csv()
        elif export_type == 'iocs':
            exporter.export_iocs_csv()
        else:
            print("Usage: python scripts/dashboard.py export [json|csv|iocs]")
    
    else:
        print("Unknown command. Available commands:")
        print("  summary         - Show overview statistics")
        print("  critical [n]    - Show critical/high severity items (default: 10)")
        print("  severity [level]- Filter by severity level")
        print("  tag [name]      - Filter by tag name")
        print("  recent [hours]  - Show recent items (default: 24h)")
        print("  export [type]   - Export data (json|csv|iocs)")

if __name__ == "__main__":
    main()