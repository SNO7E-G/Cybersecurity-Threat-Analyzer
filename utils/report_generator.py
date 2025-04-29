import os
import logging
import datetime
from io import BytesIO
from django.conf import settings
from django.db.models import Count
from django.utils import timezone
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak

from core.models import NetworkScan, Packet, Threat, Vulnerability

logger = logging.getLogger('core')

class ReportGenerator:
    """Utility class for generating scan reports in various formats."""
    
    def __init__(self, report_obj):
        """
        Initialize the report generator.
        
        Args:
            report_obj: Report model instance
        """
        self.report = report_obj
        self.scan = report_obj.scan
        self.report_type = report_obj.report_type
        self.title = report_obj.title
        self.description = report_obj.description
        self.created_by = report_obj.created_by
        
        # Set up paths
        reports_dir = os.path.join(settings.MEDIA_ROOT, 'reports')
        os.makedirs(reports_dir, exist_ok=True)
        
        # Report filename
        timestamp = timezone.now().strftime('%Y%m%d%H%M%S')
        self.filename = f"{self.scan.id}_{self.report_type}_{timestamp}.pdf"
        self.filepath = os.path.join(reports_dir, self.filename)
    
    def generate(self):
        """
        Generate the report and save it to disk.
        
        Returns:
            Path to the generated report file
        """
        try:
            # Generate the appropriate report type
            if self.report_type == 'summary':
                self._generate_summary_report()
            elif self.report_type == 'detailed':
                self._generate_detailed_report()
            elif self.report_type == 'executive':
                self._generate_executive_report()
            elif self.report_type == 'compliance':
                self._generate_compliance_report()
            else:
                self._generate_summary_report()  # Default to summary
            
            # Update the report object with the file path
            self.report.report_file.name = os.path.join('reports', self.filename)
            self.report.save(update_fields=['report_file'])
            
            logger.info(f"Generated report: {self.report.title} ({self.filename})")
            
            return self.filepath
            
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")
            return None
    
    def _generate_summary_report(self):
        """Generate a summary report with key statistics."""
        buffer = BytesIO()
        
        # Create the PDF document
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        elements = []
        
        # Styles
        styles = getSampleStyleSheet()
        title_style = styles['Title']
        heading_style = styles['Heading1']
        heading2_style = styles['Heading2']
        normal_style = styles['Normal']
        
        # Title
        elements.append(Paragraph(self.title, title_style))
        elements.append(Spacer(1, 12))
        
        # Description
        if self.description:
            elements.append(Paragraph("Description", heading_style))
            elements.append(Paragraph(self.description, normal_style))
            elements.append(Spacer(1, 12))
        
        # Scan Information
        elements.append(Paragraph("Scan Information", heading_style))
        scan_data = [
            ["Name", self.scan.name],
            ["Target Network", self.scan.target_network],
            ["Type", self.scan.scan_type],
            ["Status", self.scan.status],
            ["Start Time", self.scan.start_time.strftime('%Y-%m-%d %H:%M:%S')],
        ]
        
        if self.scan.end_time:
            scan_data.append(["End Time", self.scan.end_time.strftime('%Y-%m-%d %H:%M:%S')])
            
            # Calculate duration if end time exists
            duration = self.scan.end_time - self.scan.start_time
            hours, remainder = divmod(duration.total_seconds(), 3600)
            minutes, seconds = divmod(remainder, 60)
            scan_data.append(["Duration", f"{int(hours):02}:{int(minutes):02}:{int(seconds):02}"])
        
        scan_table = Table(scan_data, colWidths=[100, 300])
        scan_table.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(scan_table)
        elements.append(Spacer(1, 12))
        
        # Packet Statistics
        elements.append(Paragraph("Network Traffic Summary", heading_style))
        
        packet_count = Packet.objects.filter(scan=self.scan).count()
        protocol_counts = Packet.objects.filter(scan=self.scan).values('protocol').annotate(
            count=Count('id')
        ).order_by('-count')
        
        elements.append(Paragraph(f"Total Packets Captured: {packet_count}", normal_style))
        elements.append(Spacer(1, 6))
        
        if protocol_counts:
            elements.append(Paragraph("Protocol Distribution", heading2_style))
            protocol_data = [["Protocol", "Count", "Percentage"]]
            
            for item in protocol_counts:
                protocol = item['protocol']
                count = item['count']
                percentage = (count / packet_count) * 100 if packet_count > 0 else 0
                protocol_data.append([protocol, str(count), f"{percentage:.2f}%"])
            
            protocol_table = Table(protocol_data, colWidths=[100, 100, 100])
            protocol_table.setStyle(TableStyle([
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('ALIGN', (1, 1), (-1, -1), 'RIGHT'),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ]))
            elements.append(protocol_table)
            elements.append(Spacer(1, 12))
        
        # Threat Summary
        elements.append(Paragraph("Threat Summary", heading_style))
        
        threat_count = Threat.objects.filter(scan=self.scan).count()
        severity_counts = Threat.objects.filter(scan=self.scan).values('severity').annotate(
            count=Count('id')
        ).order_by('-count')
        
        elements.append(Paragraph(f"Total Threats Detected: {threat_count}", normal_style))
        elements.append(Spacer(1, 6))
        
        if severity_counts:
            elements.append(Paragraph("Threats by Severity", heading2_style))
            severity_data = [["Severity", "Count", "Percentage"]]
            
            for item in severity_counts:
                severity = item['severity']
                count = item['count']
                percentage = (count / threat_count) * 100 if threat_count > 0 else 0
                severity_data.append([severity.capitalize(), str(count), f"{percentage:.2f}%"])
            
            severity_table = Table(severity_data, colWidths=[100, 100, 100])
            severity_table.setStyle(TableStyle([
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('ALIGN', (1, 1), (-1, -1), 'RIGHT'),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ]))
            elements.append(severity_table)
            elements.append(Spacer(1, 12))
        
        # Report Footer
        elements.append(Paragraph(f"Report generated on {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
        elements.append(Paragraph(f"Generated by: {self.created_by.username}", normal_style))
        
        # Build the PDF document
        doc.build(elements)
        
        # Save the PDF to disk
        with open(self.filepath, 'wb') as f:
            f.write(buffer.getvalue())
    
    def _generate_detailed_report(self):
        """Generate a detailed report with comprehensive information."""
        buffer = BytesIO()
        
        # Create the PDF document
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        elements = []
        
        # Styles
        styles = getSampleStyleSheet()
        title_style = styles['Title']
        heading_style = styles['Heading1']
        heading2_style = styles['Heading2']
        heading3_style = styles['Heading3']
        normal_style = styles['Normal']
        
        # Title
        elements.append(Paragraph(self.title, title_style))
        elements.append(Spacer(1, 12))
        
        # Description
        if self.description:
            elements.append(Paragraph("Description", heading_style))
            elements.append(Paragraph(self.description, normal_style))
            elements.append(Spacer(1, 12))
        
        # Scan Information (same as summary report)
        elements.append(Paragraph("Scan Information", heading_style))
        scan_data = [
            ["Name", self.scan.name],
            ["Target Network", self.scan.target_network],
            ["Type", self.scan.scan_type],
            ["Status", self.scan.status],
            ["Start Time", self.scan.start_time.strftime('%Y-%m-%d %H:%M:%S')],
        ]
        
        if self.scan.end_time:
            scan_data.append(["End Time", self.scan.end_time.strftime('%Y-%m-%d %H:%M:%S')])
            
            # Calculate duration if end time exists
            duration = self.scan.end_time - self.scan.start_time
            hours, remainder = divmod(duration.total_seconds(), 3600)
            minutes, seconds = divmod(remainder, 60)
            scan_data.append(["Duration", f"{int(hours):02}:{int(minutes):02}:{int(seconds):02}"])
        
        scan_table = Table(scan_data, colWidths=[100, 300])
        scan_table.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(scan_table)
        elements.append(Spacer(1, 12))
        
        # Detailed Threat Analysis
        elements.append(Paragraph("Detailed Threat Analysis", heading_style))
        
        threats = Threat.objects.filter(scan=self.scan).order_by('-severity', '-timestamp')
        
        if threats.exists():
            elements.append(Paragraph(f"Total Threats Detected: {threats.count()}", normal_style))
            elements.append(Spacer(1, 12))
            
            # Group threats by severity
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
            current_severity = None
            
            for threat in threats:
                # Add a page break between severity levels
                if current_severity != threat.severity and current_severity is not None:
                    elements.append(PageBreak())
                
                current_severity = threat.severity
                
                # Severity heading
                if current_severity != threat.severity:
                    elements.append(Paragraph(f"{threat.severity.capitalize()} Severity Threats", heading2_style))
                
                # Threat details
                elements.append(Paragraph(f"Threat: {threat.threat_type}", heading3_style))
                
                threat_data = [
                    ["Detected", threat.timestamp.strftime('%Y-%m-%d %H:%M:%S')],
                    ["Source IP", str(threat.source_ip) if threat.source_ip else "N/A"],
                    ["Destination IP", str(threat.destination_ip) if threat.destination_ip else "N/A"],
                    ["Status", threat.status],
                    ["Description", threat.description],
                ]
                
                if threat.affected_system:
                    threat_data.append(["Affected System", threat.affected_system])
                
                if threat.mitigated_by:
                    threat_data.append(["Mitigated By", threat.mitigated_by.username])
                    threat_data.append(["Mitigated At", threat.mitigated_at.strftime('%Y-%m-%d %H:%M:%S')])
                
                threat_table = Table(threat_data, colWidths=[100, 300])
                threat_table.setStyle(TableStyle([
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ]))
                elements.append(threat_table)
                elements.append(Spacer(1, 12))
        else:
            elements.append(Paragraph("No threats detected during this scan.", normal_style))
            elements.append(Spacer(1, 12))
        
        # Vulnerability Analysis
        elements.append(PageBreak())
        elements.append(Paragraph("Vulnerability Analysis", heading_style))
        
        vulnerabilities = Vulnerability.objects.filter(
            vulnerability_scan__scan=self.scan
        ).order_by('-severity')
        
        if vulnerabilities.exists():
            elements.append(Paragraph(f"Total Vulnerabilities Found: {vulnerabilities.count()}", normal_style))
            elements.append(Spacer(1, 12))
            
            # Group vulnerabilities by severity
            current_severity = None
            
            for vuln in vulnerabilities:
                # Add a page break between severity levels
                if current_severity != vuln.severity and current_severity is not None:
                    elements.append(PageBreak())
                
                current_severity = vuln.severity
                
                # Severity heading
                if current_severity != vuln.severity:
                    elements.append(Paragraph(f"{vuln.severity.capitalize()} Severity Vulnerabilities", heading2_style))
                
                # Vulnerability details
                cve_id = vuln.cve_id if vuln.cve_id else "No CVE"
                elements.append(Paragraph(f"{vuln.name} ({cve_id})", heading3_style))
                
                vuln_data = [
                    ["Severity", vuln.severity.capitalize()],
                    ["Affected Service", vuln.affected_service if vuln.affected_service else "N/A"],
                ]
                
                if vuln.affected_port:
                    vuln_data.append(["Affected Port", str(vuln.affected_port)])
                
                vuln_table = Table(vuln_data, colWidths=[100, 300])
                vuln_table.setStyle(TableStyle([
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ]))
                elements.append(vuln_table)
                elements.append(Spacer(1, 6))
                
                # Description and remediation
                elements.append(Paragraph("Description:", normal_style))
                elements.append(Paragraph(vuln.description, normal_style))
                elements.append(Spacer(1, 6))
                
                if vuln.remediation:
                    elements.append(Paragraph("Remediation:", normal_style))
                    elements.append(Paragraph(vuln.remediation, normal_style))
                
                elements.append(Spacer(1, 12))
        else:
            elements.append(Paragraph("No vulnerabilities found during this scan.", normal_style))
            elements.append(Spacer(1, 12))
        
        # Report Footer
        elements.append(PageBreak())
        elements.append(Paragraph("Report Summary", heading_style))
        elements.append(Paragraph(f"This report provides a detailed analysis of the network scan '{self.scan.name}' conducted on {self.scan.target_network}.", normal_style))
        elements.append(Spacer(1, 12))
        elements.append(Paragraph(f"Report generated on {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
        elements.append(Paragraph(f"Generated by: {self.created_by.username}", normal_style))
        
        # Build the PDF document
        doc.build(elements)
        
        # Save the PDF to disk
        with open(self.filepath, 'wb') as f:
            f.write(buffer.getvalue())
    
    def _generate_executive_report(self):
        """Generate an executive summary report with highlights and recommendations."""
        # Implement similar to summary report but with executive focus
        self._generate_summary_report()  # Placeholder
    
    def _generate_compliance_report(self):
        """Generate a compliance-focused report."""
        # Implement similar to detailed report but with compliance focus
        self._generate_detailed_report()  # Placeholder 