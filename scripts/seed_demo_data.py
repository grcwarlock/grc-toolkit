"""
Seed script — full-library demo data for GRC Warlock.
Includes all 324 NIST 800-53 Rev5 base controls, full SOC 2 TSC (64 criteria),
full ISO 27001:2022 (93 controls), full HIPAA safeguards, and all 110 CMMC Level 2 practices.
Each control receives 1-3 automated checks in the latest run.

Run: python -m scripts.seed_demo_data
"""

from __future__ import annotations

import random
import uuid
from datetime import UTC, date, datetime, timedelta

from api.routers.auth import _hash_password
from db.models import (
    AssessmentResultRecord,
    AssessmentRun,
    DataSource,
    EvidenceRecord,
    PolicyViolation,
    User,
    VendorRecord,
)
from db.session import get_session_factory, init_db

FRAMEWORKS = ["nist_800_53", "soc2", "iso27001", "hipaa", "cmmc_l2"]

# ─── Full NIST 800-53 Rev5 (324 base controls) ───────────────────────────────
NIST_CONTROLS = [
    ("AC-1","Policy and Procedures"),("AC-2","Account Management"),
    ("AC-3","Access Enforcement"),("AC-4","Information Flow Enforcement"),
    ("AC-5","Separation of Duties"),("AC-6","Least Privilege"),
    ("AC-7","Unsuccessful Logon Attempts"),("AC-8","System Use Notification"),
    ("AC-9","Previous Logon Notification"),("AC-10","Concurrent Session Control"),
    ("AC-11","Device Lock"),("AC-12","Session Termination"),
    ("AC-13","Supervision and Review — Access Control"),
    ("AC-14","Permitted Actions Without Identification or Authentication"),
    ("AC-15","Automated Marking"),("AC-16","Security and Privacy Attributes"),
    ("AC-17","Remote Access"),("AC-18","Wireless Access"),
    ("AC-19","Access Control for Mobile Devices"),
    ("AC-20","Use of External Systems"),("AC-21","Information Sharing"),
    ("AC-22","Publicly Accessible Content"),("AC-23","Data Mining Protection"),
    ("AC-24","Access Control Decisions"),("AC-25","Reference Monitor"),
    ("AT-1","Policy and Procedures"),("AT-2","Literacy Training and Awareness"),
    ("AT-3","Role-based Training"),("AT-4","Training Records"),
    ("AT-5","Contacts with Security Groups and Associations"),
    ("AT-6","Training Feedback"),
    ("AU-1","Policy and Procedures"),("AU-2","Event Logging"),
    ("AU-3","Content of Audit Records"),("AU-4","Audit Log Storage Capacity"),
    ("AU-5","Response to Audit Logging Process Failures"),
    ("AU-6","Audit Record Review, Analysis, and Reporting"),
    ("AU-7","Audit Record Reduction and Report Generation"),
    ("AU-8","Time Stamps"),("AU-9","Protection of Audit Information"),
    ("AU-10","Non-repudiation"),("AU-11","Audit Record Retention"),
    ("AU-12","Audit Record Generation"),
    ("AU-13","Monitoring for Information Disclosure"),
    ("AU-14","Session Audit"),("AU-15","Alternate Audit Logging Capability"),
    ("AU-16","Cross-organizational Audit Logging"),
    ("CA-1","Policy and Procedures"),("CA-2","Control Assessments"),
    ("CA-3","Information Exchange"),("CA-4","Security Certification"),
    ("CA-5","Plan of Action and Milestones"),("CA-6","Authorization"),
    ("CA-7","Continuous Monitoring"),("CA-8","Penetration Testing"),
    ("CA-9","Internal System Connections"),
    ("CM-1","Policy and Procedures"),("CM-2","Baseline Configuration"),
    ("CM-3","Configuration Change Control"),("CM-4","Impact Analyses"),
    ("CM-5","Access Restrictions for Change"),
    ("CM-6","Configuration Settings"),("CM-7","Least Functionality"),
    ("CM-8","System Component Inventory"),
    ("CM-9","Configuration Management Plan"),
    ("CM-10","Software Usage Restrictions"),
    ("CM-11","User-installed Software"),("CM-12","Information Location"),
    ("CM-13","Data Action Mapping"),("CM-14","Signed Components"),
    ("CP-1","Policy and Procedures"),("CP-2","Contingency Plan"),
    ("CP-3","Contingency Training"),("CP-4","Contingency Plan Testing"),
    ("CP-5","Contingency Plan Update"),("CP-6","Alternate Storage Site"),
    ("CP-7","Alternate Processing Site"),
    ("CP-8","Telecommunications Services"),("CP-9","System Backup"),
    ("CP-10","System Recovery and Reconstitution"),
    ("CP-11","Alternate Communications Protocols"),("CP-12","Safe Mode"),
    ("CP-13","Alternative Security Mechanisms"),
    ("IA-1","Policy and Procedures"),
    ("IA-2","Identification and Authentication (Organizational Users)"),
    ("IA-3","Device Identification and Authentication"),
    ("IA-4","Identifier Management"),("IA-5","Authenticator Management"),
    ("IA-6","Authentication Feedback"),("IA-7","Cryptographic Module Authentication"),
    ("IA-8","Identification and Authentication (Non-Organizational Users)"),
    ("IA-9","Service Identification and Authentication"),
    ("IA-10","Adaptive Authentication"),
    ("IA-11","Re-authentication"),("IA-12","Identity Proofing"),
    ("IA-13","Identity Provider"),
    ("IR-1","Policy and Procedures"),("IR-2","Incident Response Training"),
    ("IR-3","Incident Response Testing"),("IR-4","Incident Handling"),
    ("IR-5","Incident Monitoring"),("IR-6","Incident Reporting"),
    ("IR-7","Incident Response Assistance"),
    ("IR-8","Incident Response Plan"),("IR-9","Information Spillage Response"),
    ("IR-10","Integrated Information Security Analysis Team"),
    ("MA-1","Policy and Procedures"),("MA-2","Controlled Maintenance"),
    ("MA-3","Maintenance Tools"),("MA-4","Nonlocal Maintenance"),
    ("MA-5","Maintenance Personnel"),("MA-6","Timely Maintenance"),
    ("MA-7","Field Maintenance"),
    ("MP-1","Policy and Procedures"),("MP-2","Media Access"),
    ("MP-3","Media Marking"),("MP-4","Media Storage"),
    ("MP-5","Media Transport"),("MP-6","Media Sanitization"),
    ("MP-7","Media Use"),("MP-8","Media Downgrading"),
    ("PE-1","Policy and Procedures"),("PE-2","Physical Access Authorizations"),
    ("PE-3","Physical Access Control"),("PE-4","Access Control for Transmission"),
    ("PE-5","Access Control for Output Devices"),
    ("PE-6","Monitoring Physical Access"),("PE-7","Visitor Control"),
    ("PE-8","Visitor Access Records"),("PE-9","Power Equipment and Cabling"),
    ("PE-10","Emergency Shutoff"),("PE-11","Emergency Power"),
    ("PE-12","Emergency Lighting"),("PE-13","Fire Protection"),
    ("PE-14","Environmental Controls"),("PE-15","Water Damage Protection"),
    ("PE-16","Delivery and Removal"),("PE-17","Alternate Work Site"),
    ("PE-18","Location of System Components"),
    ("PE-19","Information Leakage"),("PE-20","Asset Monitoring and Tracking"),
    ("PE-21","Electromagnetic Pulse Protection"),
    ("PE-22","Component Marking"),("PE-23","Facility Location"),
    ("PL-1","Policy and Procedures"),("PL-2","System Security and Privacy Plans"),
    ("PL-3","System Security and Privacy Plan Update"),
    ("PL-4","Rules of Behavior"),("PL-5","Privacy Impact Assessment"),
    ("PL-6","Security- and Privacy-related Plans"),
    ("PL-7","Concept of Operations"),("PL-8","Security and Privacy Architectures"),
    ("PL-9","Central Management"),("PL-10","Baseline Selection"),
    ("PL-11","Baseline Tailoring"),
    ("PM-1","Information Security Program Plan"),
    ("PM-2","Information Security Program Leadership Role"),
    ("PM-3","Information Security and Privacy Resources"),
    ("PM-4","Plan of Action and Milestones Process"),
    ("PM-5","System Inventory"),("PM-6","Measures of Performance"),
    ("PM-7","Enterprise Architecture"),("PM-8","Critical Infrastructure Plan"),
    ("PM-9","Risk Management Strategy"),
    ("PM-10","Authorization Process"),("PM-11","Mission and Business Process Definition"),
    ("PM-12","Insider Threat Program"),
    ("PM-13","Security and Privacy Workforce"),("PM-14","Testing, Training, and Monitoring"),
    ("PM-15","Security and Privacy Groups and Associations"),
    ("PM-16","Threat Awareness Program"),
    ("PM-17","Protecting Controlled Unclassified Information"),
    ("PM-18","Privacy Program Plan"),("PM-19","Privacy Program Leadership Role"),
    ("PM-20","Dissemination of Privacy Program Information"),
    ("PM-21","Accounting of Disclosures"),
    ("PM-22","Personally Identifiable Information Quality Management"),
    ("PM-23","Data Governance Body"),("PM-24","Data Integrity Board"),
    ("PM-25","Minimization of Personally Identifiable Information Used in Testing, Training, and Research"),
    ("PM-26","Complaint Management"),
    ("PM-27","Privacy Reporting"),("PM-28","Risk Framing"),
    ("PM-29","Risk Management Program Leadership Roles"),
    ("PM-30","Supply Chain Risk Management Strategy"),
    ("PM-31","Continuous Monitoring Strategy"),
    ("PM-32","Purposing"),
    ("PS-1","Policy and Procedures"),("PS-2","Position Risk Designation"),
    ("PS-3","Personnel Screening"),("PS-4","Personnel Termination"),
    ("PS-5","Personnel Transfer"),("PS-6","Access Agreements"),
    ("PS-7","External Personnel Security"),("PS-8","Personnel Sanctions"),
    ("PS-9","Position Descriptions"),
    ("PT-1","Policy and Procedures"),
    ("PT-2","Authority to Process Personally Identifiable Information"),
    ("PT-3","Personally Identifiable Information Processing Purposes"),
    ("PT-4","Consent"),("PT-5","Privacy Notice"),
    ("PT-6","System of Records Notice"),("PT-7","Specific Categories of Personally Identifiable Information"),
    ("PT-8","Computer Matching Requirements"),
    ("RA-1","Policy and Procedures"),("RA-2","Security Categorization"),
    ("RA-3","Risk Assessment"),("RA-4","Risk Assessment Update"),
    ("RA-5","Vulnerability Monitoring and Scanning"),
    ("RA-6","Technical Surveillance Countermeasures Survey"),
    ("RA-7","Risk Response"),("RA-8","Privacy Impact Assessments"),
    ("RA-9","Criticality Analysis"),("RA-10","Threat Hunting"),
    ("SA-1","Policy and Procedures"),("SA-2","Allocation of Resources"),
    ("SA-3","System Development Life Cycle"),
    ("SA-4","Acquisition Process"),("SA-5","System Documentation"),
    ("SA-6","Software License Management"),
    ("SA-7","User-installed Software"),
    ("SA-8","Security and Privacy Engineering Principles"),
    ("SA-9","External System Services"),
    ("SA-10","Developer Configuration Management"),
    ("SA-11","Developer Testing and Evaluation"),
    ("SA-12","Memory Protection"),("SA-13","Trustworthiness"),
    ("SA-14","Criticality Analysis"),
    ("SA-15","Development Process, Standards, and Tools"),
    ("SA-16","Developer-provided Training"),
    ("SA-17","Developer Security and Privacy Architecture and Design"),
    ("SA-18","Tamper Resistance and Detection"),
    ("SA-19","Component Authenticity"),("SA-20","Customized Development of Critical Components"),
    ("SA-21","Developer Screening"),("SA-22","Unsupported System Components"),
    ("SA-23","Specialization"),("SA-24","Component Provenance"),
    ("SC-1","Policy and Procedures"),("SC-2","Separation of System and User Functionality"),
    ("SC-3","Security Function Isolation"),("SC-4","Information in Shared System Resources"),
    ("SC-5","Denial of Service Protection"),
    ("SC-6","Resource Availability"),("SC-7","Boundary Protection"),
    ("SC-8","Transmission Confidentiality and Integrity"),
    ("SC-9","Transmission Confidentiality"),("SC-10","Network Disconnect"),
    ("SC-11","Trusted Path"),("SC-12","Cryptographic Key Establishment and Management"),
    ("SC-13","Cryptographic Protection"),
    ("SC-14","Public Access Protections"),("SC-15","Collaborative Computing Devices and Applications"),
    ("SC-16","Transmission of Security and Privacy Attributes"),
    ("SC-17","Public Key Infrastructure Certificates"),
    ("SC-18","Mobile Code"),("SC-19","Voice over Internet Protocol"),
    ("SC-20","Secure Name/Address Resolution Service (Authoritative Source)"),
    ("SC-21","Secure Name/Address Resolution Service (Recursive or Caching Resolver)"),
    ("SC-22","Architecture and Provisioning for Name/Address Resolution Service"),
    ("SC-23","Session Authenticity"),
    ("SC-24","Fail in Known State"),("SC-25","Thin Nodes"),
    ("SC-26","Decoys"),("SC-27","Platform-independent Applications"),
    ("SC-28","Protection of Information at Rest"),
    ("SC-29","Heterogeneity"),("SC-30","Concealment and Misdirection"),
    ("SC-31","Covert Channel Analysis"),("SC-32","System Partitioning"),
    ("SC-33","Transmission Preparation Integrity"),("SC-34","Non-modifiable Executable Programs"),
    ("SC-35","External Malicious Code Identification"),
    ("SC-36","Distributed Processing and Storage"),("SC-37","Out-of-band Channels"),
    ("SC-38","Operations Security"),("SC-39","Process Isolation"),
    ("SC-40","Wireless Link Protection"),("SC-41","Port and I/O Device Access"),
    ("SC-42","Sensor Capability and Data"),("SC-43","Usage Restrictions"),
    ("SC-44","Detonation Chambers"),("SC-45","System Time Synchronization"),
    ("SC-46","Cross Domain Policy Enforcement"),
    ("SC-47","Alternate Communications Paths"),("SC-48","Sensor Relocation"),
    ("SC-49","Hardware-enforced Separation and Policy Enforcement"),
    ("SC-50","Software-enforced Separation and Policy Enforcement"),
    ("SC-51","Hardware-based Protection"),
    ("SI-1","Policy and Procedures"),("SI-2","Flaw Remediation"),
    ("SI-3","Malicious Code Protection"),("SI-4","System Monitoring"),
    ("SI-5","Security Alerts, Advisories, and Directives"),
    ("SI-6","Security and Privacy Function Verification"),
    ("SI-7","Software, Firmware, and Information Integrity"),
    ("SI-8","Spam Protection"),("SI-9","Information Input Restrictions"),
    ("SI-10","Information Input Validation"),("SI-11","Error Handling"),
    ("SI-12","Information Management and Retention"),
    ("SI-13","Predictable Failure Prevention"),("SI-14","Non-persistence"),
    ("SI-15","Information Output Filtering"),("SI-16","Memory Protection"),
    ("SI-17","Fail-safe Procedures"),
    ("SI-18","Personally Identifiable Information Quality Operations"),
    ("SI-19","De-identification"),("SI-20","Tainting"),
    ("SI-21","Information Refresh"),("SI-22","Information Diversity"),
    ("SI-23","Information Fragmentation"),
    ("SR-1","Policy and Procedures"),
    ("SR-2","Supply Chain Risk Management Plan"),
    ("SR-3","Supply Chain Controls and Processes"),("SR-4","Provenance"),
    ("SR-5","Acquisition Strategies, Tools, and Methods"),
    ("SR-6","Supplier Assessments and Reviews"),
    ("SR-7","Supply Chain Operations Security"),("SR-8","Notification Agreements"),
    ("SR-9","Tamper Resistance and Detection"),
    ("SR-10","Inspection of Systems or Components"),
    ("SR-11","Component Authenticity"),("SR-12","Component Disposal"),
]

# ─── Full SOC 2 Type II Trust Services Criteria (64) ─────────────────────────
SOC2_CONTROLS = [
    ("CC1.1","COSO Principle 1 - Demonstrates Commitment to Integrity and Ethical Values"),
    ("CC1.2","COSO Principle 2 - Exercises Oversight Responsibility"),
    ("CC1.3","COSO Principle 3 - Establishes Structure, Authority, and Responsibility"),
    ("CC1.4","COSO Principle 4 - Demonstrates Commitment to Competence"),
    ("CC1.5","COSO Principle 5 - Enforces Accountability"),
    ("CC2.1","COSO Principle 13 - Uses Relevant Information"),
    ("CC2.2","COSO Principle 14 - Communicates Internally"),
    ("CC2.3","COSO Principle 15 - Communicates Externally"),
    ("CC3.1","COSO Principle 6 - Specifies Suitable Objectives"),
    ("CC3.2","COSO Principle 7 - Identifies and Analyzes Risk"),
    ("CC3.3","COSO Principle 8 - Assesses Fraud Risk"),
    ("CC3.4","COSO Principle 9 - Identifies and Analyzes Significant Change"),
    ("CC4.1","COSO Principle 16 - Conducts Ongoing or Separate Evaluations"),
    ("CC4.2","COSO Principle 17 - Evaluates and Communicates Deficiencies"),
    ("CC5.1","COSO Principle 10 - Selects and Develops Control Activities"),
    ("CC5.2","COSO Principle 11 - Selects and Develops General Controls over Technology"),
    ("CC5.3","COSO Principle 12 - Deploys through Policies and Procedures"),
    ("CC6.1","Logical Access Controls"),
    ("CC6.2","New Internal Personnel and Confidential Information"),
    ("CC6.3","Personnel Role Changes and System Access"),
    ("CC6.4","Restricts Physical Access"),
    ("CC6.5","Logical Access Removal"),
    ("CC6.6","Logical Access Security Measures (External Threats)"),
    ("CC6.7","Restricts Unauthorized or Malicious Software"),
    ("CC6.8","Prevents or Detects Unauthorized or Malicious Software"),
    ("CC7.1","Threat and Vulnerability Identification"),
    ("CC7.2","Monitoring Infrastructure and Software"),
    ("CC7.3","Evaluates Security Events"),
    ("CC7.4","Responds to Security Incidents"),
    ("CC7.5","Identifies, Develops, and Implements Activities to Recover from Security Incidents"),
    ("CC8.1","Change Management"),
    ("CC9.1","Risk Mitigation"),
    ("CC9.2","Monitors and Assesses Third-party Vendor and Business Partners"),
    ("A1.1","Capacity Management"),
    ("A1.2","Environmental Threat Management"),
    ("A1.3","Recovery and Business Continuity"),
    ("C1.1","Confidentiality Policies and Practices"),
    ("C1.2","Secure Disposal of Confidential Information"),
    ("P1.1","Privacy Policy Notification"),
    ("P2.1","Data Subject Choice and Consent"),
    ("P3.1","Personal Information Collection Consistency"),
    ("P3.2","Personal Information Collection Explicit Consent"),
    ("P4.1","Purpose Consistent Use of Personal Information"),
    ("P4.2","Personal Information Retention"),
    ("P4.3","Personal Information Disposal"),
    ("P5.1","Access to Personal Information"),
    ("P5.2","Correction of Personal Information"),
    ("P6.1","Personal Information Disclosure Notification"),
    ("P6.2","Personal Information Third-party Disclosure Authorization"),
    ("P6.3","Disclosure of Personal Information to Third Parties"),
    ("P6.4","Disclosure of Personal Information to Third Parties for New Purposes"),
    ("P6.5","Personal Information Disclosure to Government Authorities"),
    ("P6.6","Provision of Personal Information to Third Parties"),
    ("P6.7","Notification of Personal Information Disclosure"),
    ("P7.1","Quality and Accuracy of Personal Information"),
    ("P8.1","Privacy Compliance Review"),
    ("PI1.1","Complete and Accurate Processing"),
    ("PI1.2","Complete and Accurate Processing Commitments"),
    ("PI1.3","System Inputs Complete and Accurate"),
    ("PI1.4","System Outputs Complete and Accurate"),
    ("PI1.5","Store and Maintain Complete and Accurate Inputs and Outputs"),
    ("PI1.6","Inputs and Outputs Meet Processing Requirements"),
    ("PI1.7","Processing Complete and Accurate"),
    ("PI1.8","Provide Reports to Users on System Performance"),
]

# ─── Full ISO 27001:2022 Annex A (93 controls) ───────────────────────────────
ISO27001_CONTROLS = [
    # Organizational Controls (A5 — 37 controls)
    ("A.5.1","Policies for information security"),
    ("A.5.2","Information security roles and responsibilities"),
    ("A.5.3","Segregation of duties"),
    ("A.5.4","Management responsibilities"),
    ("A.5.5","Contact with authorities"),
    ("A.5.6","Contact with special interest groups"),
    ("A.5.7","Threat intelligence"),
    ("A.5.8","Information security in project management"),
    ("A.5.9","Inventory of information and other associated assets"),
    ("A.5.10","Acceptable use of information and other associated assets"),
    ("A.5.11","Return of assets"),
    ("A.5.12","Classification of information"),
    ("A.5.13","Labelling of information"),
    ("A.5.14","Information transfer"),
    ("A.5.15","Access control"),
    ("A.5.16","Identity management"),
    ("A.5.17","Authentication information"),
    ("A.5.18","Access rights"),
    ("A.5.19","Information security in supplier relationships"),
    ("A.5.20","Addressing information security within supplier agreements"),
    ("A.5.21","Managing information security in the ICT supply chain"),
    ("A.5.22","Monitoring, review and change management of supplier services"),
    ("A.5.23","Information security for use of cloud services"),
    ("A.5.24","Information security incident management planning and preparation"),
    ("A.5.25","Assessment and decision on information security events"),
    ("A.5.26","Response to information security incidents"),
    ("A.5.27","Learning from information security incidents"),
    ("A.5.28","Collection of evidence"),
    ("A.5.29","Information security during disruption"),
    ("A.5.30","ICT readiness for business continuity"),
    ("A.5.31","Legal, statutory, regulatory and contractual requirements"),
    ("A.5.32","Intellectual property rights"),
    ("A.5.33","Protection of records"),
    ("A.5.34","Privacy and protection of PII"),
    ("A.5.35","Independent review of information security"),
    ("A.5.36","Compliance with policies, rules and standards for information security"),
    ("A.5.37","Documented operating procedures"),
    # People Controls (A6 — 8 controls)
    ("A.6.1","Screening"),
    ("A.6.2","Terms and conditions of employment"),
    ("A.6.3","Information security awareness, education and training"),
    ("A.6.4","Disciplinary process"),
    ("A.6.5","Responsibilities after termination or change of employment"),
    ("A.6.6","Confidentiality or non-disclosure agreements"),
    ("A.6.7","Remote working"),
    ("A.6.8","Information security event reporting"),
    # Physical Controls (A7 — 14 controls)
    ("A.7.1","Physical security perimeters"),
    ("A.7.2","Physical entry"),
    ("A.7.3","Securing offices, rooms and facilities"),
    ("A.7.4","Physical security monitoring"),
    ("A.7.5","Protecting against physical and environmental threats"),
    ("A.7.6","Working in secure areas"),
    ("A.7.7","Clear desk and clear screen"),
    ("A.7.8","Equipment siting and protection"),
    ("A.7.9","Security of assets off-premises"),
    ("A.7.10","Storage media"),
    ("A.7.11","Supporting utilities"),
    ("A.7.12","Cabling security"),
    ("A.7.13","Equipment maintenance"),
    ("A.7.14","Secure disposal or re-use of equipment"),
    # Technological Controls (A8 — 34 controls)
    ("A.8.1","User endpoint devices"),
    ("A.8.2","Privileged access rights"),
    ("A.8.3","Information access restriction"),
    ("A.8.4","Access to source code"),
    ("A.8.5","Secure authentication"),
    ("A.8.6","Capacity management"),
    ("A.8.7","Protection against malware"),
    ("A.8.8","Management of technical vulnerabilities"),
    ("A.8.9","Configuration management"),
    ("A.8.10","Information deletion"),
    ("A.8.11","Data masking"),
    ("A.8.12","Data leakage prevention"),
    ("A.8.13","Information backup"),
    ("A.8.14","Redundancy of information processing facilities"),
    ("A.8.15","Logging"),
    ("A.8.16","Monitoring activities"),
    ("A.8.17","Clock synchronization"),
    ("A.8.18","Use of privileged utility programs"),
    ("A.8.19","Installation of software on operational systems"),
    ("A.8.20","Networks security"),
    ("A.8.21","Security of network services"),
    ("A.8.22","Segregation of networks"),
    ("A.8.23","Web filtering"),
    ("A.8.24","Use of cryptography"),
    ("A.8.25","Secure development life cycle"),
    ("A.8.26","Application security requirements"),
    ("A.8.27","Secure system architecture and engineering principles"),
    ("A.8.28","Secure coding"),
    ("A.8.29","Security testing in development and acceptance"),
    ("A.8.30","Outsourced development"),
    ("A.8.31","Separation of development, test and production environments"),
    ("A.8.32","Change management"),
    ("A.8.33","Test information"),
    ("A.8.34","Protection of information systems during audit testing"),
]

# ─── HIPAA Safeguards (75 specifications) ────────────────────────────────────
HIPAA_CONTROLS = [
    ("164.308(a)(1)(i)","Security Management Process — Risk Analysis"),
    ("164.308(a)(1)(ii)(A)","Risk Management"),
    ("164.308(a)(1)(ii)(B)","Sanction Policy"),
    ("164.308(a)(1)(ii)(C)","Information System Activity Review"),
    ("164.308(a)(2)","Assigned Security Responsibility"),
    ("164.308(a)(3)(i)","Workforce Security"),
    ("164.308(a)(3)(ii)(A)","Authorization and/or Supervision"),
    ("164.308(a)(3)(ii)(B)","Workforce Clearance Procedure"),
    ("164.308(a)(3)(ii)(C)","Termination Procedures"),
    ("164.308(a)(4)(i)","Information Access Management"),
    ("164.308(a)(4)(ii)(A)","Isolating Health Care Clearinghouse Functions"),
    ("164.308(a)(4)(ii)(B)","Access Authorization"),
    ("164.308(a)(4)(ii)(C)","Access Establishment and Modification"),
    ("164.308(a)(5)(i)","Security Awareness and Training"),
    ("164.308(a)(5)(ii)(A)","Security Reminders"),
    ("164.308(a)(5)(ii)(B)","Protection from Malicious Software"),
    ("164.308(a)(5)(ii)(C)","Log-in Monitoring"),
    ("164.308(a)(5)(ii)(D)","Password Management"),
    ("164.308(a)(6)(i)","Security Incident Procedures"),
    ("164.308(a)(6)(ii)","Response and Reporting"),
    ("164.308(a)(7)(i)","Contingency Plan"),
    ("164.308(a)(7)(ii)(A)","Data Backup Plan"),
    ("164.308(a)(7)(ii)(B)","Disaster Recovery Plan"),
    ("164.308(a)(7)(ii)(C)","Emergency Mode Operation Plan"),
    ("164.308(a)(7)(ii)(D)","Testing and Revision Procedures"),
    ("164.308(a)(7)(ii)(E)","Applications and Data Criticality Analysis"),
    ("164.308(a)(8)","Evaluation"),
    ("164.308(b)(1)","Business Associate Contracts and Other Arrangements"),
    ("164.308(b)(3)","Written Contract or Other Arrangement"),
    ("164.310(a)(1)","Facility Access Controls"),
    ("164.310(a)(2)(i)","Contingency Operations"),
    ("164.310(a)(2)(ii)","Facility Security Plan"),
    ("164.310(a)(2)(iii)","Access Control and Validation Procedures"),
    ("164.310(a)(2)(iv)","Maintenance Records"),
    ("164.310(b)","Workstation Use"),
    ("164.310(c)","Workstation Security"),
    ("164.310(d)(1)","Device and Media Controls"),
    ("164.310(d)(2)(i)","Disposal"),
    ("164.310(d)(2)(ii)","Media Re-use"),
    ("164.310(d)(2)(iii)","Accountability"),
    ("164.310(d)(2)(iv)","Data Backup and Storage"),
    ("164.312(a)(1)","Access Control"),
    ("164.312(a)(2)(i)","Unique User Identification"),
    ("164.312(a)(2)(ii)","Emergency Access Procedure"),
    ("164.312(a)(2)(iii)","Automatic Logoff"),
    ("164.312(a)(2)(iv)","Encryption and Decryption"),
    ("164.312(b)","Audit Controls"),
    ("164.312(c)(1)","Integrity"),
    ("164.312(c)(2)","Mechanism to Authenticate ePHI"),
    ("164.312(d)","Person or Entity Authentication"),
    ("164.312(e)(1)","Transmission Security"),
    ("164.312(e)(2)(i)","Integrity Controls"),
    ("164.312(e)(2)(ii)","Encryption"),
    ("164.314(a)(1)","Business Associate Contracts"),
    ("164.314(a)(2)(i)","Business Associate Contracts — Required"),
    ("164.314(a)(2)(ii)","Business Associate Contracts — Other Arrangements"),
    ("164.314(b)(1)","Requirements for Group Health Plans"),
    ("164.314(b)(2)(i)","Plan Documents"),
    ("164.316(a)","Policies and Procedures"),
    ("164.316(b)(1)(i)","Documentation — Time Limit"),
    ("164.316(b)(1)(ii)","Documentation — Availability"),
    ("164.316(b)(2)(i)","Documentation — Updates"),
    ("164.316(b)(2)(ii)","Documentation — Actions, Activities, and Assessments"),
    ("164.316(b)(2)(iii)","Documentation — Retention"),
]

# ─── CMMC Level 2 (110 practices) ────────────────────────────────────────────
CMMC_CONTROLS = [
    ("AC.L2-3.1.1","Authorized Access Control"),("AC.L2-3.1.2","Transaction & Function Control"),
    ("AC.L2-3.1.3","Control CUI Flow"),("AC.L2-3.1.4","Separation of Duties"),
    ("AC.L2-3.1.5","Least Privilege"),("AC.L2-3.1.6","Non-Privileged Account Use"),
    ("AC.L2-3.1.7","Privileged Functions"),("AC.L2-3.1.8","Unsuccessful Logon Attempts"),
    ("AC.L2-3.1.9","Privacy & Security Notices"),("AC.L2-3.1.10","Session Lock"),
    ("AC.L2-3.1.11","Session Termination"),("AC.L2-3.1.12","Remote Access Monitoring"),
    ("AC.L2-3.1.13","Remote Access Confidentiality"),
    ("AC.L2-3.1.14","Remote Access Routing"),("AC.L2-3.1.15","Privileged Remote Access"),
    ("AC.L2-3.1.16","Wireless Authorization"),("AC.L2-3.1.17","Wireless Protection"),
    ("AC.L2-3.1.18","Mobile Device Control"),("AC.L2-3.1.19","Encrypt CUI on Mobile"),
    ("AC.L2-3.1.20","External System Connections"),
    ("AC.L2-3.1.21","Portable Storage Use"),("AC.L2-3.1.22","Control Public Information"),
    ("AT.L2-3.2.1","Role-Based Risk Awareness"),("AT.L2-3.2.2","Role-Based Training"),
    ("AT.L2-3.2.3","Insider Threat Awareness"),
    ("AU.L2-3.3.1","System Auditing"),("AU.L2-3.3.2","User Accountability"),
    ("AU.L2-3.3.3","Event Review"),("AU.L2-3.3.4","Alert on Audit Failure"),
    ("AU.L2-3.3.5","Correlate Audit Records"),("AU.L2-3.3.6","Reduce and Report Audit"),
    ("AU.L2-3.3.7","Authoritative Time Source"),("AU.L2-3.3.8","Protect Audit Information"),
    ("AU.L2-3.3.9","Limit Audit Log Management"),
    ("CM.L2-3.4.1","Baseline Configurations"),("CM.L2-3.4.2","Security Configuration"),
    ("CM.L2-3.4.3","Change Control"),("CM.L2-3.4.4","Security Impact Analysis"),
    ("CM.L2-3.4.5","Access Restrictions for Change"),
    ("CM.L2-3.4.6","Least Functionality"),("CM.L2-3.4.7","Nonessential Functionality"),
    ("CM.L2-3.4.8","Application Execution Policy"),("CM.L2-3.4.9","User-Installed Software"),
    ("IA.L2-3.5.1","Identification"),("IA.L2-3.5.2","Authentication"),
    ("IA.L2-3.5.3","Multi-Factor Authentication"),("IA.L2-3.5.4","Replay-Resistant Authentication"),
    ("IA.L2-3.5.5","Identifier Reuse"),("IA.L2-3.5.6","Identifier Handling"),
    ("IA.L2-3.5.7","Password Complexity"),("IA.L2-3.5.8","Password Reuse"),
    ("IA.L2-3.5.9","Temporary Passwords"),("IA.L2-3.5.10","Cryptographically-Protected Passwords"),
    ("IA.L2-3.5.11","Obscure Feedback"),
    ("IR.L2-3.6.1","Incident Handling"),("IR.L2-3.6.2","Incident Reporting"),
    ("IR.L2-3.6.3","Incident Response Testing"),
    ("MA.L2-3.7.1","Perform Maintenance"),("MA.L2-3.7.2","System Maintenance Control"),
    ("MA.L2-3.7.3","Equipment Sanitization"),("MA.L2-3.7.4","Media Inspection"),
    ("MA.L2-3.7.5","Nonlocal Maintenance"),("MA.L2-3.7.6","Maintenance Personnel"),
    ("MP.L2-3.8.1","Media Protection"),("MP.L2-3.8.2","Media Access"),
    ("MP.L2-3.8.3","Media Sanitization"),("MP.L2-3.8.4","Media Marking"),
    ("MP.L2-3.8.5","Media Accountability"),("MP.L2-3.8.6","Portable Storage Encryption"),
    ("MP.L2-3.8.7","Removable Media"),("MP.L2-3.8.8","Shared Media"),
    ("MP.L2-3.8.9","Protect Backups"),
    ("PS.L2-3.9.1","Screen Individuals"),("PS.L2-3.9.2","Personnel Actions"),
    ("PE.L2-3.10.1","Limit Physical Access"),("PE.L2-3.10.2","Monitor Facility"),
    ("PE.L2-3.10.3","Visitor Control"),("PE.L2-3.10.4","Maintain Audit Logs"),
    ("PE.L2-3.10.5","Manage Physical Access Devices"),("PE.L2-3.10.6","Enforce Safeguarding"),
    ("RA.L2-3.11.1","Risk Assessment"),("RA.L2-3.11.2","Vulnerability Scan"),
    ("RA.L2-3.11.3","Remediate Vulnerabilities"),
    ("CA.L2-3.12.1","Assess Controls"),("CA.L2-3.12.2","Plan of Action"),
    ("CA.L2-3.12.3","Monitor Controls"),("CA.L2-3.12.4","Develop SSP"),
    ("SC.L2-3.13.1","Boundary Protection"),("SC.L2-3.13.2","Network Segmentation"),
    ("SC.L2-3.13.3","Duty Separation"),("SC.L2-3.13.4","Shared Resource Control"),
    ("SC.L2-3.13.5","Public Access Denial"),("SC.L2-3.13.6","Network Communication by Exception"),
    ("SC.L2-3.13.7","Split Tunneling"),("SC.L2-3.13.8","Data in Transit"),
    ("SC.L2-3.13.9","Terminate Network Connections"),
    ("SC.L2-3.13.10","Key Management"),("SC.L2-3.13.11","FIPS Cryptography"),
    ("SC.L2-3.13.12","Collaborative Device Control"),("SC.L2-3.13.13","Mobile Code"),
    ("SC.L2-3.13.14","VoIP"),("SC.L2-3.13.15","Communications Authenticity"),
    ("SC.L2-3.13.16","Data at Rest"),
    ("SI.L2-3.14.1","Flaw Remediation"),("SI.L2-3.14.2","Malicious Code Protection"),
    ("SI.L2-3.14.3","Security Alerts"),("SI.L2-3.14.4","Update Malicious Code Protection"),
    ("SI.L2-3.14.5","System and File Scanning"),("SI.L2-3.14.6","Monitor Communications"),
    ("SI.L2-3.14.7","Identify Unauthorized Use"),
]

CONTROLS = {
    "nist_800_53": NIST_CONTROLS,
    "soc2": SOC2_CONTROLS,
    "iso27001": ISO27001_CONTROLS,
    "hipaa": HIPAA_CONTROLS,
    "cmmc_l2": CMMC_CONTROLS,
}

PROVIDERS = ["aws", "azure", "gcp"]
REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]
SEVERITIES = ["critical", "high", "medium", "low"]
SEVERITY_WEIGHTS = [0.08, 0.17, 0.40, 0.35]

# Check templates per control family → realistic assertion text
CHECK_TEMPLATES: dict[str, list[str]] = {
    "AC": [
        "Verify all user accounts have documented approvals and are reviewed quarterly",
        "Ensure privileged accounts use separate credentials from standard accounts",
        "Confirm access provisioning workflow enforces manager approval before grant",
        "Validate MFA is enforced on all privileged and remote access accounts",
        "Check that inactive accounts are disabled within 90 days",
    ],
    "AT": [
        "Confirm all users completed annual security awareness training",
        "Verify role-based training is completed before system access is granted",
        "Check that training completion records are retained for at least 3 years",
    ],
    "AU": [
        "Verify audit logs are enabled across all in-scope systems",
        "Confirm logs are shipped to centralized, tamper-resistant SIEM",
        "Validate log retention meets minimum policy requirement (365 days)",
        "Check that failed authentication events are captured and alerted on",
        "Ensure log integrity protection is enabled (e.g., CloudTrail validation)",
    ],
    "CA": [
        "Verify last control assessment was completed within 12 months",
        "Confirm POA&M items are tracked and reviewed monthly",
        "Check that penetration testing is scheduled at least annually",
    ],
    "CM": [
        "Validate baseline configuration is documented and version-controlled",
        "Confirm configuration drift detection is enabled and alerting",
        "Check that CIS Benchmarks or equivalent hardening is applied",
        "Verify software inventory is maintained and reviewed quarterly",
        "Ensure no unauthorized software is installed on production systems",
    ],
    "CP": [
        "Verify business continuity plan has been tested in the last 12 months",
        "Confirm backup schedule meets RPO requirements and is tested",
        "Validate alternate processing site capability exists and is documented",
    ],
    "IA": [
        "Verify MFA is enforced for all privileged accounts",
        "Confirm password policy enforces minimum length and complexity",
        "Check that default credentials are changed on all systems",
        "Validate no shared service accounts exist without documented justification",
    ],
    "IR": [
        "Confirm incident response plan is documented and reviewed annually",
        "Verify tabletop exercise was completed in the last 12 months",
        "Check that all security incidents are logged and tracked to resolution",
    ],
    "MA": [
        "Verify maintenance activities are logged and authorized",
        "Confirm remote maintenance sessions use encrypted channels",
        "Check that maintenance personnel are screened and authorized",
    ],
    "MP": [
        "Verify media sanitization procedures are documented and followed",
        "Confirm media containing sensitive data is encrypted at rest",
        "Check that portable storage use is controlled and logged",
    ],
    "PE": [
        "Verify physical access is limited to authorized personnel",
        "Confirm visitor access is logged and escorted",
        "Check that physical security monitoring is operational",
    ],
    "PL": [
        "Verify system security plan is documented and current",
        "Confirm privacy impact assessment is up to date",
        "Check that rules of behavior are acknowledged by all users",
    ],
    "PM": [
        "Verify information security program plan is documented",
        "Confirm security metrics are tracked and reported to leadership",
        "Check that supply chain risk management strategy is in place",
    ],
    "PS": [
        "Verify background checks are completed before system access is granted",
        "Confirm employee termination procedures revoke all access within 24 hours",
        "Check that personnel security policies are documented and enforced",
    ],
    "PT": [
        "Verify PII processing authority is documented and current",
        "Confirm privacy notices are provided at point of collection",
        "Check that consent mechanisms comply with applicable regulations",
    ],
    "RA": [
        "Verify risk assessment was completed or updated within 12 months",
        "Confirm vulnerability scans are run at least weekly on critical systems",
        "Check that all critical/high vulnerabilities are remediated within SLA",
        "Validate threat hunting activities are performed quarterly",
    ],
    "SA": [
        "Confirm security requirements are included in all acquisition contracts",
        "Verify third-party code undergoes security review before deployment",
        "Check that SDLC security checkpoints are enforced",
    ],
    "SC": [
        "Verify network segmentation isolates production from development environments",
        "Confirm TLS 1.2+ is enforced on all external-facing endpoints",
        "Check that encryption at rest is enabled for all sensitive data stores",
        "Validate firewall rules are reviewed and no overly permissive rules exist",
        "Confirm WAF is deployed in front of all public web applications",
    ],
    "SI": [
        "Verify critical patches are applied within 24 hours of release",
        "Confirm EDR/AV is deployed on all endpoints and servers",
        "Check that vulnerability scanner is integrated into CI/CD pipeline",
        "Validate malware detection alerts are reviewed within 4 hours",
    ],
    "SR": [
        "Verify supply chain risk assessments are completed for critical vendors",
        "Confirm component provenance is tracked for critical software dependencies",
        "Check that vendor notification agreements cover security incidents",
    ],
    # SOC2 families
    "CC": [
        "Validate control environment documentation is current and approved",
        "Confirm risk assessment process is performed at least annually",
        "Verify control activities are operating effectively",
        "Check that monitoring activities identify and address deficiencies",
    ],
    "A": [
        "Verify system capacity is monitored and alerts are configured",
        "Confirm environmental controls protect against physical threats",
        "Check that recovery procedures meet availability SLA commitments",
    ],
    "C": [
        "Verify confidentiality policies are documented and enforced",
        "Confirm confidential data is encrypted and access-controlled",
    ],
    "P": [
        "Verify privacy policy is accessible and current",
        "Confirm personal data collection is limited to stated purposes",
        "Check that data subjects can access and correct their information",
    ],
    "PI": [
        "Verify processing integrity controls are operating effectively",
        "Confirm inputs and outputs are validated for completeness and accuracy",
    ],
    # ISO27001 families
    "A.5": [
        "Verify information security policies are approved and communicated",
        "Confirm security roles and responsibilities are assigned",
        "Check that supplier agreements include security requirements",
    ],
    "A.6": [
        "Verify personnel screening is completed before access is granted",
        "Confirm security awareness training is current for all staff",
        "Check that termination procedures revoke access immediately",
    ],
    "A.7": [
        "Verify physical access controls restrict entry to authorized personnel",
        "Confirm surveillance and monitoring systems are operational",
        "Check that secure areas have appropriate environmental controls",
    ],
    "A.8": [
        "Verify endpoint protection is deployed and current",
        "Confirm privileged access rights are reviewed quarterly",
        "Check that vulnerability management process meets SLA requirements",
        "Validate encryption is applied to sensitive data in transit and at rest",
    ],
    # HIPAA safeguard areas
    "164.308": [
        "Verify risk analysis is current and documented",
        "Confirm security policies are reviewed and approved annually",
        "Check that workforce security training is completed and recorded",
        "Validate access management procedures are enforced",
    ],
    "164.310": [
        "Verify physical access controls for ePHI systems are operational",
        "Confirm workstation security policies are implemented",
        "Check that device and media disposal procedures are followed",
    ],
    "164.312": [
        "Verify access controls are implemented for all ePHI systems",
        "Confirm audit controls capture all ePHI access events",
        "Check that transmission encryption is enforced for ePHI",
        "Validate automatic logoff is configured on workstations handling ePHI",
    ],
    "164.314": [
        "Verify business associate agreements are signed and current",
        "Confirm BAA security requirements are being met by associates",
    ],
    "164.316": [
        "Verify security policies are documented and up to date",
        "Confirm policy retention requirements are being met",
    ],
    # CMMC families
    "AC.L2": [
        "Verify all CUI access is restricted to authorized users",
        "Confirm MFA is implemented for privileged and remote access",
        "Check that session lock and termination controls are configured",
    ],
    "AT.L2": [
        "Verify role-based security training is completed before system access",
        "Confirm insider threat awareness training is current",
    ],
    "AU.L2": [
        "Verify audit logging captures all required events per CMMC",
        "Confirm logs are reviewed regularly and anomalies are investigated",
        "Check that audit log integrity protection is in place",
    ],
    "CM.L2": [
        "Verify baseline configurations are documented and enforced",
        "Confirm configuration change control process is operating",
        "Check for unauthorized software installations monthly",
    ],
    "IA.L2": [
        "Verify MFA is enforced for CUI system access",
        "Confirm password policies meet CMMC minimum requirements",
        "Check that account identifiers are managed per policy",
    ],
    "IR.L2": [
        "Verify incident response procedures are documented and tested",
        "Confirm incidents are reported within required timeframes",
    ],
    "MA.L2": ["Verify maintenance is performed by authorized personnel only"],
    "MP.L2": ["Verify media protection controls are enforced for CUI media"],
    "PS.L2": ["Verify personnel screening procedures are enforced"],
    "PE.L2": ["Verify physical access to CUI systems is properly controlled"],
    "RA.L2": [
        "Verify risk assessments are performed and documented",
        "Confirm vulnerability remediation meets CMMC SLA requirements",
    ],
    "CA.L2": [
        "Verify System Security Plan (SSP) is documented and current",
        "Confirm POA&M items are tracked to resolution",
    ],
    "SC.L2": [
        "Verify boundary protection controls are in place",
        "Confirm CUI is encrypted during transmission",
        "Check that network segmentation separates CUI systems",
    ],
    "SI.L2": [
        "Verify flaw remediation process meets CMMC SLA",
        "Confirm malware protection is deployed on all systems",
        "Check that system monitoring is active for unauthorized use",
    ],
}

# Realistic findings for failing controls
FINDINGS_BANK: dict[str, list[str]] = {
    "AC": [
        "{count} user accounts have not been reviewed in over 90 days",
        "Found {count} accounts with no MFA enrolled in privileged role groups",
        "Service account '{svc}' has administrator privileges with no documented justification",
        "Access review for {group} group was last completed {days} days ago (max 90)",
        "{count} terminated employee accounts still active in Active Directory",
        "Shared credentials detected on {count} production systems",
    ],
    "AU": [
        "CloudTrail logging disabled in region {region} — {count} trails affected",
        "Log retention set to {days} days; policy requires minimum 365 days",
        "SIEM failed to ingest logs from {count} sources in the last 24 hours",
        "Authentication failure events not forwarded to alerting platform",
        "Log integrity validation disabled on {count} CloudTrail trails",
    ],
    "CM": [
        "{count} EC2 instances deviate from approved CIS Level 2 baseline",
        "Unauthorized software '{pkg}' detected on {count} production servers",
        "Configuration drift detected: {count} resources non-compliant with baseline",
        "Security group '{sg}' allows unrestricted inbound traffic (0.0.0.0/0)",
        "{count} systems running end-of-life OS with no patch coverage",
    ],
    "IA": [
        "{count} admin accounts do not have MFA enabled",
        "Password policy does not enforce minimum 16-character length",
        "Default credentials unchanged on {count} network devices",
        "API keys older than 90 days without rotation: {count} keys affected",
    ],
    "SC": [
        "S3 bucket '{bucket}' allows public read access with no encryption",
        "TLS 1.0/1.1 still enabled on {count} load balancers",
        "RDS instance '{db}' does not have encryption at rest enabled",
        "Security group allows port 22/3389 access from 0.0.0.0/0",
        "WAF not enabled on {count} public-facing Application Load Balancers",
    ],
    "SI": [
        "{count} critical CVEs (CVSS ≥ 9.0) unpatched for over 30 days",
        "EDR agent not installed on {count} production hosts",
        "Vulnerability scan not run on {count} systems in the last 7 days",
        "Container image '{img}' contains {count} known critical vulnerabilities",
    ],
    "RA": [
        "Last formal risk assessment completed {months} months ago (max 12)",
        "{count} high-severity vulnerabilities exceed remediation SLA",
        "Threat hunting activities not performed in the last {months} months",
    ],
    "IR": [
        "Incident response plan not updated in {months} months (requires annual review)",
        "Last tabletop exercise completed {months} months ago",
        "{count} open security incidents unresolved beyond SLA",
    ],
    "DEFAULT": [
        "Control has not been formally assessed in the current period",
        "Evidence collection for this control is incomplete",
        "Policy documentation for this control is outdated or missing",
        "Control owner has not confirmed the control is operating effectively",
    ],
}


def _get_checks(control_id: str) -> list[str]:
    """Return 1-3 check assertion strings for a given control ID."""
    prefix = control_id.split("-")[0].split(".")[0]
    # Try increasingly specific prefixes
    templates = (
        CHECK_TEMPLATES.get(control_id)
        or CHECK_TEMPLATES.get(prefix + "." + control_id.split(".")[1] if "." in control_id else "")
        or CHECK_TEMPLATES.get(prefix)
        or CHECK_TEMPLATES.get("DEFAULT", ["Verify the control is implemented and operating effectively"])
    )
    # Clean up None from chained .get
    if not templates:
        templates = ["Verify the control is implemented and operating effectively"]
    n = random.choices([1, 2, 3], weights=[0.25, 0.50, 0.25])[0]
    return random.sample(templates, min(n, len(templates)))


def _get_finding(control_id: str) -> str:
    prefix = control_id.split("-")[0].split(".")[0]
    bank = FINDINGS_BANK.get(prefix) or FINDINGS_BANK["DEFAULT"]
    tmpl = random.choice(bank)
    return tmpl.format(
        count=random.randint(1, 47),
        days=random.randint(95, 365),
        months=random.randint(13, 24),
        region=random.choice(["us-east-1", "eu-west-1", "ap-southeast-1"]),
        svc=random.choice(["deploy-svc", "pipeline-bot", "legacy-admin", "ci-runner"]),
        group=random.choice(["DevOps", "Engineering", "DataTeam", "Platform"]),
        pkg=random.choice(["nmap", "netcat", "curl-debug", "test-suite-v2"]),
        sg=random.choice(["sg-web-prod", "sg-db-access", "sg-internal-api"]),
        bucket=random.choice(["corp-reports", "customer-uploads", "analytics-data"]),
        db=random.choice(["prod-mysql-01", "analytics-pg", "reporting-db"]),
        img=random.choice(["api-server:latest", "worker:v2.3", "nginx:1.21"]),
        months_ago=random.randint(13, 24),
    )


def random_severity() -> str:
    return random.choices(SEVERITIES, weights=SEVERITY_WEIGHTS, k=1)[0]


def random_status() -> str:
    return random.choices(["pass", "fail", "fail", "pass", "pass", "pass", "pass"], k=1)[0]


def seed(db) -> None:
    # ── Users ────────────────────────────────────────────────────────────────
    print("Seeding demo users…")
    if not db.query(User).filter(User.email == "admin@grc-demo.com").first():
        db.add(User(
            id=str(uuid.uuid4()), email="admin@grc-demo.com", full_name="Alex Johnson",
            hashed_password=_hash_password("demo1234"), role="admin",
        ))
        db.add(User(
            id=str(uuid.uuid4()), email="analyst@grc-demo.com", full_name="Sam Rivera",
            hashed_password=_hash_password("demo1234"), role="analyst",
        ))
        db.flush()
        print("  Created demo users")

    # ── Assessment Runs & Results ─────────────────────────────────────────────
    print("Seeding assessment runs and results…")
    for framework in FRAMEWORKS:
        controls = CONTROLS[framework]
        n_controls = len(controls)

        # Historic trend runs (weeks 8→1) — run-level stats only, no individual results
        for weeks_ago in range(8, 0, -1):
            run_date = datetime.now(UTC) - timedelta(weeks=weeks_ago)
            base_rate = random.uniform(0.60, 0.85)
            passed = int(n_controls * base_rate)
            failed = n_controls - passed
            db.add(AssessmentRun(
                id=str(uuid.uuid4()),
                framework=framework,
                triggered_by="scheduler",
                started_at=run_date,
                completed_at=run_date + timedelta(minutes=random.randint(3, 12)),
                status="completed",
                total_checks=n_controls,
                passed=passed,
                failed=failed,
                errors=0,
                pass_rate=round(base_rate * 100, 1),
                summary={"note": "trend run — aggregate stats only"},
            ))

        # Latest full run — individual results with multi-check
        run_id = str(uuid.uuid4())
        latest_date = datetime.now(UTC) - timedelta(hours=random.randint(1, 12))
        provider = random.choice(PROVIDERS)
        region = random.choice(REGIONS)

        results: list[AssessmentResultRecord] = []
        passed_count = 0
        failed_count = 0

        for control_id, control_name in controls:
            checks = _get_checks(control_id)
            for i, assertion in enumerate(checks):
                status = random_status()
                severity = random_severity() if status == "fail" else "pass"
                findings = [_get_finding(control_id)] if status == "fail" else []
                if status == "pass":
                    passed_count += 1
                else:
                    failed_count += 1

                results.append(AssessmentResultRecord(
                    id=str(uuid.uuid4()),
                    run_id=run_id,
                    control_id=control_id,
                    check_id=f"{control_id}.check-{i+1}",
                    assertion=assertion,
                    status=status,
                    severity=severity,
                    provider=provider,
                    region=region,
                    findings=findings,
                    remediation=None,
                    assessed_at=latest_date + timedelta(seconds=random.randint(0, 300)),
                ))

        total = passed_count + failed_count
        pass_rate = round((passed_count / total) * 100, 1) if total else 0
        db.add(AssessmentRun(
            id=run_id,
            framework=framework,
            triggered_by="scheduler",
            started_at=latest_date,
            completed_at=latest_date + timedelta(minutes=random.randint(5, 15)),
            status="completed",
            total_checks=total,
            passed=passed_count,
            failed=failed_count,
            errors=0,
            pass_rate=pass_rate,
            summary={"note": f"Full scan — {n_controls} controls, {len(results)} checks"},
        ))
        db.add_all(results)
        db.flush()
        print(f"  {framework}: {n_controls} controls, {len(results)} checks, {pass_rate}% pass rate")

    # ── Data Sources / Integrations ───────────────────────────────────────────
    print("Seeding integrations…")
    integration_defs = [
        ("AWS Security Hub", "aws", "cloud_security", True, "success"),
        ("GitHub Advanced Security", "github", "source_control", True, "success"),
        ("Okta", "okta", "identity", True, "success"),
        ("Jira", "jira", "ticketing", True, "success"),
        ("Splunk SIEM", "splunk", "siem", True, "success"),
        ("Snyk", "snyk", "vulnerability", True, "success"),
        ("Qualys", "qualys", "vulnerability", False, "pending"),
        ("CrowdStrike Falcon", "crowdstrike", "edr", True, "success"),
        ("Datadog", "datadog", "monitoring", True, "success"),
        ("ServiceNow", "servicenow", "ticketing", False, "error"),
        ("Azure Security Center", "azure", "cloud_security", True, "success"),
        ("Slack", "slack", "communication", True, "success"),
        ("PagerDuty", "pagerduty", "alerting", True, "success"),
        ("Tenable.io", "tenable", "vulnerability", True, "success"),
        ("AWS Config", "aws", "cloud_config", True, "success"),
    ]
    if not db.query(DataSource).first():
        for name, provider, stype, active, sync_status in integration_defs:
            last_sync = datetime.now(UTC) - timedelta(minutes=random.randint(5, 120)) if active else None
            db.add(DataSource(
                id=str(uuid.uuid4()),
                name=name,
                provider=provider,
                source_type=stype,
                is_active=active,
                last_sync_at=last_sync,
                last_sync_status=sync_status,
                config={"api_key": "", "base_url": "", "enabled": active},
            ))
        db.flush()
        print(f"  Created {len(integration_defs)} integrations")

    # ── Evidence Records ──────────────────────────────────────────────────────
    print("Seeding evidence records…")
    if not db.query(EvidenceRecord).first():
        evidence_items = [
            ("AC-2",   "aws", "iam", "IAM access review — 347 accounts audited, 12 stale removed",          "collected"),
            ("AU-2",   "aws", "cloudtrail", "CloudTrail logging enabled across 5 regions",                  "collected"),
            ("IA-2",   "okta", "mfa", "MFA enrollment report — 98.3% of privileged accounts enrolled",      "collected"),
            ("CC1.1",  "manual", "policy", "SOC 2 Security Policy v3.2 — approved by CISO 2026-01-15",     "collected"),
            ("CA-8",   "manual", "pentest", "Penetration test report — Q4 2025, 3 findings remediated",     "collected"),
            ("RA-5",   "qualys", "vuln_scan", "Vulnerability scan — 47 critical, 123 high findings",        "failed"),
            ("AT-2",   "workday", "training", "Security awareness training — 99.1% completion rate",        "collected"),
            ("IR-8",   "manual", "policy", "Incident Response Plan v2.1 — tested 2025-11-20",              "collected"),
            ("SC-28",  "aws", "s3", "S3 encryption audit — 143/147 buckets encrypted at rest",              "collected"),
            ("SC-7",   "aws", "vpc", "VPC network diagram — production environment Q1 2026",                "collected"),
            ("164.308(a)(1)(i)", "manual", "risk", "HIPAA Risk Assessment 2025 — accepted residual risk",  "collected"),
            ("CC9.2",  "manual", "vendor", "Vendor security questionnaire — AWS passed all 67 controls",   "collected"),
            ("CM-6",   "aws_config", "config", "CIS Benchmark scan — 312 resources, 89.4% compliant",      "failed"),
            ("A.5.1",  "manual", "policy", "ISO 27001 gap assessment — 78% maturity, 22 gaps identified",  "collected"),
            ("CA.L2-3.12.4", "manual", "ssp", "CMMC SSP v1.0 — submitted to C3PAO 2026-02-01",           "collected"),
            ("A.5.18", "okta", "access", "Annual access rights review — 892 accounts reviewed",             "collected"),
            ("CP-4",   "manual", "test", "Business continuity test — full DR failover in 47 minutes",      "collected"),
            ("SI-4",   "splunk", "siem", "SIEM alert configuration review — 156 active rules validated",   "collected"),
            ("CP-9",   "aws", "backup", "Backup and recovery test — all critical DBs restored in 23 min",  "collected"),
            ("CC9.2",  "manual", "vendor", "Third-party risk assessment — Salesforce SOC 2 reviewed",      "collected"),
        ]
        for control_id, provider, service, description, status in evidence_items:
            db.add(EvidenceRecord(
                id=str(uuid.uuid4()),
                control_id=control_id,
                check_id=f"{control_id}.evidence",
                provider=provider,
                service=service,
                resource_type="evidence",
                region="us-east-1",
                account_id="demo-account",
                collected_at=datetime.now(UTC) - timedelta(days=random.randint(1, 90)),
                data={"description": description},
                normalized_data={"description": description, "provider": provider},
                status=status,
                sha256_hash="",
            ))
        db.flush()
        print(f"  Created {len(evidence_items)} evidence records")

    # ── Vendors ───────────────────────────────────────────────────────────────
    print("Seeding vendors…")
    if not db.query(VendorRecord).first():
        vendors = [
            ("Amazon Web Services", "cloud_infrastructure", "critical", "confidential"),
            ("Microsoft Azure", "cloud_infrastructure", "high", "confidential"),
            ("GitHub", "source_control", "high", "internal"),
            ("Okta", "identity_access_management", "critical", "restricted"),
            ("Splunk", "security_monitoring", "high", "internal"),
            ("CrowdStrike", "endpoint_security", "critical", "restricted"),
            ("Datadog", "observability", "medium", "internal"),
            ("Snyk", "application_security", "medium", "internal"),
            ("Salesforce", "crm", "medium", "confidential"),
            ("Stripe", "payment_processing", "critical", "restricted"),
            ("Twilio", "communications", "medium", "internal"),
            ("MongoDB Atlas", "database", "high", "confidential"),
            ("Cloudflare", "cdn_security", "high", "internal"),
            ("PagerDuty", "incident_management", "medium", "internal"),
            ("Atlassian", "project_management", "medium", "internal"),
        ]
        today = date.today()
        for name, category, criticality, data_class in vendors:
            db.add(VendorRecord(
                id=str(uuid.uuid4()),
                name=name,
                category=category,
                criticality=criticality,
                data_classification=data_class,
                contract_start=today - timedelta(days=random.randint(365, 1095)),
                contract_end=today + timedelta(days=random.randint(90, 730)),
                last_assessment_date=today - timedelta(days=random.randint(10, 300)),
                risk_level=criticality,
                primary_contact=f"security@{name.lower().replace(' ', '')[:12]}.com",
                notes=f"{name} — {criticality} criticality vendor",
                is_active=True,
            ))
        db.flush()
        print(f"  Created {len(vendors)} vendors")

    # ── Policy Violations ──────────────────────────────────────────────────────
    print("Seeding policy violations…")
    if not db.query(PolicyViolation).first():
        violations = [
            ("S3_PUBLIC_BUCKET", "Public S3 Bucket", "bucket-corp-backups-2024", "s3_bucket",
             "aws", "us-east-1", "S3 bucket corp-backups-2024 is publicly accessible — 4.2 GB exposed", "high", "open"),
            ("IAM_MFA_MISSING", "MFA Not Enforced", "iam-group-admins", "iam_group",
             "aws", "global", "3 admin accounts have no MFA enrolled (CISA KEV requirement)", "critical", "open"),
            ("SSL_CERT_EXPIRY", "Expiring SSL Certificate", "api.internal.corp", "certificate",
             "aws", "us-east-1", "SSL certificate expires in 14 days — auto-renewal failed", "medium", "in_progress"),
            ("ROOT_ACCOUNT_LOGIN", "Root Account Usage", "root-account", "iam_user",
             "aws", "global", "AWS root account used for console login on 2026-03-10 at 14:23 UTC", "critical", "open"),
            ("RDS_UNENCRYPTED", "Unencrypted RDS Instance", "rds-analytics-prod", "rds_instance",
             "aws", "us-east-1", "rds-analytics-prod has encryption at rest disabled — contains PII", "high", "open"),
            ("IAM_EXCESSIVE_PERMS", "Excessive IAM Permissions", "role-dev-admin", "iam_role",
             "aws", "global", "Role dev-admin has AdministratorAccess — violates least privilege", "high", "in_progress"),
            ("CLOUDTRAIL_DISABLED", "CloudTrail Not Enabled", "region-eu-west-1", "cloudtrail",
             "aws", "eu-west-1", "CloudTrail logging not enabled in eu-west-1 — blind spot for EU operations", "high", "open"),
            ("WEAK_PASSWORD_POLICY", "Weak Password Policy", "okta-org-policy", "identity_policy",
             "okta", "global", "Password policy allows 8-character minimum — NIST 800-63B requires 8+", "medium", "open"),
            ("SG_SSH_OPEN", "SSH Open to Internet", "sg-bastion-prod", "security_group",
             "aws", "us-east-1", "Security group sg-bastion allows SSH (22/tcp) from 0.0.0.0/0", "critical", "open"),
            ("MISSING_SEC_HEADERS", "Missing Security Headers", "cloudfront-distributions", "cdn_config",
             "aws", "global", "8 CloudFront distributions missing HSTS, CSP, X-Frame-Options headers", "low", "open"),
        ]
        for (pol_id, pol_name, resource_id, resource_type, provider, region,
             detail, severity, status) in violations:
            db.add(PolicyViolation(
                id=str(uuid.uuid4()),
                policy_id=pol_id,
                policy_name=pol_name,
                resource_id=resource_id,
                resource_type=resource_type,
                provider=provider,
                region=region,
                violation_detail=detail,
                severity=severity,
                status=status,
                detected_at=datetime.now(UTC) - timedelta(days=random.randint(1, 30)),
                resolved_at=None,
            ))
        db.flush()
        print(f"  Created {len(violations)} policy violations")

    db.commit()
    print("\n✓ Seed complete!")


if __name__ == "__main__":
    init_db()
    factory = get_session_factory()
    with factory() as session:
        seed(session)
