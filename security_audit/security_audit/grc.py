"""Framework catalog and compliance mapping."""
CONTROLS = [
 ("CIS v8","4.1","Establish and Maintain a Secure Configuration Process","Document and maintain secure configurations for enterprise assets."),
 ("CIS v8","4.5","Implement and Manage a Firewall on Servers","Deploy and manage host-based firewalls on servers."),
 ("CIS v8","7.1","Establish and Maintain a Vulnerability Management Process","Establish a risk-based vulnerability management process."),
 ("CIS v8","12.1","Ensure Network Infrastructure is Up to Date","Ensure network infrastructure is kept up to date."),
 ("NIST CSF 2.0","ID.AM-01","Inventories of hardware managed","Maintain inventories of hardware managed by the organization."),
 ("NIST CSF 2.0","ID.AM-02","Inventories of software managed","Maintain inventories of software, services, and systems."),
 ("NIST CSF 2.0","PR.PS-01","Configuration management practices","Configuration management practices are established and applied."),
 ("NIST CSF 2.0","DE.CM-01","Networks and network services monitored","Monitor networks and network services for potentially adverse events."),
 ("ISO 27001:2022","A.8.8","Management of technical vulnerabilities","Obtain information about technical vulnerabilities and take appropriate measures."),
 ("ISO 27001:2022","A.8.9","Configuration management","Establish, document, implement, monitor and review configurations."),
 ("ISO 27001:2022","A.8.20","Network security","Secure, manage and control networks and network devices."),
 ("SOC 2","CC6.1","Logical access security","Implement logical access security software, infrastructure and architectures."),
 ("SOC 2","CC7.1","Configuration and vulnerability monitoring","Monitor infrastructure and software for vulnerabilities and configuration changes."),
]
def seed(db):
    db.executemany("INSERT OR IGNORE INTO controls(framework,control_key,title,description) VALUES(?,?,?,?)",CONTROLS)
    templates=[("Baseline infrastructure review","Inventory, secure configuration, service exposure and vulnerability review",'["asset_inventory","configuration","services","vulnerabilities"]'),("Endpoint security review","Local endpoint configuration and software inventory",'["local_security","software_inventory","vulnerabilities"]'),("Network exposure review","Authorized private-scope host and service discovery",'["authorized_discovery","service_review"]')]
    db.executemany("INSERT OR IGNORE INTO templates(name,description,checks) SELECT ?,?,? WHERE NOT EXISTS (SELECT 1 FROM templates WHERE name=?)",[(n,d,c,n) for n,d,c in templates])
def evaluate(db, project_id):
    result=[]
    for row in db.execute("SELECT c.*, COALESCE(r.status,'not_assessed') status, COALESCE(r.evidence,'') evidence, r.assessor, r.updated_at FROM controls c LEFT JOIN control_results r ON r.control_id=c.id AND r.project_id=? ORDER BY c.framework,c.control_key",(project_id,)):
        result.append(dict(row))
    return result

FINDING_CONTROL_MAP = {
 "vulnerability":(("CIS v8","7.1"),("ISO 27001:2022","A.8.8"),("SOC 2","CC7.1")),
 "configuration":(("CIS v8","4.1"),("ISO 27001:2022","A.8.9"),("NIST CSF 2.0","PR.PS-01")),
 "endpoint protection":(("CIS v8","4.1"),("NIST CSF 2.0","PR.PS-01")),
 "network service":(("CIS v8","12.1"),("ISO 27001:2022","A.8.20"),("NIST CSF 2.0","DE.CM-01")),
 "network exposure":(("CIS v8","12.1"),("ISO 27001:2022","A.8.20"),("NIST CSF 2.0","DE.CM-01")),
 "vulnerability candidate":(("CIS v8","7.1"),("ISO 27001:2022","A.8.8"),("NIST CSF 2.0","DE.CM-01")),
}
def mapped_control_ids(db, category):
    return [r[0] for framework,key in FINDING_CONTROL_MAP.get(category,())
            if (r:=db.execute("SELECT id FROM controls WHERE framework=? AND control_key=?",(framework,key)).fetchone())]
