import sqlite3

DB_NAME = "vulnerabilities.db"


def create_table():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset TEXT,
            port INTEGER,
            service TEXT,
            vulnerability_name TEXT,
            severity TEXT,
            source_tool TEXT
        )
    """)

    conn.commit()
    conn.close()


def insert_vulnerability(vuln: dict):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM vulnerabilities
        WHERE asset = ?
        AND port = ?
        AND service = ?
        AND vulnerability_name = ?
        AND severity = ?
        AND source_tool = ?
    """, (
        vuln["asset"],
        vuln["port"],
        vuln["service"],
        vuln["vulnerability_name"],
        vuln["severity"],
        vuln["source_tool"]
    ))

    existing = cursor.fetchone()

    if existing:
        conn.close()
        return False

    cursor.execute("""
        INSERT INTO vulnerabilities 
        (asset, port, service, vulnerability_name, severity, source_tool)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        vuln["asset"],
        vuln["port"],
        vuln["service"],
        vuln["vulnerability_name"],
        vuln["severity"],
        vuln["source_tool"]
    ))

    conn.commit()
    conn.close()
    return True


def get_all_vulnerabilities():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM vulnerabilities")
    rows = cursor.fetchall()

    conn.close()

    result = []
    for row in rows:
        result.append({
            "id": row[0],
            "asset": row[1],
            "port": row[2],
            "service": row[3],
            "vulnerability_name": row[4],
            "severity": row[5],
            "source_tool": row[6]
        })

    return result


def search_vulnerabilities(keyword: str):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM vulnerabilities
        WHERE asset LIKE ?
        OR service LIKE ?
        OR vulnerability_name LIKE ?
        OR severity LIKE ?
    """, (
        f"%{keyword}%",
        f"%{keyword}%",
        f"%{keyword}%",
        f"%{keyword}%"
    ))

    rows = cursor.fetchall()
    conn.close()

    result = []
    for row in rows:
        result.append({
            "id": row[0],
            "asset": row[1],
            "port": row[2],
            "service": row[3],
            "vulnerability_name": row[4],
            "severity": row[5],
            "source_tool": row[6]
        })

    return result


def clear_all_vulnerabilities():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("DELETE FROM vulnerabilities")

    conn.commit()
    conn.close()