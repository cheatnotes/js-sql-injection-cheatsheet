## SQL Injection in JavaScript Applications


### 1. VULNERABLE FUNCTIONS & PATTERNS

#### **Direct String Concatenation**
```javascript
// VULNERABLE - String concatenation
const query = "SELECT * FROM users WHERE username = '" + username + "'";
const query = `SELECT * FROM users WHERE id = ${userId}`;
const query = "SELECT * FROM products WHERE name = '" + req.body.name + "'";

// VULNERABLE - Template literals with interpolation
const query = `SELECT * FROM users WHERE email = '${email}' AND password = '${password}'`;

// VULNERABLE - concat() method
const query = "SELECT * FROM users WHERE role = '".concat(role, "'");
```

#### **Database-Specific Vulnerable Functions**

**MySQL (mysql/mysql2 packages)**
```javascript
// VULNERABLE
connection.query("SELECT * FROM users WHERE id = " + userId, callback);
connection.query(`SELECT * FROM products WHERE category = '${category}'`);
connection.execute("SELECT * FROM users WHERE email = '" + email + "'");

// VULNERABLE - Multiple statements enabled
const connection = mysql.createConnection({
  multipleStatements: true  // Allows stacked queries!
});
```

**PostgreSQL (pg package)**
```javascript
// VULNERABLE
client.query("SELECT * FROM users WHERE name = '" + name + "'");
pool.query(`SELECT * FROM items WHERE id = ${itemId}`);

// VULNERABLE - Manual escaping (insufficient)
const escaped = input.replace(/'/g, "''"); // NOT SAFE!
client.query(`SELECT * FROM users WHERE email = '${escaped}'`);
```

**SQLite (sqlite3 package)**
```javascript
// VULNERABLE
db.run("INSERT INTO users VALUES ('" + username + "', '" + email + "')");
db.get(`SELECT * FROM users WHERE id = ${userId}`);
db.all("SELECT * FROM posts WHERE title LIKE '%" + searchTerm + "%'");
```

**MongoDB (NoSQL but relevant)**
```javascript
// VULNERABLE - NoSQL injection
const query = { username: req.body.username, password: req.body.password };
db.collection('users').find(query);

// VULNERABLE - $where operator
db.collection('users').find({ $where: `this.name == '${name}'` });
```

#### **ORM Vulnerabilities**

**Sequelize**
```javascript
// VULNERABLE - Raw queries
sequelize.query("SELECT * FROM users WHERE id = " + userId);
sequelize.query(`SELECT * FROM items WHERE name = '${itemName}'`);

// VULNERABLE - Literals
sequelize.literal(`COUNT(*) FILTER (WHERE status = '${status}')`);

// SAFE - Parameterized queries
sequelize.query("SELECT * FROM users WHERE id = ?", {
  replacements: [userId]
});
```

**Knex.js**
```javascript
// VULNERABLE - Raw
knex.raw("SELECT * FROM users WHERE id = " + userId);
knex.raw(`DELETE FROM products WHERE id = ${productId}`);

// SAFE - Parameterized
knex.raw("SELECT * FROM users WHERE id = ?", [userId]);
knex('users').where('id', userId);
```

**TypeORM**
```javascript
// VULNERABLE
getConnection().query("SELECT * FROM users WHERE name = '" + name + "'");
repository.query(`SELECT * FROM posts WHERE author = '${author}'`);
```

### 2. INJECTION POINTS

#### **User Input Vectors**
```javascript
// URL Parameters
app.get('/user/:id', (req, res) => {
  const id = req.params.id;  // INJECTION POINT
});

// Query Strings
app.get('/search', (req, res) => {
  const query = req.query.q;  // INJECTION POINT
});

// POST Body
app.post('/login', (req, res) => {
  const { username, password } = req.body;  // INJECTION POINTS
});

// Headers
const userAgent = req.headers['user-agent'];  // INJECTION POINT
const referer = req.headers['referer'];  // INJECTION POINT

// Cookies
const sessionId = req.cookies.sessionId;  // INJECTION POINT

// File Uploads
const filename = req.file.originalname;  // INJECTION POINT
```

#### **Dynamic Query Building**
```javascript
// VULNERABLE - Dynamic WHERE clauses
function buildQuery(filters) {
  let query = "SELECT * FROM products WHERE 1=1";
  
  if (filters.category) {
    query += " AND category = '" + filters.category + "'"; // INJECTION
  }
  if (filters.price) {
    query += " AND price <= " + filters.price; // INJECTION
  }
  return query;
}

// VULNERABLE - Dynamic ORDER BY
const sortField = req.query.sort; // INJECTION POINT
const query = `SELECT * FROM users ORDER BY ${sortField}`;

// VULNERABLE - Dynamic table/column names
const tableName = req.params.table; // INJECTION POINT
const query = `SELECT * FROM ${tableName}`;
```

### 3. HOW TO FIND SQL INJECTION VULNERABILITIES

#### **Manual Code Review Patterns**

**Search for dangerous patterns:**
```bash
# Grep for string concatenation in queries
grep -r "SELECT.*\+" .
grep -r "INSERT.*\+" .
grep -r "DELETE.*\+" .
grep -r "UPDATE.*\+" .

# Find template literals with variables in queries
grep -r "\`SELECT.*\$\{" .
grep -r "\`INSERT.*\$\{" .

# Find raw query execution
grep -r "\.query(" .
grep -r "\.execute(" .
grep -r "\.raw(" .

# Find dangerous concatenation methods
grep -r "\.concat(" .
grep -r "util\.format(" .
```

#### **Automated Scanning Tools**
```javascript
// ESLint Plugin for SQL Injection detection
npm install eslint-plugin-sql-injection

// Example .eslintrc.json
{
  "plugins": ["sql-injection"],
  "rules": {
    "sql-injection/no-sql-injection": "error"
  }
}

// Static Analysis Tools
// - Snyk: npm install -g snyk && snyk test
// - npm audit: npm audit
// - OWASP Dependency Check
```

#### **Dynamic Testing Payloads**

**Basic Detection Payloads:**
```sql
' OR '1'='1
' OR '1'='1' --
" OR "1"="1
' OR '1'='1' /*
' OR 1=1 --
admin' --
1' OR '1'='1
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

**Time-Based Blind SQLi:**
```sql
' OR SLEEP(5)--
' OR pg_sleep(5)--
' WAITFOR DELAY '0:0:5'--
' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--
```

**Error-Based Detection:**
```sql
' OR 1=CONVERT(int,@@version)--
' AND 1=CAST(@@version AS int)--
' OR extractvalue(1,concat(0x7e,database()))--
```

#### **Black-Box Testing Methodology**

```javascript
// 1. Identify all input points
const injectionPoints = [
  document.forms,           // Form inputs
  window.location.search,   // URL parameters
  document.cookie,          // Cookies
  localStorage,             // Local storage
  sessionStorage,           // Session storage
  fetch/XHR requests       // API calls
];

// 2. Test each point with SQLi payloads
const testPayloads = [
  "'", '"', '`', ';', '--', '/*',
  "' OR '1'='1", "admin' --",
  "' UNION SELECT 1--"
];

// 3. Monitor responses for:
// - Database errors
// - Different response lengths
// - Response time delays
// - Blind boolean behavior
```

### 4. SECURE CODING PATTERNS (Defense)

```javascript
// PARAMETERIZED QUERIES (Best Practice)
// MySQL
connection.execute(
  'SELECT * FROM users WHERE username = ? AND password = ?',
  [username, password]
);

// PostgreSQL
client.query(
  'SELECT * FROM users WHERE email = $1',
  [email]
);

// SQLite
db.get(
  'SELECT * FROM users WHERE id = ?',
  [userId]
);

// STORED PROCEDURES
connection.query('CALL GetUser(?)', [userId]);

// INPUT VALIDATION
const Joi = require('joi');
const schema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30),
  id: Joi.number().integer().positive()
});

// ESCAPING (Last resort, parameterized queries preferred)
const mysql = require('mysql');
const escaped = mysql.escape(userInput); // MySQL only

// WHITELISTING for dynamic values
const ALLOWED_COLUMNS = ['id', 'username', 'email', 'created_at'];
const sortBy = ALLOWED_COLUMNS.includes(req.query.sort) 
  ? req.query.sort 
  : 'id';

// ORM SAFE METHODS
User.findAll({
  where: {
    username: username // Automatically parameterized
  }
});
```

### 5. COMMON VULNERABLE NODE.JS FRAMEWORK PATTERNS

**Express.js**
```javascript
// VULNERABLE
app.get('/user/:id', (req, res) => {
  db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
});

// SAFE
app.get('/user/:id', (req, res) => {
  db.query('SELECT * FROM users WHERE id = ?', [req.params.id]);
});
```

**NestJS**
```javascript
// VULNERABLE
@Get(':id')
findOne(@Param('id') id: string) {
  return this.connection.query(`SELECT * FROM users WHERE id = ${id}`);
}

// SAFE
@Get(':id')
findOne(@Param('id') id: string) {
  return this.userRepository.findOne({ where: { id } });
}
```

### 6. DETECTION CHECKLIST

```javascript
const securityChecklist = {
  codeReview: [
    "No string concatenation in SQL queries",
    "No template literals in SQL queries",
    "All user input parameterized",
    "No dynamic table/column names from input",
    "Input validation on all user-supplied data",
    "Least privilege database accounts",
    "Stored procedures when possible"
  ],
  
  runtimeProtection: [
    "WAF (Web Application Firewall) configured",
    "Database error messages suppressed",
    "Query timeouts configured",
    "Rate limiting on endpoints",
    "SQL injection monitoring/alerting"
  ],
  
  testing: [
    "Automated SAST scanning",
    "DAST scanning in CI/CD",
    "Regular penetration testing",
    "Fuzzing with SQLi payloads",
    "Code review for new database queries"
  ]
};
```

Remember: **Never trust user input. Always use parameterized queries. Input validation is good, but parameterized queries are essential.**
