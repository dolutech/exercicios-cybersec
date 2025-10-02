<?php
/* Lab Web Vulnerável — NÃO usar em produção.
 * Funcionalidades: init DB SQLite, login SQLi, busca SQLi, comentários com XSS, LFI via file_get_contents.
 */

ini_set('display_errors', 1);
error_reporting(E_ALL);

$dbFile = __DIR__ . '/database.db';

function db() {
    global $dbFile;
    static $pdo = null;
    if ($pdo === null) {
        $pdo = new PDO('sqlite:' . $dbFile);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    }
    return $pdo;
}

function init_db() {
    $pdo = db();
    // Cria tabelas se não existirem
    $pdo->exec("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    );");
    $pdo->exec("CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        author TEXT,
        content TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );");
    // Semeia utilizador admin se não existir
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE username='admin';");
    if ($stmt->execute() && $stmt->fetchColumn() == 0) {
        $pdo->exec("INSERT INTO users (username, password) VALUES ('admin','admin123');");
        $pdo->exec("INSERT INTO users (username, password) VALUES ('bob','bob123');");
    }
}
init_db();

function h($s){ return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }

$action = $_GET['action'] ?? ($_POST['action'] ?? null);

// Roteamento simples
if ($action === 'login' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $u = $_POST['username'] ?? '';
    $p = $_POST['password'] ?? '';

    // VULNERAVEL: CONCATENAÇÃO DIRETA (SQLi)
    $sql = "SELECT * FROM users WHERE username='$u' AND password='$p' LIMIT 1;";
    try {
        $res = db()->query($sql)->fetch(PDO::FETCH_ASSOC);
        echo "<h2>Login</h2>";
        echo "<p>Query executada (vulnerável): <code>" . h($sql) . "</code></p>";
        if ($res) {
            echo "<p>Autenticado como <strong>" . h($res['username']) . "</strong></p>";
            echo "<p>Prossiga com enumeração de sessão simulada.</p>";
        } else {
            echo "<p>Falha de autenticação.</p>";
        }
    } catch (Exception $e) {
        echo "<p>Erro: " . h($e->getMessage()) . "</p>";
    }
    echo '<p><a href="index.html">Voltar</a></p>';
    exit;
}

if ($action === 'search') {
    $q = $_GET['q'] ?? '';

    // VULNERAVEL: LIKE com entrada direta (SQLi via GET)
    $sql = "SELECT id, username FROM users WHERE username LIKE '%$q%';";
    echo "<h2>Pesquisa</h2>";
    echo "<p>Query executada (vulnerável): <code>" . h($sql) . "</code></p>";
    try {
        $rows = db()->query($sql)->fetchAll(PDO::FETCH_ASSOC);
        if ($rows) {
            echo "<ul>";
            foreach ($rows as $r) {
                echo "<li>ID " . h($r['id']) . " — " . h($r['username']) . "</li>";
            }
            echo "</ul>";
        } else {
            echo "<p>Sem resultados.</p>";
        }
    } catch (Exception $e) {
        echo "<p>Erro: " . h($e->getMessage()) . "</p>";
    }
    echo '<p><a href="index.html">Voltar</a></p>';
    exit;
}

if ($action === 'comment' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $author = $_POST['author'] ?? 'anon';
    $content = $_POST['content'] ?? '';

    // Inserção "normal" (sem blindagem de saída posterior).
    $stmt = db()->prepare("INSERT INTO comments (author, content) VALUES (:a, :c)");
    $stmt->execute([':a' => $author, ':c' => $content]);

    echo "<h2>Comentário publicado</h2>";
    echo "<p>Autor: <strong>" . h($author) . "</strong></p>";
    echo "<p>Conteúdo guardado <em>sem sanitização</em> e exibido cru na listagem (XSS armazenado).</p>";
    echo '<p><a href="app.php?action=list_comments">Ver comentários</a></p>';
    echo '<p><a href="index.html">Voltar</a></p>';
    exit;
}

if ($action === 'list_comments') {
    echo "<h2>Comentários (vulnerável a XSS armazenado)</h2>";
    $rows = db()->query("SELECT author, content, created_at FROM comments ORDER BY id DESC;")->fetchAll(PDO::FETCH_ASSOC);
    if ($rows) {
        echo "<ul>";
        foreach ($rows as $r) {
            // VULNERAVEL: saída sem htmlspecialchars => XSS
            echo "<li><strong>" . h($r['author']) . "</strong> em " . h($r['created_at']) . "<br>" . $r['content'] . "</li>";
        }
        echo "</ul>";
    } else {
        echo "<p>Nenhum comentário.</p>";
    }
    echo '<p>Exemplo de payload: <code>&lt;script&gt;alert("XSS")&lt;/script&gt;</code></p>';
    echo '<p><a href="index.html">Voltar</a></p>';
    exit;
}

if ($action === 'view') {
    $file = $_GET['file'] ?? 'app.php';
    echo "<h2>Leitura de ficheiro (LFI)</h2>";
    echo "<p>Parâmetro <code>file</code> recebido: <code>" . h($file) . "</code></p>";
    echo "<p>Conteúdo bruto abaixo:</p><pre style='white-space:pre-wrap;border:1px solid #ccc;padding:8px;'>";
    // VULNERAVEL: leitura de caminho arbitrário, potencial RFI se allow_url_fopen=On
    try {
        $content = @file_get_contents($file);
        if ($content === false) {
            echo h("Falha ao ler o ficheiro.");
        } else {
            echo htmlspecialchars($content, ENT_NOQUOTES, 'UTF-8');
        }
    } catch (Exception $e) {
        echo h("Erro: " . $e->getMessage());
    }
    echo "</pre>";
    echo "<p>Experimente: <code>../../etc/hosts</code> ou <code>php://filter/convert.base64-encode/resource=app.php</code></p>";
    echo '<p><a href="index.html">Voltar</a></p>';
    exit;
}

// Fallback
header('Location: index.html');
