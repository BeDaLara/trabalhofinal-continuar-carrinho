<?php
// ==============================================
// CONFIGURAÇÕES INICIAIS
// ==============================================

// Habilitar relatório de erros
ini_set('display_errors', 1);
error_reporting(E_ALL);

// Garantir que não haja saída antes dos headers
if (ob_get_length()) ob_clean();

// Configurações de CORS
$allowedOrigins = [
    "http://127.0.0.1:5500",
    "http://127.0.0.1:5501", 
    "http://127.0.0.1:5502",
    "http://localhost"
];

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';

if (in_array($origin, $allowedOrigins)) {
    header("Access-Control-Allow-Origin: " . $origin);
}
header("Access-Control-Allow-Credentials: true");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Methods: POST, GET, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");

// Responder imediatamente para requisições OPTIONS
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Iniciar sessão com configurações seguras
session_set_cookie_params([
    'lifetime' => 86400,
    'path' => '/',
    'domain' => 'localhost',
    'secure' => false,
    'httponly' => true,
    'samesite' => 'Lax'
]);

session_start();

// Função para enviar erros como JSON
function sendError($message, $code = 400) {
    http_response_code($code);
    die(json_encode(['success' => false, 'message' => $message]));
}

// ==============================================
// CONEXÃO COM O BANCO DE DADOS
// ==============================================

require_once 'conexao.php';

// ==============================================
// PROCESSAMENTO DA REQUISIÇÃO
// ==============================================

try {
    // Verifica se é POST
    if ($_SERVER['REQUEST_METHOD'] != 'POST') {
        sendError('Método não permitido', 405);
    }

    // Obter os dados JSON da requisição
    $input = json_decode(file_get_contents('php://input'), true);

    // Verificar se o JSON é válido
    if (json_last_error() !== JSON_ERROR_NONE) {
        sendError('Dados JSON inválidos', 400);
    }

    // Verificar se a ação foi especificada
    if (empty($input['action'])) {
        sendError('Parâmetro "action" não especificado', 400);
    }

    // ==============================================
    // FUNÇÕES AUXILIARES
    // ==============================================

    function sanitizeInput($data) {
        $data = trim($data);
        $data = stripslashes($data);
        $data = htmlspecialchars($data);
        return $data;
    }

    function validateEmail($email) {
        return filter_var($email, FILTER_VALIDATE_EMAIL);
    }

    function validateCPF($cpf) {
        $cpf = preg_replace('/[^0-9]/', '', $cpf);
        return strlen($cpf) == 11;
    }

    // ==============================================
    // LÓGICA PRINCIPAL
    // ==============================================

    $response = [];
    
    switch ($input['action']) {
        case 'register':
            // Validação dos campos obrigatórios
            $requiredFields = ['firstName', 'lastName', 'email', 'phone', 'cpf', 'password'];
            foreach ($requiredFields as $field) {
                if (empty($input[$field])) {
                    throw new Exception("O campo {$field} é obrigatório");
                }
            }

            // Sanitização dos dados
            $firstName = sanitizeInput($input['firstName']);
            $lastName = sanitizeInput($input['lastName']);
            $email = sanitizeInput($input['email']);
            $phone = preg_replace('/[^0-9]/', '', $input['phone']);
            $cpf = preg_replace('/[^0-9]/', '', $input['cpf']);
            $password = $input['password'];

            // Validações específicas
            if (!validateEmail($email)) {
                throw new Exception("E-mail inválido");
            }

            if (!validateCPF($cpf)) {
                throw new Exception("CPF inválido");
            }

            if (strlen($password) < 6) {
                throw new Exception("A senha deve ter pelo menos 6 caracteres");
            }

            // Verificar se usuário já existe
            $stmt = $conn->prepare("SELECT id FROM users WHERE email = ? OR cpf = ?");
            $stmt->execute([$email, $cpf]);
            
            if ($stmt->rowCount() > 0) {
                throw new Exception("E-mail ou CPF já cadastrado");
            }

            // Hash da senha
            $passwordHash = password_hash($password, PASSWORD_BCRYPT);

            // Inserir novo usuário
            $stmt = $conn->prepare("INSERT INTO users 
                (first_name, last_name, email, phone, cpf, password) 
                VALUES (?, ?, ?, ?, ?, ?)");
            
            $success = $stmt->execute([
                $firstName,
                $lastName,
                $email,
                $phone,
                $cpf,
                $passwordHash
            ]);

            if (!$success || $stmt->rowCount() === 0) {
                throw new Exception("Erro ao registrar usuário no banco de dados");
            }

            $userId = $conn->lastInsertId();
            
            $response = [
                'success' => true,
                'message' => 'Usuário registrado com sucesso',
                'userId' => $userId
            ];
            
            http_response_code(201);
            break;

        case 'login':
            // Validação dos campos
            if (empty($input['email']) || empty($input['password'])) {
                throw new Exception("E-mail e senha são obrigatórios");
            }

            $email = sanitizeInput($input['email']);
            $password = $input['password'];

            // Buscar usuário
            $stmt = $conn->prepare("SELECT * FROM users WHERE email = ?");
            $stmt->execute([$email]);
            
            if ($stmt->rowCount() === 0) {
                throw new Exception("Credenciais inválidas");
            }

            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            // Verificação da senha com tratamento especial para hashes antigos
            $validPassword = password_verify($password, $user['password']);

            if (!$validPassword) {
                // Tentativa de verificação com hash antigo (se necessário)
                if (md5($password) === $user['password']) {
                    // Atualiza para o novo hash
                    $newHash = password_hash($password, PASSWORD_BCRYPT);
                    $conn->prepare("UPDATE users SET password = ? WHERE id = ?")->execute([$newHash, $user['id']]);
                    $validPassword = true;
                } else {
                    throw new Exception("Credenciais inválidas");
                }
            }

            // Configuração da sessão
            session_regenerate_id(true);
            $_SESSION = [
                'user_id' => $user['id'],
                'user_email' => $user['email'],
                'logged_in' => true,
                'is_admin' => (bool)$user['isAdmin']
            ];

            // Preparar resposta
            unset($user['password']);
            
            $response = [
                'success' => true,
                'message' => 'Login realizado com sucesso',
                'user' => [
                    'id' => $user['id'],
                    'first_name' => $user['first_name'],
                    'last_name' => $user['last_name'],
                    'email' => $user['email'],
                    'phone' => $user['phone'],
                    'avatar' => $user['avatar'] ?? null,
                    'isAdmin' => (bool)$user['isAdmin']
                ]
            ];
            break;

        default:
            throw new Exception("Ação inválida");
    }

} catch (Exception $e) {
    $response = [
        'success' => false,
        'message' => $e->getMessage()
    ];
    http_response_code(400);
}

// Garantir que a resposta seja JSON válido
if (ob_get_length()) ob_clean();
header("Content-Type: application/json");
echo json_encode($response);
exit();