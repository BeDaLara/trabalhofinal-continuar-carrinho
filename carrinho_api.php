<?php
$allowedOrigins = [
    "http://127.0.0.1:5500",
    "http://127.0.0.1:5501",
    "http://localhost"
];

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';

if (in_array($origin, $allowedOrigins)) {
    header("Access-Control-Allow-Origin: $origin");
}
header("Access-Control-Allow-Credentials: true");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Methods: POST, GET, OPTIONS, DELETE");
header("Access-Control-Allow-Headers: Content-Type, Authorization");

// Responde imediatamente para requisições OPTIONS (pré-voo CORS)
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    http_response_code(200);
    exit();
}

$input = json_decode(file_get_contents('php://input'), true);
$userId = $input['user_id'] ?? null;

if (!$userId) {
    http_response_code(401);
    die(json_encode(['success' => false, 'message' => 'ID de usuário não fornecido']));
}

require_once 'conexao.php';

try {
    $produtoId = $input['produto_id'];
    $quantidade = $input['quantidade'] ?? 1;

    // Verifica se o produto existe
    $stmt = $conn->prepare("SELECT id FROM produto WHERE id = ?");
    $stmt->execute([$produtoId]);
    
    if ($stmt->rowCount() === 0) {
        http_response_code(404);
        die(json_encode(['success' => false, 'message' => 'Produto não encontrado']));
    }

    // Insere ou atualiza o carrinho
    $stmt = $conn->prepare("INSERT INTO carrinho (usuario_id, produto_id, quantidade) 
                           VALUES (?, ?, ?)
                           ON DUPLICATE KEY UPDATE quantidade = quantidade + VALUES(quantidade)");
    $stmt->execute([$userId, $produtoId, $quantidade]);

    echo json_encode(['success' => true, 'message' => 'Item adicionado ao carrinho']);
    
} catch (PDOException $e) {
    http_response_code(500);
    die(json_encode(['success' => false, 'message' => 'Erro no servidor']));
}