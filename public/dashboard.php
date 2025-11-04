<?php

date_default_timezone_set('America/Sao_Paulo');

require_once '../src/config/config.php';
require_once '../src/models/User.php';
requireLogin();

try{
    // Search user data
    $userModel = new User($pdo);
    $usuario = $userModel->findById($_SESSION['user_id']);

    if(!$usuario){
        session_destroy();
        header('Location: login.php');
        exit();
    }

    // Login history
    $loginHistory = $userModel->getLoginHistory($_SESSION['user_id'], 5);

} catch(PDOException $e){
    error_log("Erro ao iniciar a conta: " . $e->getMessage(), 3, "../logs/errors.log");
    die("Error to load the page.");
}

$csrf_token = Security::generateCSFRToken();
?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <link rel="stylesheet" href="./assets/CSS/style.css">
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="dashboard-header">
                <div>
                    <h1>Welcome</h1>
                </div>
                <div class="user-info">
                    <span><strong><?php echo htmlspecialchars($usuario['nome'], ENT_QUOTES, 'UTF-8'); ?></strong></span>
                    <a href="logout.php" class="btn btn-danger">Logout</a>
                </div>
            </div>

             <?php
            $success = Session::getFlash('success');
            $error = Session::getFlash('error');

            if($success): ?>
                <div class="alert alert-success">
                    <?php echo $success; ?>
                </div>
            <?php endif;

            if($error): ?>
                <div class="alert alert-error">
                    <?php echo $error?>
                </div>
            <?php endif?>

            <div class="info-card">
                <h3>Informações da conta</h3>
                <ul class="info-list">
                    <p><strong>ID: </strong><?php echo $usuario['id'];?></p>
                    <p><strong>NOME: </strong><?php echo htmlspecialchars($usuario['nome']);?></p>
                    <p><strong>EMAIL: </strong><?php echo htmlspecialchars($usuario['email']);?></p>
                    <p><strong>DATA CADASTRO: </strong><?php echo date('d/m/Y H:i', strtotime($usuario['data_cadastro']))?></p>
                    <p><strong>ÚLTIMO LOGIN: </strong><?php echo $usuario['ultimo_login'] ? date('d/m/Y H:i', strtotime($usuario['ultimo_login'])) :'Primeiro login';?></p>
                </ul>
            </div>

            <div class="info-card">
                <h3>Segurança</h3>
                <div class="security-status">
                    <p>☑️ Sessão segura</p>
                    <p>☑️ Autenticação validada</p>
                    <p>☑️ Conexão criptografada</p>
                    <p>Sessão iniciada: <?php echo date('H:i:s');?></p>
                </div>
            </div>

            <div class="info-card">
                <h3>Atualizar perfil</h3>
                <form action="../src/controllers/AuthController.php?action=update_profile" method="POST" class="form">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">

                    <div class="form-group">
                        <label for="nome">Nome completo: </label>
                        <input type="text" name="nome" id="nome" required value="<?php echo htmlspecialchars($usuario['nome'])?>" minlength="2" maxlength="100">
                    </div>
                    <button type="submit" class="btn btn-secundary">Atualizar</button>

                </form>
            </div>

            <?php if(!empty($loginHistory)): ?>

                <div class="info-card">
                    <h3>Histórico de login</h3>

                    <div class="history-list"> 
                        <?php foreach ($loginHistory as $log): ?>
                            <div class="history-item>
                                <?php echo $log['sucesso'] ? 'success' : 'error'; ?>">
                                <span class="action"> <?php echo $log['acao']; ?></span>

                                <span class="date"> <?php echo date('d/M/Y H:i', strtotime($log['data_acesso'])); ?> </span>

                                <span class="ip"><?php echo $log['ip_address']; ?></span>

                                <span class="status"> <?php echo $log['sucesso'] ? '☑️' : 'X'; ?> </span>
                            </div>
                        <?php endforeach; ?>
                    </div>

                </div>

            <?php endif; ?>
        </div>
        <div class="actions">
            <a href="index.php" class="btn btn-secondary">Página inicial</a>
            <a href="logout.php" class="btn btn-danger">Logout</a>
        </div>
    </div>
</body>
</html>