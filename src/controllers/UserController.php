<?php

require_once '../config/config.php';
require_once '../models/User.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_GET['action'] ?? '';

    if($action === 'update_profile' && isLoggedIn()){
        handleUpdateProfile($pdo);
    }
}
function handleUpdateProfile($pdo) {
    // CSRF Token verify

    if(!Security::verifyCSRFToken($_POST['csrf_token'] ?? '')){
        Session::setFlash('Error', 'Token de segurança inválido.');
        header('Location: ../../public/dashboard.php');
        exit();
    }

    $user_id = $_SESSION['user_id'];
    $nome = Security::sanitizeInput($_POST['nome'] ?? '');

    // Validação
    $errors = [];
    if(!Security::validateName($nome)){
        $errors[] = "Nome deve ter entre 2 e 100 caracteres.";
    }

    if(empty($errors)){
        try{
            $sql = "UPDATE usuarios SET nome =? WHERE id =?";

            $stmt = $pdo->prepare($sql);
            if($stmt->execute([$nome, $user_id])){
                $_SESSION['user_nome'] = $nome;

                Session::setFlash('Success' , "Perfil atualizado com sucesso.");
            }

            else{
                $error[] = "Erro ao atualizar o perfil: ";
            }

        }catch(Exception $e){
            error_log("Erro ao atualizar o perfil: " . $e->getMessage());
            $error[] = "Erro no sistema. Tente novamente";
        }
    }

    if(!empty($errors)) {
        Session::setFlash('error', implode('<br>', $errors));
    }

    header('Location: ../../public/dashboard.php');
    exit();

}
?>