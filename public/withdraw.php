<?php

date_default_timezone_set('America/Sao_Paulo');

require_once '../src/config/config.php';
requireLogin();

$csrf_token = Security::generateCSFRToken();
?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sacar Dinheiro - Sistema Seguro</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-sRIl4kxILFvY47J16cr9ZwB07vP4J8+LH7qKQnuqIAvNWLzeN8tE5YBujZqJLB" crossorigin="anonymous">
    <link rel="stylesheet" href="./assets/CSS/style.css">
</head>
<body class="bg-light">
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-lg-8">
                <div class="card shadow-lg">
                    <div class="card-header bg-success text-white text-center">
                        <h1 class="mb-0">Sacar Dinheiro</h1>
                    </div>
                    <div class="card-body">
                        <?php
                        $success = Session::getFlash('success');
                        $error = Session::getFlash('error');

                        if($success): ?>
                            <div class="alert alert-success">
                                <?php echo $success; ?>
                            </div>
                        <?php endif;

                        if($error): ?>
                            <div class="alert alert-danger">
                                <?php echo $error; ?>
                            </div>
                        <?php endif; ?>

                        <div class="alert alert-info">
                            <strong>Saldo Atual:</strong> 1000 moedas (R$ 100,00)
                        </div>

                        <form action="../src/controllers/AuthController.php?action=withdraw" method="POST">
                            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">

                            <div class="mb-3">
                                <label for="withdraw_amount" class="form-label">Valor para Sacar (em moedas):</label>
                                <input type="number" name="withdraw_amount" id="withdraw_amount" class="form-control" min="10" max="1000" required placeholder="Mínimo 10 moedas">
                            </div>

                            <h5>Informações do Cartão de Crédito</h5>
                            <div class="row">
                                <div class="col-md-6 mb-3">
                                    <label for="card_number" class="form-label">Número do Cartão:</label>
                                    <input type="text" name="card_number" id="card_number" class="form-control" required placeholder="1234 5678 9012 3456" maxlength="19">
                                </div>
                                <div class="col-md-3 mb-3">
                                    <label for="expiry_date" class="form-label">Data de Expiração:</label>
                                    <input type="text" name="expiry_date" id="expiry_date" class="form-control" required placeholder="MM/AA" maxlength="5">
                                </div>
                                <div class="col-md-3 mb-3">
                                    <label for="cvv" class="form-label">CVV:</label>
                                    <input type="text" name="cvv" id="cvv" class="form-control" required placeholder="123" maxlength="4">
                                </div>
                            </div>

                            <div class="mb-3">
                                <label for="cardholder_name" class="form-label">Nome no Cartão:</label>
                                <input type="text" name="cardholder_name" id="cardholder_name" class="form-control" required placeholder="Nome como aparece no cartão">
                            </div>

                            <div class="d-grid">
                                <button type="submit" class="btn btn-success btn-lg">Solicitar Saque</button>
                            </div>
                        </form>

                        <div class="text-center mt-4">
                            <a href="casinoPlane.php" class="btn btn-secondary me-2">Voltar ao Casino</a>
                            <a href="dashboard.php" class="btn btn-primary">Dashboard</a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js" integrity="sha384-w76AqPfDkMBDXo30jS1Sgez6pr3x5MlQ1ZAGC+nuZB+EYdgRZgiwxhTBTkF7CXvN" crossorigin="anonymous"></script>
    <script>
        // Format card number
        document.getElementById('card_number').addEventListener('input', function(e) {
            let value = e.target.value.replace(/\D/g, '');
            value = value.replace(/(\d{4})(?=\d)/g, '$1 ');
            e.target.value = value;
        });

        // Format expiry date
        document.getElementById('expiry_date').addEventListener('input', function(e) {
            let value = e.target.value.replace(/\D/g, '');
            if (value.length >= 2) {
                value = value.slice(0, 2) + '/' + value.slice(2, 4);
            }
            e.target.value = value;
        });

        // Only allow numbers for CVV
        document.getElementById('cvv').addEventListener('input', function(e) {
            e.target.value = e.target.value.replace(/\D/g, '');
        });
    </script>
</body>
</html>
