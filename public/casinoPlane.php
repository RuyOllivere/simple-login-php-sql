<?php

date_default_timezone_set('America/Sao_Paulo');

require_once '../src/config/config.php';
require_once '../src/models/User.php';
requireLogin();

$csrf_token = Security::generateCSFRToken();

$userModel = new User($pdo);
$user = $userModel->findById($_SESSION['user_id']);
$userCoins = $user ? $user['coins'] : 100;
?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Casino Plane - Aviator Game</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-sRIl4kxILFvY47J16cr9ZwB07vP4J8+LH7qKQnuqIAvNWLzeN8tE5YBujZqJLB" crossorigin="anonymous">
    <link rel="stylesheet" href="./assets/CSS/style.css">
    <style>
        body {
            background: linear-gradient(135deg, #000000 0%, #1a1a1a 100%);
            color: #FFD700;
            font-family: 'Arial', sans-serif;
        }
        .card {
            background: linear-gradient(135deg, #2a2a2a 0%, #1a1a1a 100%);
            border: 2px solid #FFD700;
            border-radius: 15px;
            box-shadow: 0 0 30px rgba(255, 215, 0, 0.3);
        }
        .card-header {
            background: linear-gradient(135deg, #FFD700 0%, #FFA500 100%);
            border-bottom: 2px solid #FFD700;
            color: #000000;
            font-weight: bold;
        }
        #game-canvas {
            border: 3px solid #FFD700;
            background: linear-gradient(135deg, #000000 0%, #1a1a1a 50%, #2a2a2a 100%);
            position: relative;
            overflow: hidden;
            border-radius: 10px;
            box-shadow: inset 0 0 50px rgba(255, 215, 0, 0.2);
        }
        #multiplier {
            position: absolute;
            top: 20px;
            left: 20px;
            font-size: 2.5rem;
            font-weight: bold;
            color: #FFD700;
            text-shadow: 0 0 20px rgba(255, 215, 0, 0.8), 2px 2px 4px rgba(0,0,0,0.8);
            z-index: 10;
        }
        .bet-controls {
            background: linear-gradient(135deg, #333333 0%, #1a1a1a 100%);
            padding: 20px;
            border-radius: 10px;
            border: 2px solid #FFD700;
        }
        .bet-controls h4 {
            color: #FFD700;
            text-align: center;
            margin-bottom: 20px;
            text-shadow: 0 0 10px rgba(255, 215, 0, 0.5);
        }
        .form-control {
            background: #333333;
            border: 2px solid #FFD700;
            color: #FFD700;
            border-radius: 5px;
        }
        .form-control:focus {
            background: #333333;
            border-color: #FFA500;
            color: #FFD700;
            box-shadow: 0 0 10px rgba(255, 215, 0, 0.5);
        }
        .form-label {
            color: #FFD700;
            font-weight: bold;
        }
        .btn {
            border: none;
            border-radius: 8px;
            font-weight: bold;
            text-transform: uppercase;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(255, 215, 0, 0.3);
        }
        .btn-success {
            background: linear-gradient(135deg, #FFD700 0%, #FFA500 100%);
            color: #000000;
        }
        .btn-success:hover {
            background: linear-gradient(135deg, #FFA500 0%, #FFD700 100%);
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(255, 215, 0, 0.5);
        }
        .btn-warning {
            background: linear-gradient(135deg, #FFA500 0%, #FF8C00 100%);
            color: #000000;
        }
        .btn-warning:hover {
            background: linear-gradient(135deg, #FF8C00 0%, #FFA500 100%);
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(255, 140, 0, 0.5);
        }
        .btn-secondary {
            background: linear-gradient(135deg, #666666 0%, #333333 100%);
            color: #FFD700;
        }
        .btn-secondary:hover {
            background: linear-gradient(135deg, #333333 0%, #666666 100%);
            transform: translateY(-2px);
        }
        .alert {
            border: 2px solid #FFD700;
            border-radius: 8px;
            font-weight: bold;
        }
        .alert-info {
            background: linear-gradient(135deg, #333333 0%, #1a1a1a 100%);
            color: #FFD700;
        }
        .alert-warning {
            background: linear-gradient(135deg, #FFA500 0%, #FF8C00 100%);
            color: #000000;
        }
        .alert-danger {
            background: linear-gradient(135deg, #8B0000 0%, #DC143C 100%);
            color: #FFD700;
        }
        .alert-success {
            background: linear-gradient(135deg, #FFD700 0%, #FFA500 100%);
            color: #000000;
        }
        #balance {
            font-size: 1.2rem;
            font-weight: bold;
            color: #FFD700;
            text-align: center;
            text-shadow: 0 0 10px rgba(255, 215, 0, 0.5);
        }
    </style>
</head>
<body class="bg-dark">
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-lg-10">
                <div class="card shadow-lg">
                    <div class="card-header bg-primary text-white text-center">
                        <h1 class="mb-0">Casino Plane - Aviator</h1>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-8">
                                <canvas id="game-canvas" width="600" height="400"></canvas>
                                <div id="multiplier">1.00x</div>
                            </div>
                            <div class="col-md-4">
                                <div class="bet-controls">
                                    <h4>Controle de Aposta</h4>
                                    <div class="mb-3">
                                        <label for="bet-amount" class="form-label">Valor da Aposta:</label>
                                        <input type="number" id="bet-amount" class="form-control" min="1" max="1000" value="10">
                                    </div>
                                    <button id="place-bet" class="btn btn-success w-100 mb-2">Fazer Aposta</button>
                                    <button id="cash-out" class="btn btn-warning w-100 mb-2" disabled>Cash Out</button>
                                    <div id="bet-status" class="alert alert-info">Aguardando aposta...</div>
                                    <div id="balance" class="mt-3">Saldo: <?php echo $userCoins; ?> moedas</div>
                                    <button id="withdraw-btn" class="btn btn-success w-100 mt-2">Sacar Dinheiro</button>
                                </div>
                            </div>
                        </div>
                        <div class="text-center mt-4">
                            <a href="dashboard.php" class="btn btn-secondary">Voltar ao Dashboard</a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js" integrity="sha384-w76AqPfDkMBDXo30jS1Sgez6pr3x5MlQ1ZAGC+nuZB+EYdgRZgiwxhTBTkF7CXvN" crossorigin="anonymous"></script>
    <script>
        const canvas = document.getElementById('game-canvas');
        const ctx = canvas.getContext('2d');
        const multiplierDisplay = document.getElementById('multiplier');
        const placeBetBtn = document.getElementById('place-bet');
        const cashOutBtn = document.getElementById('cash-out');
        const betStatus = document.getElementById('bet-status');
        const balanceDisplay = document.getElementById('balance');
        const betAmountInput = document.getElementById('bet-amount');

        let balance = <?php echo $userCoins; ?>;
        let currentBet = 0;
        let multiplier = 1.00;
        let gameRunning = false;
        let crashed = false;
        let planeX = 50;
        let planeY = canvas.height - 50;
        let animationId;

        function drawPlane() {
            ctx.clearRect(0, 0, canvas.width, canvas.height);

            // Draw background with golden blur effect
            const gradient = ctx.createRadialGradient(canvas.width/2, canvas.height/2, 0, canvas.width/2, canvas.height/2, 300);
            gradient.addColorStop(0, 'rgba(255, 215, 0, 0.1)');
            gradient.addColorStop(0.5, 'rgba(255, 215, 0, 0.05)');
            gradient.addColorStop(1, 'rgba(0, 0, 0, 0.8)');
            ctx.fillStyle = gradient;
            ctx.fillRect(0, 0, canvas.width, canvas.height);

            // Draw ground
            ctx.fillStyle = '#333333';
            ctx.fillRect(0, canvas.height - 30, canvas.width, 30);

            // Draw plane with golden glow
            ctx.shadowColor = '#FFD700';
            ctx.shadowBlur = 20;
            ctx.fillStyle = '#FFD700';
            ctx.fillRect(planeX, planeY, 35, 12);
            // Draw wings with glow
            ctx.fillRect(planeX + 5, planeY - 6, 25, 6);
            ctx.fillRect(planeX + 5, planeY + 12, 25, 6);
            // Draw tail
            ctx.fillRect(planeX - 5, planeY + 3, 8, 6);

            // Reset shadow
            ctx.shadowBlur = 0;
        }

        function updateMultiplier() {
            multiplier += 0.01;
            multiplierDisplay.textContent = multiplier.toFixed(2) + 'x';
        }

        function startGame() {
            if (gameRunning) return;
            gameRunning = true;
            crashed = false;
            multiplier = 1.00;
            planeX = 50;
            planeY = canvas.height - 50;
            cashOutBtn.disabled = false;
            betStatus.textContent = 'Jogo em andamento...';
            betStatus.className = 'alert alert-warning';

            const crashPoint = Math.random() * 10 + 1; // Random crash between 1x and 11x

            function animate() {
                if (!gameRunning) return;

                updateMultiplier();
                planeX += 2;
                planeY -= 1;

                if (planeX > canvas.width) {
                    planeX = 0;
                }

                drawPlane();

                if (multiplier >= crashPoint) {
                    crash();
                    return;
                }

                animationId = requestAnimationFrame(animate);
            }

            animate();
        }

        function crash() {
            gameRunning = false;
            crashed = true;
            cancelAnimationFrame(animationId);
            betStatus.textContent = 'Avião caiu! Você perdeu sua aposta.';
            betStatus.className = 'alert alert-danger';
            cashOutBtn.disabled = true;
            placeBetBtn.disabled = false;
            currentBet = 0;
        }

        function cashOut() {
            if (!gameRunning || crashed) return;
            gameRunning = false;
            cancelAnimationFrame(animationId);
            const winnings = currentBet * multiplier;
            balance += winnings - currentBet;
            balanceDisplay.textContent = `Saldo: ${balance.toFixed(2)} moedas`;
            betStatus.textContent = `Cash out realizado! Você ganhou ${(winnings - currentBet).toFixed(2)} moedas.`;
            betStatus.className = 'alert alert-success';
            cashOutBtn.disabled = true;
            placeBetBtn.disabled = false;
            currentBet = 0;
        }

        placeBetBtn.addEventListener('click', () => {
            const betAmount = parseInt(betAmountInput.value);
            if (betAmount > balance) {
                betStatus.textContent = 'Saldo insuficiente!';
                betStatus.className = 'alert alert-danger';
                return;
            }
            currentBet = betAmount;
            balance -= betAmount;
            balanceDisplay.textContent = `Saldo: ${balance.toFixed(2)} moedas`;
            betStatus.textContent = `Aposta de ${betAmount} moedas feita. Avião decolando...`;
            betStatus.className = 'alert alert-info';
            placeBetBtn.disabled = true;
            startGame();
        });

        cashOutBtn.addEventListener('click', cashOut);

        document.getElementById('withdraw-btn').addEventListener('click', () => {
            window.location.href = 'withdraw.php';
        });

        // Function to save balance to database
        async function saveBalanceToDB() {
            try {
                const formData = new FormData();
                formData.append('csrf_token', '<?php echo $csrf_token; ?>');
                formData.append('balance', balance);

                const response = await fetch('../src/controllers/AuthController.php?action=update_coins', {
                    method: 'POST',
                    body: formData
                });

                const result = await response.json();
                if (!result.success) {
                    console.error('Error saving balance:', result.error);
                }
            } catch (error) {
                console.error('Error saving balance:', error);
            }
        }

        // Save balance when it changes
        let lastBalance = balance;
        setInterval(() => {
            if (balance !== lastBalance) {
                saveBalanceToDB();
                lastBalance = balance;
            }
        }, 1000); // Save every second when balance changes

        drawPlane();
    </script>
</body>
</html>

<!--
?php
// date_default_timezone_set('America/Sao_Paulo');

// require_once '../src/config/config.php';
// require_once '../src/models/User.php';
// requireLogin();

// $csrf_token = Security::generateCSFRToken();

// $userModel = new User($pdo);
// $user = $userModel->findById($_SESSION['user_id']);
// $userCoins = $user ? $user['coins'] : 100;
// ?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Casino Plane - Aviator Game</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-sRIl4kxILFvY47J16cr9ZwB07vP4J8+LH7qKQnuqIAvNWLzeN8tE5YBujZqJLB" crossorigin="anonymous">
    <link rel="stylesheet" href="./assets/CSS/style.css">
    <style>
        body {
            background: linear-gradient(135deg, #000000 0%, #1a1a1a 100%);
            color: #FFD700;
            font-family: 'Arial', sans-serif;
        }
        .card {
            background: linear-gradient(135deg, #2a2a2a 0%, #1a1a1a 100%);
            border: 2px solid #FFD700;
            border-radius: 15px;
            box-shadow: 0 0 30px rgba(255, 215, 0, 0.3);
        }
        .card-header {
            background: linear-gradient(135deg, #FFD700 0%, #FFA500 100%);
            border-bottom: 2px solid #FFD700;
            color: #000000;
            font-weight: bold;
        }
        #game-canvas {
            border: 3px solid #FFD700;
            background: linear-gradient(135deg, #000000 0%, #1a1a1a 50%, #2a2a2a 100%);
            position: relative;
            overflow: hidden;
            border-radius: 10px;
            box-shadow: inset 0 0 50px rgba(255, 215, 0, 0.2);
        }
        #multiplier {
            position: absolute;
            top: 20px;
            left: 20px;
            font-size: 2.5rem;
            font-weight: bold;
            color: #FFD700;
            text-shadow: 0 0 20px rgba(255, 215, 0, 0.8), 2px 2px 4px rgba(0,0,0,0.8);
            z-index: 10;
        }
        .bet-controls {
            background: linear-gradient(135deg, #333333 0%, #1a1a1a 100%);
            padding: 20px;
            border-radius: 10px;
            border: 2px solid #FFD700;
        }
        .bet-controls h4 {
            color: #FFD700;
            text-align: center;
            margin-bottom: 20px;
            text-shadow: 0 0 10px rgba(255, 215, 0, 0.5);
        }
        .form-control {
            background: #333333;
            border: 2px solid #FFD700;
            color: #FFD700;
            border-radius: 5px;
        }
        .form-control:focus {
            background: #333333;
            border-color: #FFA500;
            color: #FFD700;
            box-shadow: 0 0 10px rgba(255, 215, 0, 0.5);
        }
        .form-label {
            color: #FFD700;
            font-weight: bold;
        }
        .btn {
            border: none;
            border-radius: 8px;
            font-weight: bold;
            text-transform: uppercase;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(255, 215, 0, 0.3);
        }
        .btn-success {
            background: linear-gradient(135deg, #FFD700 0%, #FFA500 100%);
            color: #000000;
        }
        .btn-success:hover {
            background: linear-gradient(135deg, #FFA500 0%, #FFD700 100%);
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(255, 215, 0, 0.5);
        }
        .btn-warning {
            background: linear-gradient(135deg, #FFA500 0%, #FF8C00 100%);
            color: #000000;
        }
        .btn-warning:hover {
            background: linear-gradient(135deg, #FF8C00 0%, #FFA500 100%);
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(255, 140, 0, 0.5);
        }
        .btn-secondary {
            background: linear-gradient(135deg, #666666 0%, #333333 100%);
            color: #FFD700;
        }
        .btn-secondary:hover {
            background: linear-gradient(135deg, #333333 0%, #666666 100%);
            transform: translateY(-2px);
        }
        .alert {
            border: 2px solid #FFD700;
            border-radius: 8px;
            font-weight: bold;
        }
        .alert-info {
            background: linear-gradient(135deg, #333333 0%, #1a1a1a 100%);
            color: #FFD700;
        }
        .alert-warning {
            background: linear-gradient(135deg, #FFA500 0%, #FF8C00 100%);
            color: #000000;
        }
        .alert-danger {
            background: linear-gradient(135deg, #8B0000 0%, #DC143C 100%);
            color: #FFD700;
        }
        .alert-success {
            background: linear-gradient(135deg, #FFD700 0%, #FFA500 100%);
            color: #000000;
        }
        #balance {
            font-size: 1.2rem;
            font-weight: bold;
            color: #FFD700;
            text-align: center;
            text-shadow: 0 0 10px rgba(255, 215, 0, 0.5);
        }
    </style>
</head>
<body class="bg-dark">
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-lg-10">
                <div class="card shadow-lg">
                    <div class="card-header bg-primary text-white text-center">
                        <h1 class="mb-0">Casino Plane - Aviator</h1>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-8 position-relative">
                                <canvas id="game-canvas" width="600" height="400"></canvas>
                                <div id="multiplier">1.00x</div>
                            </div>
                            <div class="col-md-4">
                                <div class="bet-controls">
                                    <h4>Controle de Aposta</h4>
                                    <div class="mb-3">
                                        <label for="bet-amount" class="form-label">Valor da Aposta:</label>
                                        <input type="number" id="bet-amount" class="form-control" min="1" max="1000" value="10">
                                    </div>
                                    <button id="place-bet" class="btn btn-success w-100 mb-2">Fazer Aposta</button>
                                    <button id="cash-out" class="btn btn-warning w-100 mb-2" disabled>Cash Out</button>
                                    <div id="bet-status" class="alert alert-info">Aguardando aposta...</div>
                                    <div id="balance" class="mt-3">Saldo: <?php echo $userCoins; ?> moedas</div>
                                    <button id="withdraw-btn" class="btn btn-success w-100 mt-2">Sacar Dinheiro</button>
                                </div>
                            </div>
                        </div>
                        <div class="text-center mt-4">
                            <a href="dashboard.php" class="btn btn-secondary">Voltar ao Dashboard</a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

<script>
const canvas = document.getElementById('game-canvas');
const ctx = canvas.getContext('2d');
const multiplierDisplay = document.getElementById('multiplier');
const placeBetBtn = document.getElementById('place-bet');
const cashOutBtn = document.getElementById('cash-out');
const betStatus = document.getElementById('bet-status');
const balanceDisplay = document.getElementById('balance');
const betAmountInput = document.getElementById('bet-amount');

let balance = <?php echo $userCoins; ?>;
let currentBet = 0;
let multiplier = 1.00;
let gameRunning = false;
let crashed = false;
let planeX = 50;
let planeY = canvas.height - 50;
let animationId;
let trail = [];

// --- VISUAL MELHORADO DO JOGO ---
function drawBackground() {
    const gradient = ctx.createLinearGradient(0, 0, 0, canvas.height);
    gradient.addColorStop(0, '#000000');
    gradient.addColorStop(1, '#1a1a1a');
    ctx.fillStyle = gradient;
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    ctx.strokeStyle = 'rgba(255, 215, 0, 0.1)';
    ctx.lineWidth = 1;
    for (let i = 50; i < canvas.height; i += 50) {
        ctx.beginPath();
        ctx.moveTo(0, i);
        ctx.lineTo(canvas.width, i);
        ctx.stroke();
    }
}

function drawPlane(x, y) {
    ctx.save();
    ctx.translate(x, y);
    ctx.shadowColor = '#FFD700';
    ctx.shadowBlur = 15;
    ctx.fillStyle = '#FFD700';

    // Corpo principal
    ctx.beginPath();
    ctx.moveTo(0, 0);
    ctx.lineTo(30, -5);
    ctx.lineTo(40, 0);
    ctx.lineTo(30, 5);
    ctx.closePath();
    ctx.fill();

    // Asa
    ctx.beginPath();
    ctx.moveTo(10, -5);
    ctx.lineTo(25, -15);
    ctx.lineTo(20, -5);
    ctx.closePath();
    ctx.fill();

    // Cauda
    ctx.beginPath();
    ctx.moveTo(0, 0);
    ctx.lineTo(-10, -3);
    ctx.lineTo(-10, 3);
    ctx.closePath();
    ctx.fill();
    ctx.restore();
}

function drawTrail() {
    if (trail.length < 2) return;
    ctx.beginPath();
    ctx.moveTo(trail[0].x, trail[0].y);
    for (let i = 1; i < trail.length; i++) {
        ctx.lineTo(trail[i].x, trail[i].y);
    }
    const grad = ctx.createLinearGradient(0, 0, canvas.width, 0);
    grad.addColorStop(0, 'rgba(255,215,0,0)');
    grad.addColorStop(1, 'rgba(255,215,0,0.8)');
    ctx.strokeStyle = grad;
    ctx.lineWidth = 2;
    ctx.stroke();
}

function updateMultiplier() {
    multiplier += 0.02;
    multiplierDisplay.textContent = multiplier.toFixed(2) + 'x';
}

function startGame() {
    if (gameRunning) return;
    gameRunning = true;
    crashed = false;
    multiplier = 1.00;
    planeX = 50;
    planeY = canvas.height - 50;
    trail = [{x: planeX, y: planeY}];
    cashOutBtn.disabled = false;
    betStatus.textContent = 'Jogo em andamento...';
    betStatus.className = 'alert alert-warning';

    const crashPoint = Math.random() * 10 + 1;

    function animate() {
        if (!gameRunning) return;
        updateMultiplier();
        planeX += 3;
        planeY -= Math.pow(multiplier / 2, 1.2);
        trail.push({x: planeX, y: planeY});
        if (trail.length > 200) trail.shift();

        ctx.clearRect(0, 0, canvas.width, canvas.height);
        drawBackground();
        drawTrail();
        drawPlane(planeX, planeY);

        if (multiplier >= crashPoint || planeY < 20) {
            crash();
            return;
        }
        animationId = requestAnimationFrame(animate);
    }
    animate();
}

function crash() {
    gameRunning = false;
    crashed = true;
    cancelAnimationFrame(animationId);
    betStatus.textContent = 'Avião caiu! Você perdeu sua aposta.';
    betStatus.className = 'alert alert-danger';
    cashOutBtn.disabled = true;
    placeBetBtn.disabled = false;
    currentBet = 0;
}

function cashOut() {
    if (!gameRunning || crashed) return;
    gameRunning = false;
    cancelAnimationFrame(animationId);
    const winnings = currentBet * multiplier;
    balance += winnings - currentBet;
    balanceDisplay.textContent = `Saldo: ${balance.toFixed(2)} moedas`;
    betStatus.textContent = `Cash out realizado! Você ganhou ${(winnings - currentBet).toFixed(2)} moedas.`;
    betStatus.className = 'alert alert-success';
    cashOutBtn.disabled = true;
    placeBetBtn.disabled = false;
    currentBet = 0;
}

placeBetBtn.addEventListener('click', () => {
    const betAmount = parseInt(betAmountInput.value);
    if (betAmount > balance) {
        betStatus.textContent = 'Saldo insuficiente!';
        betStatus.className = 'alert alert-danger';
        return;
    }
    currentBet = betAmount;
    balance -= betAmount;
    balanceDisplay.textContent = `Saldo: ${balance.toFixed(2)} moedas`;
    betStatus.textContent = `Aposta de ${betAmount} moedas feita. Avião decolando...`;
    betStatus.className = 'alert alert-info';
    placeBetBtn.disabled = true;
    startGame();
});

cashOutBtn.addEventListener('click', cashOut);

document.getElementById('withdraw-btn').addEventListener('click', () => {
    window.location.href = 'withdraw.php';
});

async function saveBalanceToDB() {
    try {
        const formData = new FormData();
        formData.append('csrf_token', '<?php echo $csrf_token; ?>');
        formData.append('balance', balance);
        const response = await fetch('../src/controllers/AuthController.php?action=update_coins', {
            method: 'POST',
            body: formData
        });
        const result = await response.json();
        if (!result.success) console.error('Erro ao salvar saldo:', result.error);
    } catch (error) {
        console.error('Erro ao salvar saldo:', error);
    }
}

let lastBalance = balance;
setInterval(() => {
    if (balance !== lastBalance) {
        saveBalanceToDB();
        lastBalance = balance;
    }
}, 1000);

drawBackground();
drawPlane(planeX, planeY);
</script>
</body>
</html> -->

