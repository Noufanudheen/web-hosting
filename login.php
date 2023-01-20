<?php
// Include database configuration file
require_once 'config.php';

// Start session
session_start();

// Check if the user is already logged in
if (isset($_SESSION['username'])) {
    header('Location: protected.php');
    exit;
}

// CSRF token
$csrf_token = md5(uniqid(rand(), TRUE));
$_SESSION['csrf_token'] = $csrf_token;

// Check if the login form was submitted
if (isset($_POST['submit'])) {
    // Get the user's input
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Check for CSRF token
    if ($_POST['csrf_token'] != $csrf_token) {
        die('Invalid CSRF token');
    }

    // Rate limit login attempts
    if (isset($_SESSION['last_login_attempt']) && time() - $_SESSION['last_login_attempt'] < 30) {
        die('Too many login attempts. Please try again later.');
    }
    $_SESSION['last_login_attempt'] = time();

    // Connect to the database
    $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }

    // Prepare a statement to prevent SQL injection
    $stmt = $conn->prepare("SELECT password FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        $hashed_password = $row['password'];

        // Verify the entered password against the hashed password
        if (password_verify($password, $hashed_password)) {
            // Start a session and redirect the user to a protected page
            $_SESSION['username'] = $username;
            header('Location: protected.php');
            exit;
        }
    }

    // Close the connection
    $stmt->close();
    $conn->close();

    // Display an error message
    echo 'Invalid login credentials.';
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Log In</title>
</head>
<body>
    <h1>Log In</h1>
    <form action="login.php" method="post">
        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required>
        <br>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required>
        <br>
        <input type="submit" name="submit" value="Log In">
    </form>
    <?php
    // Check if login failed
    if (isset($_POST['submit'])) {
        if (isset($_SESSION['last_login_attempt']) && time() - $_SESSION['last_login_attempt'] < 30) {
            echo 'Too many login attempts. Please try again later.';
        }
        else if (!isset($_SESSION['username'])){
            echo 'Invalid login credentials.';
        }
    }
    ?>
</body>
</html>