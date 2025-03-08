<?php
session_start(); // Für CSRF-Token und Session-Speicherung

// CSRF-Token generieren
if (empty($_SESSION['csrf_token'])) {
	$_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Funktion zur Eingabevalidierung
function validateInput($input, $pattern = '/^[a-zA-Z0-9_-]+$/') {
	return preg_match($pattern, $input) ? $input : false;
}

// Channel-ID Verarbeitung
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['get_channelid']) && $_POST['csrf_token'] === $_SESSION['csrf_token']) {
	$client_id = trim($_POST["client_id_b"]);
	$authtoken = trim($_POST["authtoken"]);
	$username = trim($_POST["username"]);
	$save_channelid = isset($_POST['save_channelid']) ? 1 : 0;

	if (validateInput($client_id) && validateInput($authtoken, '/^[a-zA-Z0-9]+$/') && validateInput($username)) {
		if ($save_channelid && isset($_POST['accept_dsgvo'])) {
			// Cookies setzen
			setcookie('client_id_b', $client_id, [
				'expires' => time() + 86400 * 30,
				'path' => '/',
				'secure' => true,
				'httponly' => true,
				'samesite' => 'Lax'
			]);
			setcookie('authtoken', $authtoken, [
				'expires' => time() + 86400 * 30,
				'path' => '/',
				'secure' => true,
				'httponly' => true,
				'samesite' => 'Lax'
			]);
			setcookie('username', $username, [
				'expires' => time() + 86400 * 30,
				'path' => '/',
				'secure' => true,
				'httponly' => true,
				'samesite' => 'Lax'
			]);
			setcookie('save_channelid_checked', '1', [
				'expires' => time() + 86400 * 30,
				'path' => '/',
				'secure' => true,
				'httponly' => true,
				'samesite' => 'Lax'
			]);
		} else {
			// Sessions setzen, wenn keine Cookies gewünscht
			$_SESSION['client_id_b'] = $client_id;
			$_SESSION['authtoken'] = $authtoken;
			$_SESSION['username'] = $username;
			setcookie('save_channelid_checked', '0', [
				'expires' => time() + 86400 * 30,
				'path' => '/',
				'secure' => true,
				'httponly' => true,
				'samesite' => 'Lax'
			]);
		}

		$url = "https://api.twitch.tv/helix/users?login=".urlencode($username);
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_URL, $url);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_HTTPHEADER, [
			"Client-ID: $client_id",
			"Authorization: Bearer $authtoken"
		]);

	$response = curl_exec($ch);
	if ($response === false) {
			$channelid = "cURL-Fehler: ".curl_error($ch);
		} else {
			$data = json_decode($response, true);
			$channelid = isset($data["data"][0]["id"]) ? $data["data"][0]["id"] : "Fehler: Benutzer nicht gefunden oder ungültige Anfrage.";
		}
		error_log($response);
		curl_close($ch);
	} else {
		$channelid = "Ungültige Eingabe! Nur alphanumerische Zeichen, Unterstriche und Bindestriche sind erlaubt.";
	}
}

// Auth Token Verarbeitung
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['get_authtoken']) && $_POST['csrf_token'] === $_SESSION['csrf_token']) {
	$client_id = trim($_POST["client_id_a"]);
	$client_secret = trim($_POST["client_secret"]);
	$save_authtoken = isset($_POST['save_authtoken']) ? 1 : 0;

	if (validateInput($client_id) && validateInput($client_secret, '/^[a-zA-Z0-9]+$/')) {
		if ($save_authtoken && isset($_POST['accept_dsgvo'])) {
			// Cookies setzen
			setcookie('client_id_a', $client_id, [
				'expires' => time() + 86400 * 30,
				'path' => '/',
				'secure' => true,
				'httponly' => true,
				'samesite' => 'Lax'
			]);
			setcookie('client_secret', $client_secret, [
				'expires' => time() + 86400 * 30,
				'path' => '/',
				'secure' => true,
				'httponly' => true,
				'samesite' => 'Lax'
			]);
			setcookie('save_authtoken_checked', '1', [
				'expires' => time() + 86400 * 30,
				'path' => '/',
				'secure' => true,
				'httponly' => true,
				'samesite' => 'Lax'
			]);
		} else {
			// Sessions setzen, wenn keine Cookies gewünscht
			$_SESSION['client_id_a'] = $client_id;
			$_SESSION['client_secret'] = $client_secret;
			setcookie('save_authtoken_checked', '0', [
				'expires' => time() + 86400 * 30,
				'path' => '/',
				'secure' => true,
				'httponly' => true,
				'samesite' => 'Lax'
			]);
		}

		$url = "https://id.twitch.tv/oauth2/token";
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_URL, $url);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_POST, true);
		curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
			'client_id' => $client_id,
			'client_secret' => $client_secret,
			'grant_type' => 'client_credentials'
		]));

		$response = curl_exec($ch);
		if ($response === false) {
			$authtoken = "cURL-Fehler: " . curl_error($ch);
		} else {
			$data = json_decode($response, true);
			$authtoken = isset($data["access_token"]) ? $data["access_token"] : "Fehler: Token konnte nicht generiert werden.";
			// Direkt nach Generierung in Session/Cookie speichern
			if ($save_authtoken && isset($_POST['accept_dsgvo'])) {
				setcookie('authtoken', $authtoken, [
					'expires' => time() + 86400 * 30,
					'path' => '/',
					'secure' => true,
					'httponly' => true,
					'samesite' => 'Lax'
				]);
			} else {
				$_SESSION['authtoken'] = $authtoken;
			}
		}
		curl_close($ch);
	} else {
		$authtoken = "Ungültige Eingabe! Nur alphanumerische Zeichen sind erlaubt.";
	}
}

// Funktion zum Abrufen von Werten (Cookie > Session > leer)
function getInputValue($cookie_key, $session_key) {
	if (isset($_COOKIE[$cookie_key])) {
		return htmlspecialchars($_COOKIE[$cookie_key]);
	} elseif (isset($_SESSION[$session_key])) {
		return htmlspecialchars($_SESSION[$session_key]);
	}
	return '';
}
?>

<!DOCTYPE html>
<html lang="de">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Auth-Token und Twitch-ID Generator</title>
	<style>
		:root {
			color-scheme: light dark;
			--bg-color: #FFF;
			--heading-color: #FB7C3C;
			--text-color: #000;
			--a-link: #777;
			--a-hover: #FB7C3C;
			--nav-bg-color: #EEE;
			--nav-a: #777;
			--nav-a-hover: #CCC;
			--nav-a-active: #DDD;
		}

		@media (prefers-color-scheme: dark) {
			:root {
				--bg-color: #000;
				--heading-color: #FB7C3C;
				--text-color: #DDD;
				--a-link: #ABABAB;
				--a-hover: #FB7C3C;
				--nav-bg-color: #333;
				--nav-a: #ABABAB;
				--nav-a-hover: #444;
				--nav-a-active: #222;
			}
		}

		body {
			font-family: Arial, sans-serif;
			margin: 50px;
			background-color: var(--bg-color);
			color: var(--text-color);
		}

		.section {
			margin: 20px 0;
			padding: 20px;
			border: 1px solid #CCC;
			max-width: 750px;
			margin-left: auto;
			margin-right: auto;
		}

		input, button {
			padding: 10px;
			margin: 5px;
			font-size: 16px;
		}

		h2 {
			text-align: center;
			color: var(--heading-color);
		}

		a {
			color: var(--a-link);
		}

		a:hover {
			color: var(--a-hover);
		}
	</style>
</head>
<body>
	<div class="section">
		<h2>Channel-ID generieren</h2>
		<form method="post">
			<input type="text" name="client_id_b" placeholder="Client-ID" value="<?php echo getInputValue('client_id_b', 'client_id_b'); ?>" required>
			<input type="text" name="authtoken" placeholder="Auth Token" value="<?php echo getInputValue('authtoken', 'authtoken'); ?>" required>
			<input type="text" name="username" placeholder="Twitch Benutzername" value="<?php echo getInputValue('username', 'username'); ?>" required>
			<br>
			<input type="checkbox" name="save_channelid" id="save_channelid" <?php echo isset($_COOKIE['save_channelid_checked']) && $_COOKIE['save_channelid_checked'] === '1' ? 'checked' : ''; ?>>
			<label for="save_channelid">Eingaben als Cookies speichern</label>
			<br>
			<input type="checkbox" name="accept_dsgvo" id="accept_dsgvo_b" required>
			<label for="accept_dsgvo_b">Ich stimme der Verwendung der Daten durch Twitch zu</label>
			<br>
			<input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
			<button type="submit" name="get_channelid">Channel-ID generieren</button>
		</form>
		<p>Die Client-ID kann hier unter neue Anwendung generiert werden: <a href="https://dev.twitch.tv/console" target="_blank">https://dev.twitch.tv/console</a></p>

		<?php if (isset($channelid)) { ?>
			<h3>Ergebnis:</h3>
			<p><?php echo htmlspecialchars($channelid); ?></p>
		<?php } ?>
	</div>

	<div class="section">
		<h2>Auth Token generieren</h2>
		<form method="post">
			<input type="text" name="client_id_a" placeholder="Client-ID" value="<?php echo getInputValue('client_id_a', 'client_id_a'); ?>" required>
			<input type="text" name="client_secret" placeholder="Client Secret" value="<?php echo getInputValue('client_secret', 'client_secret'); ?>" required>
			<br>
			<input type="checkbox" name="save_authtoken" id="save_authtoken" 
				   <?php echo isset($_COOKIE['save_authtoken_checked']) && $_COOKIE['save_authtoken_checked'] === '1' ? 'checked' : ''; ?>>
			<label for="save_authtoken">Eingaben als Cookies speichern</label>
			<br>
			<input type="checkbox" name="accept_dsgvo" id="accept_dsgvo_a" required>
			<label for="accept_dsgvo_a">Ich stimme der Verwendung der Daten durch Twitch zu</label>
			<br>
			<input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
			<button type="submit" name="get_authtoken">Auth Token generieren</button>
		</form>
		<p>Die Client-ID und Client Secret können hier unter neue Anwendung generiert werden: <a href="https://dev.twitch.tv/console" target="_blank">https://dev.twitch.tv/console</a></p>

		<?php if (isset($authtoken)) { ?>
			<h3>Ergebnis:</h3>
			<p><?php echo htmlspecialchars($authtoken); ?></p>
		<?php } ?>
	</div>
</body>
</html>
