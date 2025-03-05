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

// Broadcaster ID/Twitch ID Verarbeitung
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['get_broadcaster']) && $_POST['csrf_token'] === $_SESSION['csrf_token']) {
	$client_id = trim($_POST["client_id_b"]);
	$accesstoken = trim($_POST["accesstoken"]);
	$username = trim($_POST["username"]);
	$save_broadcaster = isset($_POST['save_broadcaster']) ? 1 : 0;

	if (validateInput($client_id) && validateInput($accesstoken, '/^[a-zA-Z0-9]+$/') && validateInput($username)) {
		if ($save_broadcaster && isset($_POST['accept_dsgvo'])) {
			// Cookies setzen
			setcookie('client_id_b', $client_id, [
				'expires' => time() + 86400 * 30,
				'path' => '/',
				'secure' => true,
				'httponly' => true,
				'samesite' => 'Lax'
			]);
			setcookie('accesstoken', $accesstoken, [
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
			setcookie('save_broadcaster_checked', '1', [
				'expires' => time() + 86400 * 30,
				'path' => '/',
				'secure' => true,
				'httponly' => true,
				'samesite' => 'Lax'
			]);
		} else {
			// Sessions setzen, wenn keine Cookies gewünscht
			$_SESSION['client_id_b'] = $client_id;
			$_SESSION['accesstoken'] = $accesstoken;
			$_SESSION['username'] = $username;
			setcookie('save_broadcaster_checked', '0', [
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
			"Authorization: Bearer $accesstoken"
		]);

	$response = curl_exec($ch);
	if ($response === false) {
			$broadcaster_id = "cURL-Fehler: ".curl_error($ch);
		} else {
			$data = json_decode($response, true);
			$broadcaster_id = isset($data["data"][0]["id"]) ? $data["data"][0]["id"] : "Fehler: Benutzer nicht gefunden oder ungültige Anfrage.";
		}
		error_log($response);
		curl_close($ch);
	} else {
		$broadcaster_id = "Ungültige Eingabe! Nur alphanumerische Zeichen, Unterstriche und Bindestriche sind erlaubt.";
	}
}

// App Token Verarbeitung
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['get_apptoken']) && $_POST['csrf_token'] === $_SESSION['csrf_token']) {
	$client_id = trim($_POST["client_id_a"]);
	$client_secret = trim($_POST["client_secret"]);
	$save_apptoken = isset($_POST['save_apptoken']) ? 1 : 0;

	if (validateInput($client_id) && validateInput($client_secret, '/^[a-zA-Z0-9]+$/')) {
		if ($save_apptoken && isset($_POST['accept_dsgvo'])) {
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
			setcookie('save_apptoken_checked', '1', [
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
			setcookie('save_apptoken_checked', '0', [
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
			$apptoken = "cURL-Fehler: " . curl_error($ch);
		} else {
			$data = json_decode($response, true);
			$apptoken = isset($data["access_token"]) ? $data["access_token"] : "Fehler: Token konnte nicht generiert werden.";
			// Direkt nach Generierung in Session/Cookie speichern
			if ($save_apptoken && isset($_POST['accept_dsgvo'])) {
				setcookie('accesstoken', $apptoken, [
					'expires' => time() + 86400 * 30,
					'path' => '/',
					'secure' => true,
					'httponly' => true,
					'samesite' => 'Lax'
				]);
			} else {
				$_SESSION['accesstoken'] = $apptoken;
			}
		}
		curl_close($ch);
	} else {
		$apptoken = "Ungültige Eingabe! Nur alphanumerische Zeichen sind erlaubt.";
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
		<h2>Twitch-ID/Broadcaster ID generieren</h2>
		<form method="post">
			<input type="text" name="client_id_b" placeholder="Client-ID" value="<?php echo getInputValue('client_id_b', 'client_id_b'); ?>" required>
			<input type="text" name="accesstoken" placeholder="Accesstoken" value="<?php echo getInputValue('accesstoken', 'accesstoken'); ?>" required>
			<input type="text" name="username" placeholder="Twitch Benutzername" value="<?php echo getInputValue('username', 'username'); ?>" required>
			<br>
			<input type="checkbox" name="save_broadcaster" id="save_broadcaster" <?php echo isset($_COOKIE['save_broadcaster_checked']) && $_COOKIE['save_broadcaster_checked'] === '1' ? 'checked' : ''; ?>>
			<label for="save_broadcaster">Eingaben als Cookies speichern</label>
			<br>
			<input type="checkbox" name="accept_dsgvo" id="accept_dsgvo_b" required>
			<label for="accept_dsgvo_b">Ich stimme der Verwendung der Daten durch Twitch zu</label>
			<br>
			<input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
			<button type="submit" name="get_broadcaster">Broadcaster ID generieren</button>
		</form>
		<p>Die Client-ID kann hier unter neue Anwendung generiert werden: <a href="https://dev.twitch.tv/console" target="_blank">https://dev.twitch.tv/console</a></p>

		<?php if (isset($broadcaster_id)) { ?>
			<h3>Ergebnis:</h3>
			<p><?php echo htmlspecialchars($broadcaster_id); ?></p>
		<?php } ?>
	</div>

	<div class="section">
		<h2>App Token/Access Token/Twitch OAuth Token generieren</h2>
		<form method="post">
			<input type="text" name="client_id_a" placeholder="Client-ID" value="<?php echo getInputValue('client_id_a', 'client_id_a'); ?>" required>
			<input type="text" name="client_secret" placeholder="Client Secret" value="<?php echo getInputValue('client_secret', 'client_secret'); ?>" required>
			<br>
			<input type="checkbox" name="save_apptoken" id="save_apptoken" 
				   <?php echo isset($_COOKIE['save_apptoken_checked']) && $_COOKIE['save_apptoken_checked'] === '1' ? 'checked' : ''; ?>>
			<label for="save_apptoken">Eingaben als Cookies speichern</label>
			<br>
			<input type="checkbox" name="accept_dsgvo" id="accept_dsgvo_a" required>
			<label for="accept_dsgvo_a">Ich stimme der Verwendung der Daten durch Twitch zu</label>
			<br>
			<input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
			<button type="submit" name="get_apptoken">App Token generieren</button>
		</form>
		<p>Die Client-ID und Client Secret können hier unter neue Anwendung generiert werden: <a href="https://dev.twitch.tv/console" target="_blank">https://dev.twitch.tv/console</a></p>

		<?php if (isset($apptoken)) { ?>
			<h3>Ergebnis:</h3>
			<p><?php echo htmlspecialchars($apptoken); ?></p>
		<?php } ?>
	</div>
</body>
</html>
