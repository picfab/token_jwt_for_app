<?php

/**
 * Plugin Name: Create token JWT for app
 * Plugin URI: https://github.com/ahmadawais/create-guten-block/
 * Description: Create a token for use in frontend and backend app
 * Author: Fabien Picard
 * Version: 1.0.0
 * License: GPL2+
 * License URI: https://www.gnu.org/licenses/gpl-2.0.txt
 *
 * @package CGB
 */

// Exit if accessed directly.
if (!defined('ABSPATH')) {
	exit;
}



if (constant('JWT_AUTH_SECRET_KEY') && class_exists('Jwt_Auth_Public')) {
	function filter_wp_authenticate_user($user, $password)
	{
			$userDataTemp = [$user, $password];
			add_action('wp_login', function () use ($userDataTemp) {
				create_token_jwt_for_app($userDataTemp);
			});
		return $user;
	};
	add_filter('wp_authenticate_user', 'filter_wp_authenticate_user', 10, 2);

	function create_token_jwt_for_app($userDataTemp)
	{
		$ch = curl_init();
		$url_request = get_bloginfo('url') . '/wp-json/jwt-auth/v1/token';

		curl_setopt($ch, CURLOPT_URL, $url_request);

		curl_setopt($ch, CURLOPT_POST, 1);

		# Admin credentials here
		curl_setopt($ch, CURLOPT_POSTFIELDS, "username=" . $userDataTemp[0]->data->user_login . "&password=" . $userDataTemp[1]);

		// receive server response ...
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

		$server_output = curl_exec($ch);
		if ($server_output === false) {
			unset($userDataTemp);
			die('1 - Error getting JWT token on WordPress for API integration.');
		}
		$server_output = json_decode($server_output);

		if ($server_output === null && json_last_error() !== JSON_ERROR_NONE) {
			die('2 - Invalid response getting JWT token on WordPress for API integration.');
		}

		if (!empty($server_output->token)) {
			$token = $server_output->token; # Token is here
			$userID = $userDataTemp[0]->data->ID;
			$token_jwt_for_app = get_user_meta($userID, 'token_jwt_for_app');
			$date = new DateTime();
			$data = json_encode(array('date' => $date->getTimestamp(), 'token' => $token));
			if (isset($token_jwt_for_app)) {
				update_user_meta($userID, 'token_jwt_for_app', $data);
			} else {
				add_user_meta($userID, 'token_jwt_for_app', $data);
			}
			curl_close($ch);
			return true;
		} else {
			die('3 - Invalid response getting JWT token on WordPress for API integration.');
		}

		return false;
	}

	add_action('wp_logout', 'delete_token_rezoprog');
	function delete_token_rezoprog($userID)
	{
		delete_user_meta($userID, 'token_jwt_for_app');
	}

	add_action('wp_loaded', 'verif_rezoprog_token');
	function verif_rezoprog_token()
	{
		if (is_user_logged_in()) {
			$userID = get_current_user_id();
			$token_jwt_for_app = get_user_meta($userID, 'token_jwt_for_app');
			if($token_jwt_for_app){
				$token_jwt_for_app = json_decode($token_jwt_for_app[0]);
				$date = $token_jwt_for_app->date;
				$today = new DateTime();
				$today = $today->getTimestamp();
				if (($today - $date) > 7 * 24 * 60 * 60) {
					delete_user_meta($userID, 'token_jwt_for_app');
					wp_logout();
				}
			}else{
				wp_logout();
			}

		}
	}

	function get_token_jwt_app($userID){
		$token_jwt_for_app = get_user_meta($userID, 'token_jwt_for_app');
		if($token_jwt_for_app){return get_user_meta($userID, 'token_jwt_for_app')[0];}
		return false;
	}
}
