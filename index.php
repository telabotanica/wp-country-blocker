<?php
/**
 * Plugin Name: WP Country & Fail2Ban Blocker
 * Description: Block countries + export blocked IPs for Fail2Ban
 * Version: 2.0
 */

if (!defined('ABSPATH')) exit;

class WP_Country_Fail2Ban_Blocker {

    private $log_file;

    public function __construct() {
        $upload_dir = wp_upload_dir();
        $this->log_file = $upload_dir['basedir'] . '/wpff-blocked-ips.log';

        add_action('init', [$this, 'check_access'], 1);
        add_filter('rest_authentication_errors', [$this, 'check_rest_api']);

        add_action('admin_menu', [$this, 'admin_menu']);
        add_action('admin_init', [$this, 'register_settings']);
    }

    /* =========================
     * CONFIG (DB OPTIONS)
     * ========================= */

    private function get_blocked_countries() {
        return (array) get_option('wpff_blocked_countries', ['SG', 'RU', 'CN', 'KP']);
    }

    private function allow_logged_in_users() {
        return (bool) get_option('wpff_allow_logged_in_users', 1);
    }

    private function block_rest_api() {
        return (bool) get_option('wpff_block_rest_api', 1);
    }

    /* =========================
     * CORE CHECK
     * ========================= */

    public function check_access() {

        if (is_admin() || wp_doing_cron() || wp_doing_ajax()) {
            return;
        }

        if ($this->allow_logged_in_users() && is_user_logged_in()) {
            return;
        }

        if ($this->is_login_page()) {
            return;
        }

        $country = $this->get_country();

        if ($country && in_array($country, $this->get_blocked_countries(), true)) {

            $ip = $this->get_ip();

            $this->log_block($ip, $country, 'FRONT');

            $this->send_fail2ban($ip, $country);

            wp_die(
                'Access denied',
                'Blocked',
                ['response' => 403]
            );
        }
    }

    /* =========================
     * REST API
     * ========================= */

    public function check_rest_api($result) {

        if (!$this->block_rest_api()) {
            return $result;
        }

        if ($this->allow_logged_in_users() && is_user_logged_in()) {
            return $result;
        }

        $country = $this->get_country();

        if ($country && in_array($country, $this->get_blocked_countries(), true)) {

            $ip = $this->get_ip();

            $this->log_block($ip, $country, 'REST');
            $this->send_fail2ban($ip, $country);

            return new WP_Error(
                'blocked_country',
                'Forbidden country',
                ['status' => 403]
            );
        }

        return $result;
    }

    /* =========================
     * GEO IP (Cloudflare first)
     * ========================= */

    private function get_country() {

        // Cloudflare (FAST PATH)
        if (!empty($_SERVER['HTTP_CF_IPCOUNTRY'])) {
            return $_SERVER['HTTP_CF_IPCOUNTRY'];
        }

        $ip = $this->get_ip();

        if (!$ip || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }

        $cache_key = 'wpff_country_' . md5($ip);
        $cached = get_transient($cache_key);

        if ($cached) {
            return $cached;
        }

        $response = wp_remote_get("https://ip-api.com/json/{$ip}?fields=countryCode", [
            'timeout' => 2
        ]);

        if (is_wp_error($response)) {
            return false;
        }

        $data = json_decode(wp_remote_retrieve_body($response), true);

        $country = isset($data['countryCode']) ? $data['countryCode'] : false;

        if ($country) {
            set_transient($cache_key, $country, HOUR_IN_SECONDS);
        }

        return $country;
    }

    /* =========================
     * IP DETECTION
     * ========================= */

    private function get_ip() {

        $keys = [
            'HTTP_CF_CONNECTING_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'REMOTE_ADDR'
        ];

        foreach ($keys as $key) {
            if (!empty($_SERVER[$key])) {
                return trim(explode(',', $_SERVER[$key])[0]);
            }
        }

        return '';
    }

    /* =========================
     * FAIL2BAN INTEGRATION
     * ========================= */

    private function send_fail2ban($ip, $country) {

        if (!$ip) return;

        $line = sprintf(
            "[%s] BLOCKED IP=%s COUNTRY=%s URI=%s\n",
            date('Y-m-d H:i:s'),
            $ip,
            $country,
            $_SERVER['REQUEST_URI'] ?? ''
        );

        file_put_contents($this->log_file, $line, FILE_APPEND);
    }

    private function log_block($ip, $country, $context) {
        error_log("[WP BLOCK] {$context} IP={$ip} COUNTRY={$country}");
    }

    /* =========================
     * LOGIN CHECK
     * ========================= */

    private function is_login_page() {
        global $pagenow;

        if (!empty($pagenow) && in_array($pagenow, ['wp-login.php'], true)) {
            return true;
        }

        return false;
    }

    /* =========================
     * ADMIN PANEL
     * ========================= */

    public function admin_menu() {
        add_options_page(
            'Country Blocker',
            'Country Blocker',
            'manage_options',
            'wpff-blocker',
            [$this, 'admin_page']
        );
    }

    public function register_settings() {
        register_setting('wpff', 'wpff_blocked_countries');
        register_setting('wpff', 'wpff_block_rest_api');
        register_setting('wpff', 'wpff_allow_logged_in_users');
    }

    public function admin_page() {
        ?>
        <div class="wrap">
            <h1>Country Blocker</h1>

            <form method="post" action="options.php">
                <?php settings_fields('wpff'); ?>

                <table class="form-table">

                    <tr>
                        <th>Blocked countries</th>
                        <td>
                            <input name="wpff_blocked_countries"
                                   value="<?php echo esc_attr(implode(',', (array)get_option('wpff_blocked_countries', []))); ?>"
                                   style="width:300px">
                        </td>
                    </tr>

                    <tr>
                        <th>Block REST API</th>
                        <td>
                            <input type="checkbox" name="wpff_block_rest_api" value="1"
                                <?php checked(1, get_option('wpff_block_rest_api', 1)); ?>>
                        </td>
                    </tr>

                    <tr>
                        <th>Allow logged users</th>
                        <td>
                            <input type="checkbox" name="wpff_allow_logged_in_users" value="1"
                                <?php checked(1, get_option('wpff_allow_logged_in_users', 1)); ?>>
                        </td>
                    </tr>

                </table>

                <?php submit_button(); ?>
            </form>

            <hr>

            <h2>Fail2Ban log file</h2>
            <code><?php echo esc_html($this->log_file); ?></code>
        </div>
        <?php
    }
}

/* INIT */
new WP_Country_Fail2Ban_Blocker();
