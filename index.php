<?php
/**
 * Plugin Name: WP Country Blocker
 * Description: Block countries with ISO auto conversion + Fail2Ban + Cloudflare support
 * Version: 1.0
 * Author: Tela Botanica
 * Author URI: https://www.tela-botanica.org
 * Author Email: accueil@tela-botanica.org
 */

if (!defined('ABSPATH')) exit;

class WP_Country_Blocker_Pro {
    
    private $log_file;
    
    public function __construct() {
        
        $upload = wp_upload_dir();
        $this->log_file = $upload['basedir'] . '/wpff-blocked.log';
        
        add_action('init', [$this, 'check_access'], 1);
        add_filter('rest_authentication_errors', [$this, 'check_rest']);
        
        add_action('admin_menu', [$this, 'admin_menu']);
        add_action('admin_init', [$this, 'register_settings']);
    }
    
    /* =========================
     * SETTINGS
     * ========================= */
    
    public function register_settings() {
        
        register_setting('wpff', 'wpff_blocked_countries', [
             'sanitize_callback' => [$this, 'sanitize_countries']
        ]);
        
        register_setting('wpff', 'wpff_block_rest_api');
        register_setting('wpff', 'wpff_allow_logged_in_users');
    }
    
    private function allow_logged_in() {
        return (bool) get_option('wpff_allow_logged_in_users', 1);
    }
    
    private function block_rest_api_enabled() {
        return (bool) get_option('wpff_block_rest_api', 1);
    }
    
    private function blocked_countries() {
        return (array) get_option('wpff_blocked_countries', ['SG', 'CN', 'RU', 'KP', 'CA']);
    }
    
    /* =========================
     * ISO NORMALIZATION
     * ========================= */
    
    public function sanitize_countries($value) {
        return $this->normalize_country_input($value);
    }
    
    private function normalize_country_input($value) {
        
        if (is_string($value)) {
            $value = explode(',', $value);
        }
        
        $map = $this->country_map();
        $out = [];
        
        foreach ((array) $value as $v) {
            
            $v = strtoupper(trim($v));
            if ($v === '') continue;
            
            // already ISO
            if (preg_match('/^[A-Z]{2}$/', $v)) {
                $out[] = $v;
                continue;
            }
            
            // convert name → ISO
            if (isset($map[$v])) {
                $out[] = $map[$v];
            }
        }
        
        return array_values(array_unique($out));
    }
    
    private function country_map() {
        return [
             'FRANCE'        => 'FR',
             'SINGAPOUR'     => 'SG',
             'SINGAPORE'     => 'SG',
             'CHINE'         => 'CN',
             'CHINA'         => 'CN',
             'RUSSIE'        => 'RU',
             'RUSSIA'        => 'RU',
             'CORÉE DU NORD' => 'KP',
             'NORTH KOREA'   => 'KP',
        ];
    }
    
    /* =========================
     * CORE CHECK
     * ========================= */
    
    public function check_access() {
        
        if (is_admin() || wp_doing_cron() || wp_doing_ajax()) return;
        if ($this->allow_logged_in() && is_user_logged_in()) return;
        if ($this->is_login_page()) return;
        
        $country = $this->get_country();
        $ip      = $this->get_ip();
        
        if ($country && in_array($country, $this->blocked_countries(), true)) {
            
            $this->log($ip, $country, 'FRONT');
            $this->fail2ban($ip, $country);
            
            wp_die('Access denied', 'Blocked', ['response' => 403]);
        }
    }
    
    /* =========================
     * REST API
     * ========================= */
    
    public function check_rest($result) {
        
        if (!$this->block_rest_api_enabled()) return $result;
        if ($this->allow_logged_in() && is_user_logged_in()) return $result;
        
        $country = $this->get_country();
        $ip      = $this->get_ip();
        
        if ($country && in_array($country, $this->blocked_countries(), true)) {
            
            $this->log($ip, $country, 'REST');
            $this->fail2ban($ip, $country);
            
            return new WP_Error('blocked_country', 'Forbidden country', ['status' => 403]);
        }
        
        return $result;
    }
    
    /* =========================
     * GEO LOCATION
     * ========================= */
    
    private function get_country() {
        
        // Cloudflare fast path
        if (!empty($_SERVER['HTTP_CF_IPCOUNTRY'])) {
            return strtoupper(sanitize_text_field($_SERVER['HTTP_CF_IPCOUNTRY']));
        }
        
        $ip = $this->get_ip();
        if (!$ip || !filter_var($ip, FILTER_VALIDATE_IP)) return false;
        
        $cache = get_transient('wpff_' . md5($ip));
        if ($cache) return $cache;
        
        $res = wp_remote_get("http://ip-api.com/json/{$ip}?fields=countryCode", [
             'timeout' => 2
        ]);
        
        if (is_wp_error($res)) return false;
        
        $data = json_decode(wp_remote_retrieve_body($res), true);
        
        $country = $data['countryCode'] ?? false;
        
        if ($country) {
            set_transient('wpff_' . md5($ip), $country, HOUR_IN_SECONDS);
        }
        
        return $country;
    }
    
    private function get_ip() {
        
        $keys = [
             'HTTP_CF_CONNECTING_IP',
             'HTTP_X_FORWARDED_FOR',
             'HTTP_X_REAL_IP',
             'REMOTE_ADDR',
        ];
        
        foreach ($keys as $k) {
            if (!empty($_SERVER[$k])) {
                return trim(explode(',', $_SERVER[$k])[0]);
            }
        }
        
        return '';
    }
    
    /* =========================
     * FAIL2BAN
     * ========================= */
    
    private function fail2ban($ip, $country) {
        
        if (!$ip) return;
        
        // FIX: argument order was wrong in the original — sprintf placeholders
        // are %s for IP, COUNTRY, URI, TIME (not TIME first as the original had).
        file_put_contents(
             $this->log_file,
             sprintf(
                  "IP=%s COUNTRY=%s URI=%s TIME=%s\n",
                  $ip,
                  $country,
                  $_SERVER['REQUEST_URI'] ?? '',
                  date('Y-m-d H:i:s')
             ),
             FILE_APPEND
        );
    }
    
    private function log($ip, $country, $ctx) {
        error_log("[WP BLOCK {$ctx}] IP={$ip} COUNTRY={$country}");
    }
    
    /* =========================
     * LOGIN
     * ========================= */
    
    private function is_login_page() {
        global $pagenow;
        return !empty($pagenow) && $pagenow === 'wp-login.php';
    }
    
    /* =========================
     * ADMIN
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
    
    public function admin_page() {
        
        $blocked = (array) get_option('wpff_blocked_countries', []);
        ?>
        
        <div class="wrap">
            <h1>Country Blocker Pro</h1>
            
            <form method="post" action="options.php">
                <?php settings_fields('wpff'); ?>
                
                <table class="form-table">
                    
                    <tr>
                        <th>Blocked countries</th>
                        <td>
                            <input name="wpff_blocked_countries"
                                   value="<?php echo esc_attr(implode(',', $blocked)); ?>"
                                   style="width:350px"
                                   placeholder="Singapour, France, CN">
                            
                            <p class="description">Auto converted to ISO (FR, SG, CN)</p>
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
            
            <h2>Blocked countries (active)</h2>
            <ul>
                <?php foreach ($blocked as $c): ?>
                    <li><strong><?php echo esc_html($c); ?></strong></li>
                <?php endforeach; ?>
            </ul>
            
            <hr>
            
            <h2>Fail2Ban log</h2>
            <code><?php echo esc_html($this->log_file); ?></code>
        </div>
        
        <?php
    }
}

/* INIT */
new WP_Country_Blocker_Pro();