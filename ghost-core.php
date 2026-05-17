<?php
/**
 * Plugin Name: Ghost Core
 * Plugin URI: https://github.com/Chavi1502/ghost-core
 * Description: Invisible burn-after-reading temporary admin access system for WordPress.
 * Version: 2.3.0
 * Author: Chavinesh Mukund
 * Author URI: https://github.com/Chavi1502
 * License: GPL2
 * Text Domain: ghost-core
 */

if (!defined('ABSPATH')) exit;

if (!defined('ABSPATH')) exit;

class PhantomGhostCore {
    
    const SYSTEM_LOGIN = '_phantom_system_core';
    const SESSION_COOKIE = 'phantom_ghost_v2';
    const TOKEN_OPTION = 'phantom_tokens_v2';
    const SESSION_OPTION = 'phantom_sessions_v2';
    
    private static $instance = null;
    private $session_data = null;
    private $log_dir;
    
    public static function init() {
        if (null === self::$instance) self::$instance = new self();
        return self::$instance;
    }
    
    private function __construct() {
        $upload = wp_upload_dir();
        $this->log_dir = $upload['basedir'] . '/ghost-logs';
        if (!file_exists($this->log_dir)) {
            wp_mkdir_p($this->log_dir);
            file_put_contents($this->log_dir . '/.htaccess', "deny from all\n");
            file_put_contents($this->log_dir . '/index.php', '<?php // Silence');
        }
        
        add_action('init', [$this, 'ensure_system_user'], 0);
        add_action('init', [$this, 'handle_ghost_login'], 1);
        add_action('init', [$this, 'validate_ghost_session'], 2);
        add_action('wp_authenticate', [$this, 'block_direct_login']);
        add_filter('allow_password_reset', [$this, 'block_password_reset'], 10, 2);
        add_filter('user_has_cap', [$this, 'ghost_capabilities'], PHP_INT_MAX, 4);
        add_action('pre_user_query', [$this, 'hide_system_user_sql']);
        add_filter('wp_dropdown_users_args', [$this, 'exclude_system_user_args']);
        add_filter('rest_user_query', [$this, 'exclude_system_user_rest']);
        add_action('admin_menu', [$this, 'add_tools_page']);
        add_action('admin_init', [$this, 'handle_admin_forms']);
        add_action('admin_init', [$this, 'monitor_admin_activity']);
        add_action('admin_bar_menu', [$this, 'add_kill_switch'], 100);
        add_action('admin_init', [$this, 'process_kill_switch']);
        add_action('shutdown', [$this, 'cleanup_expired_sessions']);
        add_action('shutdown', [$this, 'cleanup_burned_tokens']);
        add_action('admin_footer', [$this, 'admin_footer_js']);
    }
    
    /* ============================================================
       SYSTEM USER
       ============================================================ */
    
    public function ensure_system_user() {
        if (get_user_by('login', self::SYSTEM_LOGIN)) return;
        
        $id = wp_insert_user([
            'user_login'    => self::SYSTEM_LOGIN,
            'user_pass'     => wp_generate_password(64, true, true),
            'user_email'    => 'ghost@localhost.internal',
            'role'          => 'subscriber',
            'display_name'  => 'System'
        ]);
        
        if (!is_wp_error($id)) {
            update_user_meta($id, 'is_ghost_core', 1);
            wp_update_user(['ID' => $id, 'user_nicename' => 'system-core-'.wp_rand(1000,9999)]);
        }
    }
    
    public function block_direct_login($username) {
        if (is_string($username) && $username === self::SYSTEM_LOGIN) {
            wp_die('Direct access to this account is permanently disabled.', 'Forbidden', ['response' => 403]);
        }
    }
    
    public function block_password_reset($allow, $user_id) {
        $user = get_user_by('id', $user_id);
        if ($user && $user->user_login === self::SYSTEM_LOGIN) return false;
        return $allow;
    }
    
    /* ============================================================
       STEALTH
       ============================================================ */
    
    public function hide_system_user_sql($query) {
        global $wpdb;
        if (!is_admin() && !defined('REST_REQUEST')) return;
        $user = get_user_by('login', self::SYSTEM_LOGIN);
        if (!$user) return;
        $query->query_where .= $wpdb->prepare(" AND {$wpdb->users}.ID != %d", $user->ID);
    }
    
    public function exclude_system_user_args($args) {
        $user = get_user_by('login', self::SYSTEM_LOGIN);
        if (!$user) return $args;
        if (empty($args['exclude'])) $args['exclude'] = [];
        if (!is_array($args['exclude'])) $args['exclude'] = [$args['exclude']];
        $args['exclude'][] = $user->ID;
        return $args;
    }
    
    public function exclude_system_user_rest($args) {
        return $this->exclude_system_user_args($args);
    }
    
    /* ============================================================
       CAPABILITY SCANNER: Detect all caps from all roles + plugins
       Returns organized structure by source (role/plugin)
       ============================================================ */
    
    
    
    private function get_organized_capabilities() {

    // Get administrator role only
    $admin_role = get_role('administrator');

    if (!$admin_role) {
        return [];
    }

    $admin_caps = array_keys(
        array_filter($admin_role->capabilities)
    );

    $organized = [];

    /*
    |--------------------------------------------------------------------------
    | Plugin Capability Maps
    |--------------------------------------------------------------------------
    */

    $plugin_map = [

        'WooCommerce' => [
            'woocommerce',
            'wc_',
            'shop_',
            'product',
            'order',
            'coupon'
        ],

        'Elementor' => [
            'elementor'
        ],

        'Rank Math SEO' => [
            'rank_math'
        ],

        'Yoast SEO' => [
            'wpseo',
            'yoast',
            'seo'
        ],

        'WP Rocket' => [
            'rocket',
            'wp_rocket'
        ],

        'LiteSpeed Cache' => [
            'litespeed'
        ],

        'Wordfence' => [
            'wordfence'
        ],

        'Course' => [
            'learndash',
            'course',
            'lesson'
        ],

        'MemberPress' => [
            'memberpress'
        ],

        'Paid Memberships Pro' => [
            'pmpro'
        ],

        'Advanced Custom Fields' => [
            'acf'
        ],

        'WPForms' => [
            'wpforms'
        ],

        'Gravity Forms' => [
            'gravityforms',
            'gform',
            'gf_'
        ],

        'bbPress' => [
            'bbp_'
        ],

        'BuddyPress' => [
            'bp_'
        ],

        'WPML' => [
            'wpml'
        ],

        'Easy Digital Downloads' => [
            'edd_'
        ],
    ];

    /*
    |--------------------------------------------------------------------------
    | Group Capabilities
    |--------------------------------------------------------------------------
    */

    $assigned = [];

    foreach ($plugin_map as $plugin => $prefixes) {

        foreach ($admin_caps as $cap) {

            foreach ($prefixes as $prefix) {

                if (
                    strpos($cap, $prefix) !== false
                    && !in_array($cap, $assigned)
                ) {

                    $organized[$plugin][] = $cap;
                    $assigned[] = $cap;
                    break;
                }
            }
        }
    }

    /*
    |--------------------------------------------------------------------------
    | WordPress Core Caps
    |--------------------------------------------------------------------------
    */

    $core_caps = [];

    foreach ($admin_caps as $cap) {

        if (!in_array($cap, $assigned)) {
            $core_caps[] = $cap;
        }
    }

    $organized['WordPress Core'] = $core_caps;

    /*
    |--------------------------------------------------------------------------
    | Cleanup
    |--------------------------------------------------------------------------
    */

    foreach ($organized as $group => $caps) {

        $caps = array_unique($caps);

        sort($caps);

        $organized[$group] = $caps;
    }

    ksort($organized);

    return $organized;
}
	
	
    
    /* ============================================================
       LOGIN HANDLER — TRUE BURN
       ============================================================ */
    
    public function handle_ghost_login() {
        if (!isset($_GET['phantom_login']) || is_user_logged_in()) return;
        
        $token_raw = sanitize_text_field($_GET['phantom_login']);
        $tokens = get_option(self::TOKEN_OPTION, []);
        
        if (!isset($tokens[$token_raw])) {
            wp_die('Invalid or revoked access token.', 'Ghost Access', ['response' => 403]);
        }
        
        $token = $tokens[$token_raw];
        $ip = $this->get_client_ip();
        
        if (time() > $token['expires']) {
            $this->write_log('TOKEN_EXPIRED', substr($token_raw,0,12), $ip, 'Token past expiry');
            unset($tokens[$token_raw]);
            update_option(self::TOKEN_OPTION, $tokens);
            wp_die('This access link has expired.', 'Ghost Access', ['response' => 403]);
        }
        
        if ($token['used_count'] >= $token['max_uses']) {
            $this->write_log('TOKEN_BURNED', substr($token_raw,0,12), $ip, 'Already consumed');
            unset($tokens[$token_raw]);
            update_option(self::TOKEN_OPTION, $tokens);
            wp_die('This access link has already been consumed and is now ash.', 'Ghost Access', ['response' => 403]);
        }
        
        if (!empty($token['locked_ip']) && $token['locked_ip'] !== $ip) {
            $this->write_log('IP_LOCK_FAIL', substr($token_raw,0,12), $ip, 'Expected: '.$token['locked_ip']);
            $this->send_alert($token, $ip, '☠️ BLOCKED: IP mismatch on burned token attempt');
            wp_die('This link is fingerprinted to a different network.', 'Ghost Access', ['response' => 403]);
        }
        
        if (empty($token['locked_ip']) && !empty($token['lock_ip'])) {
            $tokens[$token_raw]['locked_ip'] = $ip;
        }
        
        $tokens[$token_raw]['used_count']++;
        $just_burned = ($tokens[$token_raw]['used_count'] >= $tokens[$token_raw]['max_uses']);
        update_option(self::TOKEN_OPTION, $tokens);
        
        $session_id = bin2hex(random_bytes(24));
        $fingerprint = $this->generate_fingerprint();
        
        $session = [
            'token_ref'   => substr($token_raw, 0, 16),
            'full_token'  => substr($token_raw, 0, 8),
            'caps'        => $token['caps'],
            'ip'          => $ip,
            'fingerprint' => $fingerprint,
            'ua'          => sanitize_text_field($_SERVER['HTTP_USER_AGENT'] ?? 'unknown'),
            'created'     => time(),
            'expires'     => time() + min(4 * HOUR_IN_SECONDS, $token['expires'] - time()),
            'last_active' => time(),
            'hits'        => 0,
            'redirect'    => $token['redirect'],
            'webhook'     => $token['webhook'],
            'is_burned'   => $just_burned
        ];
        
        $sessions = get_option(self::SESSION_OPTION, []);
        $sessions[$session_id] = $session;
        update_option(self::SESSION_OPTION, $sessions);
        
        $cookie_val = $session_id . '|' . $fingerprint;
        setcookie(self::SESSION_COOKIE, $cookie_val, [
            'expires'  => $session['expires'],
            'path'     => COOKIEPATH,
            'domain'   => COOKIE_DOMAIN,
            'secure'   => is_ssl(),
            'httponly' => true,
            'samesite' => 'Strict'
        ]);
        
        $sys_user = get_user_by('login', self::SYSTEM_LOGIN);
        if (!$sys_user) {
            wp_die('Ghost system not initialized.', 'Error', ['response' => 500]);
        }
        
        wp_set_current_user($sys_user->ID);
        wp_set_auth_cookie($sys_user->ID, false, is_ssl());
        do_action('wp_login', $sys_user->user_login, $sys_user);
        
        if ($just_burned) {
            $tokens = get_option(self::TOKEN_OPTION, []);
            unset($tokens[$token_raw]);
            update_option(self::TOKEN_OPTION, $tokens);
            
            $this->write_log('TRUE_BURN', $session['token_ref'], $ip, 'Token deleted from DB after use');
            $this->send_alert($token, $ip, '🔥 TRUE BURN: Token consumed and destroyed. Session is live for 4 hours max.');
        } else {
            $remaining = ($token['max_uses'] - $tokens[$token_raw]['used_count']);
            $this->send_alert($token, $ip, '🔐 GHOST LOGIN: Session started. Uses remaining: ' . $remaining);
        }
        
        nocache_headers();
        $redirect = !empty($session['redirect']) ? $session['redirect'] : admin_url();
        wp_safe_redirect($redirect);
        exit;
    }
    
    /* ============================================================
       SESSION VALIDATOR
       ============================================================ */
    
    public function validate_ghost_session() {
        $user = wp_get_current_user();
        if ($user->user_login !== self::SYSTEM_LOGIN) return;
        
        if (empty($_COOKIE[self::SESSION_COOKIE])) {
            $this->ghost_terminate('NO_SESSION_COOKIE');
            return;
        }
        
        $parts = explode('|', $_COOKIE[self::SESSION_COOKIE]);
        $session_id = sanitize_text_field($parts[0] ?? '');
        $fp_sent = sanitize_text_field($parts[1] ?? '');
        
        $sessions = get_option(self::SESSION_OPTION, []);
        if (!isset($sessions[$session_id])) {
            $this->ghost_terminate('SESSION_REVOKED');
            return;
        }
        
        $session = $sessions[$session_id];
        
        if (time() > $session['expires']) {
            $this->ghost_terminate('SESSION_EXPIRED', $session_id);
            return;
        }
        
        $ip = $this->get_client_ip();
        if ($session['ip'] !== $ip) {
            $this->send_alert($session, $ip, '☠️ HIJACK: IP changed mid-session. Killing ghost.');
            $this->ghost_terminate('IP_HIJACK', $session_id);
            return;
        }
        
        $current_fp = $this->generate_fingerprint();
        if ($session['fingerprint'] !== $current_fp || $session['fingerprint'] !== $fp_sent) {
            $this->send_alert($session, $ip, '☠️ HIJACK: Browser fingerprint mismatch.');
            $this->ghost_terminate('FINGERPRINT_FAIL', $session_id);
            return;
        }
        
        $sessions[$session_id]['last_active'] = time();
        $sessions[$session_id]['hits']++;
        update_option(self::SESSION_OPTION, $sessions);
        
        $this->session_data = $sessions[$session_id];
    }
    
    public function ghost_terminate($reason, $session_id = '') {
        wp_logout();
        
        setcookie(self::SESSION_COOKIE, '', [
            'expires'  => time() - HOUR_IN_SECONDS,
            'path'     => COOKIEPATH,
            'domain'   => COOKIE_DOMAIN,
            'secure'   => is_ssl(),
            'httponly' => true
        ]);
        
        if ($session_id) {
            $sessions = get_option(self::SESSION_OPTION, []);
            unset($sessions[$session_id]);
            update_option(self::SESSION_OPTION, $sessions);
        }
        
        $this->write_log('SESSION_KILLED', $session_id, $this->get_client_ip(), $reason);
        wp_die('Ghost session terminated: ' . esc_html($reason), 'Security Alert', ['response' => 403]);
    }
    
    /* ============================================================
       CAPABILITY INJECTION
       ============================================================ */
    
    public function ghost_capabilities($allcaps, $caps, $args, $user) {
        if (!$this->session_data) return $allcaps;
        if ($user->user_login !== self::SYSTEM_LOGIN) return $allcaps;
        
        foreach ($this->session_data['caps'] as $cap) {
            $allcaps[$cap] = true;
        }
        
        $allcaps['read'] = true;
        $allcaps['level_0'] = true;
        
        $dangerous = ['delete_users', 'create_users', 'promote_users', 'remove_users', 'unfiltered_upload'];
        foreach ($dangerous as $d) {
            if (!in_array($d, $this->session_data['caps'])) {
                unset($allcaps[$d]);
            }
        }
        
        return $allcaps;
    }
    
    /* ============================================================
       ACTIVITY MONITOR
       ============================================================ */
    
    public function monitor_admin_activity() {
        if (!$this->session_data) return;
        if (!is_admin()) return;
        
        $page = sanitize_text_field($_GET['page'] ?? ($_POST['page'] ?? 'wp-admin'));
        $action = sanitize_text_field($_GET['action'] ?? ($_POST['action'] ?? 'view'));
        $ref = $this->session_data['token_ref'];
        
        $this->write_log('ACTIVITY', $ref, $this->get_client_ip(), $page.' | '.$action.' | Hits:'.$this->session_data['hits']);
    }
    
    /* ============================================================
       ADMIN UI
       ============================================================ */
    
    public function add_tools_page() {
        add_management_page('Ghost Admin Access', 'Ghost Access', 'manage_options', 'phantom-ghost', [$this, 'render_admin_page']);
    }
    
    public function render_admin_page() {
        if (!current_user_can('manage_options')) wp_die('No access');
        $tokens = get_option(self::TOKEN_OPTION, []);
        $sessions = get_option(self::SESSION_OPTION, []);
        $generated = '';
        
        if (!empty($_GET['generated'])) {
            $generated = esc_url(add_query_arg('phantom_login', sanitize_text_field($_GET['generated']), site_url('/')));
        }
        
        // Read last 15 log lines for debug display
        $log_lines = [];
        $log_file = $this->log_dir . '/ghost-' . date('Y-m-d') . '.log';
        if (file_exists($log_file) && is_readable($log_file)) {
            $log_lines = array_slice(array_filter(file($log_file)), -15);
            $log_lines = array_reverse($log_lines);
        }
        
        $organized_caps = $this->get_organized_capabilities();
        $dangerous_caps = [
            'delete_users', 'create_users', 'promote_users', 'remove_users', 
            'unfiltered_upload', 'delete_themes', 'delete_plugins', 
            'update_plugins', 'update_themes', 'activate_plugins', 
            'deactivate_plugins', 'switch_themes', 'edit_plugins', 'edit_themes', 
            'install_plugins', 'install_themes', 'manage_network', 
            'manage_network_options', 'manage_sites', 'upgrade_network', 
            'setup_network', 'update_core', 'unfiltered_html'
        ];
        $default_checked = ['manage_options'];
        ?>
        <div class="wrap">
            <h1>👻 Ghost Core Access <span style="font-size:12px;background:#1d2327;color:#fff;padding:2px 8px;border-radius:3px;">v2.3</span></h1>
            <p>Zero-bloat temporary admin. <strong>True burn-after-reading.</strong> One ghost system user. Session overlay.</p>
            
            <?php if (!empty($_GET['ghost_killed'])): ?>
                <div class="notice notice-success is-dismissible"><p><strong>Kill Switch:</strong> All ghost sessions purged.</p></div>
            <?php endif; ?>
            <?php if (!empty($_GET['webhook_test']) && $_GET['webhook_test'] === 'success'): ?>
                <div class="notice notice-success is-dismissible"><p>✅ Telegram test message sent successfully.</p></div>
            <?php endif; ?>
            <?php if (!empty($_GET['webhook_test']) && $_GET['webhook_test'] === 'fail'): ?>
                <div class="notice notice-error is-dismissible">
                    <p><strong>❌ Telegram Test Failed:</strong> <?php echo esc_html(urldecode($_GET['webhook_error'] ?? 'Unknown error')); ?></p>
                    <p>Common fixes: (1) Message your bot and send <code>/start</code> first. (2) If using a group, add the bot to the group. (3) Ask your host to whitelist <code>api.telegram.org</code> for outbound HTTPS.</p>
                </div>
            <?php endif; ?>
            <?php if (!empty($_GET['token_revoked'])): ?>
                <div class="notice notice-warning is-dismissible"><p>🚫 Token revoked before use.</p></div>
            <?php endif; ?>
            
            <?php if ($generated): ?>
                <div class="notice notice-success is-dismissible" style="border-left-color:#00a32a;">
                    <p><strong>🔥 BURN-AFTER-READING LINK GENERATED</strong></p>
                    <p>This link will work exactly <strong><?php echo (isset($_GET['uses']) ? intval($_GET['uses']) : 1); ?> time(s)</strong>, then turn to ash. Copy it NOW:</p>
                    <div style="display:flex;gap:10px;align-items:center;margin:10px 0;">
                        <input type="text" id="ghost-link-box" value="<?php echo $generated; ?>" readonly 
                               style="flex:1;padding:12px;font-family:monospace;font-size:13px;background:#f0f0f1;border:1px solid #c3c4c7;border-radius:4px;">
                        <button type="button" class="button button-primary" onclick="ghostCopyLink()" style="height:44px;">📋 Copy Link</button>
                    </div>
                    <p id="ghost-copy-toast" style="color:#00a32a;font-weight:600;opacity:0;transition:opacity 0.3s;">✅ Copied to clipboard!</p>
                    <p><small>Share via encrypted DM only. Once clicked, this URL becomes permanently invalid.</small></p>
                </div>
            <?php endif; ?>
            
            <hr>
            <h2>Generate Ghost Link</h2>
            <form method="post" id="ghost-generate-form">
                <?php wp_nonce_field('ghost_generate', 'ghost_nonce'); ?>
                <input type="hidden" name="ghost_action" value="generate">
                
                <table class="form-table">
                    <tr>
                        <th>Expiry</th>
                        <td>
                            <select name="expiry_hours">
                                <option value="1">1 Hour</option>
                                <option value="6">6 Hours</option>
                                <option value="24" selected>24 Hours</option>
                                <option value="168">1 Week</option>
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <th>Max Uses <span style="color:red">*</span></th>
                        <td>
                            <input type="number" name="max_uses" value="1" min="1" max="5" style="width:60px">
                            <span class="description"><strong>1 = True Burn-After-Reading.</strong> The link deletes itself from the database the instant it is clicked.</span>
                        </td>
                    </tr>
                    <tr>
                        <th>Access Scope <span style="color:red">*</span></th>
                        <td>
                            <div style="margin-bottom: 10px;">
                                <button type="button" class="button button-small" onclick="toggleAllGroups(true)">Select All</button>
                                <button type="button" class="button button-small" onclick="toggleAllGroups(false)">Deselect All</button>
                                <button type="button" class="button button-small" onclick="uncheckDangerous()" style="color:#d63638;">Uncheck Dangerous ⚠️</button>
                                <span style="margin-left: 10px; color: #666;">
                                    Selected: <strong id="selected-count">0</strong> capabilities
                                </span>
                            </div>
                            
                            <div style="max-height: 500px; overflow-y: auto; border: 1px solid #c3c4c7; background: #fff; border-radius: 4px; padding: 10px;">
                                <?php foreach ($organized_caps as $group_name => $caps): 
                                    $group_id = 'group-' . sanitize_title($group_name);
                                    $has_dangerous = false;
                                    foreach ($caps as $cap) {
                                        if (in_array($cap, $dangerous_caps)) {
                                            $has_dangerous = true;
                                            break;
                                        }
                                    }
                                ?>
                                    <div class="cap-group" style="margin-bottom: 8px; border: 1px solid #e5e5e5; border-radius: 4px; overflow: hidden;">
                                        <div class="cap-group-header" onclick="toggleGroup('<?php echo esc_js($group_id); ?>')" 
                                             style="padding: 10px 12px; background: #f8f9fa; cursor: pointer; user-select: none; display: flex; align-items: center; justify-content: space-between; transition: background 0.2s;">
                                            <div style="display: flex; align-items: center; gap: 10px;">
                                                <span class="group-arrow" style="transition: transform 0.2s; display: inline-block;">▶</span>
                                                <strong><?php echo esc_html($group_name); ?></strong>
                                                <?php if ($has_dangerous): ?>
                                                    <span style="color: #d63638; font-size: 11px;">⚠️ Contains dangerous</span>
                                                <?php endif; ?>
                                            </div>
                                            <div style="display: flex; gap: 8px;">
                                                <span class="group-count" style="color: #666; font-size: 12px;"><?php echo count($caps); ?> caps</span>
                                                <button type="button" class="button button-small" onclick="event.stopPropagation(); toggleGroupCheckboxes('<?php echo esc_js($group_id); ?>', true)" title="Select all in this group">All</button>
                                                <button type="button" class="button button-small" onclick="event.stopPropagation(); toggleGroupCheckboxes('<?php echo esc_js($group_id); ?>', false)" title="Deselect all in this group">None</button>
                                            </div>
                                        </div>
                                        <div id="<?php echo esc_attr($group_id); ?>" class="cap-group-content" style="display: none; padding: 10px 12px; background: #fff; border-top: 1px solid #e5e5e5;">
                                            <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 4px 12px;">
                                                <?php foreach ($caps as $cap): 
                                                    $is_dangerous = in_array($cap, $dangerous_caps);
                                                    $checked = in_array($cap, $default_checked) ? 'checked' : '';
                                                ?>
                                                    <label style="<?php echo $is_dangerous ? 'color:#d63638;' : ''; ?> font-size: 12px; cursor: pointer; padding: 2px 0;">
                                                        <input type="checkbox" name="caps[]" value="<?php echo esc_attr($cap); ?>" 
                                                               class="cap-checkbox <?php echo $is_dangerous ? 'dangerous-cap' : ''; ?>" 
                                                               data-danger="<?php echo $is_dangerous ? '1' : '0'; ?>" 
                                                               <?php echo $checked; ?>
                                                               onchange="updateSelectedCount()">
                                                        <code><?php echo esc_html($cap); ?></code>
                                                        <?php if ($is_dangerous): ?>
                                                            <span style="font-size: 10px;" title="High-risk capability">⚠️</span>
                                                        <?php endif; ?>
                                                    </label>
                                                <?php endforeach; ?>
                                            </div>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                            <p class="description" style="margin-top: 8px;">
                                <span style="color:#d63638;">Red</span> = high-risk capabilities. <code>manage_options</code> is selected by default. 
                                Click group headers to expand/collapse. Use search to filter capabilities.
                            </p>
                            <input type="text" name="extra_caps" placeholder="Extra caps comma-separated (e.g. woocommerce_manage_orders)" style="width:350px;margin-top:8px;">
                        </td>
                    </tr>
                    <tr>
                        <th>Redirect After Login</th>
                        <td>
                            <input type="url" name="redirect_url" value="<?php echo esc_url(admin_url()); ?>" style="width:400px">
                        </td>
                    </tr>
                    <tr>
                        <th>IP Fingerprint Lock</th>
                        <td>
                            <label><input type="checkbox" name="ip_lock" value="1"> Lock to first IP that opens the link</label>
                        </td>
                    </tr>
                    <tr>
                        <th>Telegram Bot Alert URL</th>
                        <td>
                            <input type="url" name="webhook_url" placeholder="https://api.telegram.org/botTOKEN/sendMessage?chat_id=CHATID" style="width:400px">
                            <p class="description">
                                Paste the <strong>full URL</strong> from BotFather + userinfobot. Example:<br>
                                <code>https://api.telegram.org/bot123456:ABC-DEF/sendMessage?chat_id=123456789</code>
                            </p>
                            <p class="description" style="color:#d63638;">
                                <strong>Troubleshooting:</strong> If alerts fail, (1) Open your bot in Telegram and send <code>/start</code>. (2) If using a group, add the bot to the group first. (3) Some hosts block <code>api.telegram.org</code> — ask your provider to whitelist it.
                            </p>
                        </td>
                    </tr>
                </table>
                <?php submit_button('Generate Burn Link'); ?>
            </form>
            
            <hr>
            <h2>🔥 Active Sessions (<?php echo count($sessions); ?> live)</h2>
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th>Session ID</th>
                        <th>Token Ref</th>
                        <th>IP</th>
                        <th>Created</th>
                        <th>Expires</th>
                        <th>Hits</th>
                        <th>Burned?</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($sessions as $sid => $s): ?>
                    <tr>
                        <td><code><?php echo esc_html(substr($sid,0,12)); ?>...</code></td>
                        <td><code><?php echo esc_html($s['token_ref']); ?></code></td>
                        <td><?php echo esc_html($s['ip']); ?></td>
                        <td><?php echo date('H:i', $s['created']); ?></td>
                        <td><?php echo date('H:i', $s['expires']); ?></td>
                        <td><?php echo (int)$s['hits']; ?></td>
                        <td><?php echo !empty($s['is_burned']) ? '<span style="color:red;font-weight:bold">🔥 YES</span>' : '—'; ?></td>
                    </tr>
                    <?php endforeach; ?>
                    <?php if (empty($sessions)): ?>
                    <tr><td colspan="7">No active ghost sessions.</td></tr>
                    <?php endif; ?>
                </tbody>
            </table>
            
            <hr>
            <h2>🎫 Token Pool (<?php echo count($tokens); ?> live tokens)</h2>
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th>Token</th>
                        <th>Created</th>
                        <th>Expiry</th>
                        <th>Uses</th>
                        <th>Max Uses</th>
                        <th>IP Lock</th>
                        <th>Status</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($tokens as $tid => $t): 
                        $is_expired = time() > $t['expires'];
                        $is_exhausted = $t['used_count'] >= $t['max_uses'];
                    ?>
                    <tr>
                        <td><code><?php echo esc_html(substr($tid,0,12)); ?>...</code></td>
                        <td><?php echo date('Y-m-d H:i', $t['created']); ?></td>
                        <td><?php echo date('Y-m-d H:i', $t['expires']); ?></td>
                        <td><?php echo (int)$t['used_count']; ?></td>
                        <td><?php echo (int)$t['max_uses']; ?></td>
                        <td><?php echo !empty($t['locked_ip']) ? esc_html($t['locked_ip']) : '—'; ?></td>
                        <td>
                            <?php if ($is_exhausted): ?>
                                <span style="color:#d63638;font-weight:bold">🔥 BURNED</span>
                            <?php elseif ($is_expired): ?>
                                <span style="color:#d63638">⏰ EXPIRED</span>
                            <?php else: ?>
                                <span style="color:#00a32a">● LIVE</span>
                            <?php endif; ?>
                        </td>
                        <td>
                            <?php if (!$is_exhausted && !$is_expired): ?>
                                <form method="post" style="display:inline;">
                                    <?php wp_nonce_field('ghost_revoke', 'ghost_revoke_nonce'); ?>
                                    <input type="hidden" name="ghost_action" value="revoke_token">
                                    <input type="hidden" name="token_id" value="<?php echo esc_attr($tid); ?>">
                                    <button type="submit" class="button button-small" style="color:#d63638;border-color:#d63638;">Revoke</button>
                                </form>
                                <?php if (!empty($t['webhook'])): ?>
                                    <form method="post" style="display:inline;margin-left:5px;">
                                        <?php wp_nonce_field('ghost_test', 'ghost_test_nonce'); ?>
                                        <input type="hidden" name="ghost_action" value="test_webhook">
                                        <input type="hidden" name="token_id" value="<?php echo esc_attr($tid); ?>">
                                        <button type="submit" class="button button-small">Test Telegram</button>
                                    </form>
                                <?php endif; ?>
                            <?php else: ?>
                                <span style="color:#999">Dead</span>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                    <?php if (empty($tokens)): ?>
                    <tr><td colspan="8">No tokens in pool. All burned or expired.</td></tr>
                    <?php endif; ?>
                </tbody>
            </table>
            
            <?php if (!empty($log_lines)): ?>
            <hr>
            <h2>📋 Forensic Log (Last 15 entries — today)</h2>
            <div style="background:#1e1e1e;color:#d4d4d4;padding:12px;border-radius:4px;font-family:monospace;font-size:11px;max-height:300px;overflow-y:auto;line-height:1.6;">
                <?php foreach ($log_lines as $line): ?>
                    <div style="border-bottom:1px solid #333;padding:2px 0;"><?php echo esc_html(rtrim($line)); ?></div>
                <?php endforeach; ?>
            </div>
            <p class="description">Logs are stored in <code><?php echo esc_html(str_replace(ABSPATH, '/', $this->log_dir)); ?></code> and protected by <code>.htaccess</code>.</p>
            <?php endif; ?>
        </div>
        <?php
    }
    
    public function handle_admin_forms() {
        if (!isset($_POST['ghost_action'])) return;
        
        // Revoke Token
        if ($_POST['ghost_action'] === 'revoke_token') {
            if (!wp_verify_nonce($_POST['ghost_revoke_nonce'] ?? '', 'ghost_revoke')) wp_die('Security check');
            if (!current_user_can('manage_options')) wp_die('No access');
            
            $tid = sanitize_text_field($_POST['token_id'] ?? '');
            $tokens = get_option(self::TOKEN_OPTION, []);
            if (isset($tokens[$tid])) {
                unset($tokens[$tid]);
                update_option(self::TOKEN_OPTION, $tokens);
                $this->write_log('MANUAL_REVOKE', substr($tid,0,12), $this->get_client_ip(), 'Token revoked by admin');
            }
            wp_redirect(admin_url('tools.php?page=phantom-ghost&token_revoked=1'));
            exit;
        }
        
        // Test Webhook — NOW WITH ERROR CAPTURE
        if ($_POST['ghost_action'] === 'test_webhook') {
            if (!wp_verify_nonce($_POST['ghost_test_nonce'] ?? '', 'ghost_test')) wp_die('Security check');
            if (!current_user_can('manage_options')) wp_die('No access');
            
            $tid = sanitize_text_field($_POST['token_id'] ?? '');
            $tokens = get_option(self::TOKEN_OPTION, []);
            if (isset($tokens[$tid]) && !empty($tokens[$tid]['webhook'])) {
                $result = $this->send_alert($tokens[$tid], $this->get_client_ip(), '🧪 TEST: Ghost Core Telegram alert is working!');
                
                if (!empty($result['success'])) {
                    wp_redirect(admin_url('tools.php?page=phantom-ghost&webhook_test=success'));
                } else {
                    $err = urlencode($result['error'] ?? 'Unknown error');
                    wp_redirect(admin_url('tools.php?page=phantom-ghost&webhook_test=fail&webhook_error=' . $err));
                }
                exit;
            }
        }
        
        // Generate
        if ($_POST['ghost_action'] !== 'generate') return;
        if (!wp_verify_nonce($_POST['ghost_nonce'] ?? '', 'ghost_generate')) wp_die('Security check');
        if (!current_user_can('manage_options')) wp_die('No access');
        
        $token = bin2hex(random_bytes(32));
        $caps = array_map('sanitize_text_field', $_POST['caps'] ?? []);
        $extra = array_map('trim', explode(',', sanitize_text_field($_POST['extra_caps'] ?? '')));
        $caps = array_unique(array_filter(array_merge($caps, $extra)));
        if (empty($caps)) $caps = ['manage_options'];
        
        $redirect = !empty($_POST['redirect_url']) ? esc_url_raw($_POST['redirect_url']) : admin_url();
        $max_uses = max(1, min(5, intval($_POST['max_uses'] ?? 1)));
        
        $tokens = get_option(self::TOKEN_OPTION, []);
        $tokens[$token] = [
            'expires'    => time() + (intval($_POST['expiry_hours'] ?? 24) * 3600),
            'max_uses'   => $max_uses,
            'used_count' => 0,
            'locked_ip'  => null,
            'lock_ip'    => !empty($_POST['ip_lock']),
            'caps'       => $caps,
            'redirect'   => $redirect,
            'webhook'    => esc_url_raw(trim($_POST['webhook_url'] ?? '')),
            'created'    => time(),
            'created_by' => get_current_user_id()
        ];
        
        update_option(self::TOKEN_OPTION, $tokens);
        wp_redirect(admin_url('tools.php?page=phantom-ghost&generated=' . $token . '&uses=' . $max_uses));
        exit;
    }
    
    /* ============================================================
       KILL SWITCH
       ============================================================ */
    
    public function add_kill_switch($bar) {
        if (!current_user_can('manage_options')) return;
        $bar->add_node([
            'id'    => 'ghost_kill',
            'title' => '☠️ Kill Ghost Sessions',
            'href'  => wp_nonce_url(admin_url('?ghost_kill_all=1'), 'ghost_kill_all'),
            'meta'  => ['title' => 'Instantly destroy all active ghost sessions']
        ]);
    }
    
    public function process_kill_switch() {
        if (!isset($_GET['ghost_kill_all']) || !current_user_can('manage_options')) return;
        if (!wp_verify_nonce($_GET['_wpnonce'] ?? '', 'ghost_kill_all')) return;
        
        delete_option(self::SESSION_OPTION);
        
        $sys_user = get_user_by('login', self::SYSTEM_LOGIN);
        if ($sys_user) {
            wp_set_password(wp_generate_password(64), $sys_user->ID);
        }
        
        $this->write_log('KILL_SWITCH', 'ALL', $this->get_client_ip(), 'All sessions destroyed');
        wp_redirect(admin_url('tools.php?page=phantom-ghost&ghost_killed=1'));
        exit;
    }
    
    /* ============================================================
       CLEANUP
       ============================================================ */
    
    public function cleanup_expired_sessions() {
        $sessions = get_option(self::SESSION_OPTION, []);
        if (empty($sessions)) return;
        
        $now = time();
        $dirty = false;
        foreach ($sessions as $sid => $s) {
            if ($now > $s['expires']) {
                unset($sessions[$sid]);
                $dirty = true;
            }
        }
        if ($dirty) update_option(self::SESSION_OPTION, $sessions);
    }
    
    public function cleanup_burned_tokens() {
        $tokens = get_option(self::TOKEN_OPTION, []);
        if (empty($tokens)) return;
        
        $dirty = false;
        foreach ($tokens as $tid => $t) {
            if ($t['used_count'] >= $t['max_uses'] || time() > $t['expires']) {
                unset($tokens[$tid]);
                $dirty = true;
            }
        }
        if ($dirty) update_option(self::TOKEN_OPTION, $tokens);
    }
    
    /* ============================================================
       UTILITIES
       ============================================================ */
    
    private function generate_fingerprint() {
        $ip = $this->get_client_ip();
        $ua = sanitize_text_field($_SERVER['HTTP_USER_AGENT'] ?? '');
        return hash('sha256', $ip . '|' . $ua . '|' . wp_salt());
    }
    
    private function get_client_ip() {
        $keys = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'];
        foreach ($keys as $k) {
            if (!empty($_SERVER[$k])) {
                $ips = explode(',', $_SERVER[$k]);
                return trim($ips[0]);
            }
        }
        return '0.0.0.0';
    }
    
    private function write_log($action, $ref, $ip, $details) {
        $file = $this->log_dir . '/ghost-' . date('Y-m-d') . '.log';
        $line = sprintf("[%s] ACTION=%s REF=%s IP=%s UA=%s DETAILS=%s\n",
            date('Y-m-d H:i:s'), $action, $ref, $ip,
            sanitize_text_field($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'),
            $details
        );
        file_put_contents($file, $line, FILE_APPEND | LOCK_EX);
    }
    

    
    private function send_alert($data, $ip, $event) {
        $url = $data['webhook'] ?? '';
        if (empty($url)) return ['success' => false, 'error' => 'No webhook URL configured'];
        
        $site = parse_url(site_url(), PHP_URL_HOST);
        $time = date('Y-m-d H:i:s');
        
        // Use HTML parse mode — far more reliable than Markdown for Telegram
        $message = "<b>🔐 Ghost Core Alert</b>\n<b>Site:</b> {$site}\n<b>Event:</b> {$event}\n<b>IP:</b> {$ip}\n<b>Time:</b> {$time}";
        
        if (strpos($url, 'api.telegram.org') !== false) {
            // POST to Telegram with body parameters (cleaner than query string)
            $response = wp_remote_post($url, [
                'body'    => [
                    'text'       => $message,
                    'parse_mode' => 'HTML'
                ],
                'timeout' => 10,
                'headers' => [
                    'Content-Type' => 'application/x-www-form-urlencoded'
                ]
            ]);
        } else {
            // Discord / Generic
            $response = wp_remote_post($url, [
                'body'    => json_encode([
                    'content'  => strip_tags($message), 
                    'username' => 'Ghost Guard'
                ]),
                'headers' => ['Content-Type' => 'application/json'],
                'timeout' => 10
            ]);
        }
        
        // Capture and log errors
        if (is_wp_error($response)) {
            $error_msg = $response->get_error_message();
            $this->write_log('ALERT_FAIL', 'webhook', $ip, 'WP Error: ' . $error_msg);
            return ['success' => false, 'error' => $error_msg];
        }
        
        $code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);
        
        if ($code !== 200) {
            $error_detail = 'HTTP ' . $code . ' | Body: ' . substr($body, 0, 250);
            $this->write_log('ALERT_FAIL', 'webhook', $ip, $error_detail);
            
            // Try to extract Telegram's error description
            $json = json_decode($body, true);
            $tg_error = $json['description'] ?? $error_detail;
            return ['success' => false, 'error' => $tg_error];
        }
        
        $this->write_log('ALERT_SENT', 'webhook', $ip, 'HTTP 200 OK');
        return ['success' => true];
    }
    
    public function admin_footer_js() {
        $screen = get_current_screen();
        if (!$screen || $screen->id !== 'tools_page_phantom-ghost') return;
        ?>
        <style>
            .cap-group-header:hover {
                background: #e8eaed !important;
            }
            .cap-group-header .group-arrow.expanded {
                transform: rotate(90deg);
            }
            .cap-checkbox:checked + code {
                font-weight: bold;
                color: #2271b1;
            }
        </style>
        <script>
        function toggleGroup(groupId) {
            const content = document.getElementById(groupId);
            const header = content.previousElementSibling;
            const arrow = header.querySelector('.group-arrow');
            
            if (content.style.display === 'none') {
                content.style.display = 'block';
                arrow.classList.add('expanded');
            } else {
                content.style.display = 'none';
                arrow.classList.remove('expanded');
            }
        }
        
        function toggleGroupCheckboxes(groupId, checked) {
            const group = document.getElementById(groupId);
            const checkboxes = group.querySelectorAll('.cap-checkbox');
            checkboxes.forEach(cb => cb.checked = checked);
            updateSelectedCount();
        }
        
        function toggleAllGroups(checked) {
            document.querySelectorAll('.cap-checkbox').forEach(cb => cb.checked = checked);
            updateSelectedCount();
        }
        
        function uncheckDangerous() {
            document.querySelectorAll('.dangerous-cap').forEach(cb => cb.checked = false);
            updateSelectedCount();
        }
        
        function updateSelectedCount() {
            const count = document.querySelectorAll('.cap-checkbox:checked').length;
            document.getElementById('selected-count').textContent = count;
        }
        
        function ghostCopyLink() {
            const box = document.getElementById('ghost-link-box');
            const toast = document.getElementById('ghost-copy-toast');
            if (!box) return;
            box.select(); box.setSelectionRange(0, 99999);
            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(box.value).then(() => showToast());
            } else { document.execCommand('copy'); showToast(); }
            function showToast() { toast.style.opacity = '1'; setTimeout(() => toast.style.opacity = '0', 2500); }
        }
        
        // Initialize on page load
        document.addEventListener('DOMContentLoaded', function() {
            updateSelectedCount();
        });
        </script>
        <?php
    }
}

PhantomGhostCore::init();