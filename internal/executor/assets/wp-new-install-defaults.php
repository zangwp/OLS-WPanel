<?php
/** OLS WPanel: one-shot cleanup of untouched bundled defaults on a new install. */
if (!defined('ABSPATH')) {
    return;
}

add_action('wp_install', static function () {
    $option = '_ols_wpanel_default_cleanup';
    // Claim once before deleting anything. A copied helper on an installed or
    // restored site does not run on normal requests, upgrades or imports.
    if (!add_option($option, array('status' => 'running'), '', false)) {
        @unlink(__FILE__);
        return;
    }
    $helper_removed = @unlink(__FILE__);
    $manifest = json_decode('__OLS_WPANEL_DEFAULTS_MANIFEST__', true);
    $result = array('status' => 'completed', 'removed_plugins' => array(), 'removed_themes' => array(),
        'retained_themes' => array(), 'errors' => is_array($manifest) ? $manifest['errors'] : array('invalid manifest'));
    if (!$helper_removed) {
        $result['errors'][] = 'one-shot helper removal failed; cleanup will not run again';
    }
    // A same-named theme/plugin in a user-uploaded or legacy cache may
    // already contain custom code. A fresh tree fingerprint cannot prove
    // its origin, so keep the entire package unless its download was recorded.
    if (is_array($manifest) && empty($manifest['official_package'])) {
        $result['status'] = 'skipped';
        update_option($option, $result, false);
        return;
    }

    try {
        if (!is_array($manifest) || is_multisite()) {
            throw new RuntimeException('cleanup unavailable for this installation');
        }
        $normalize = static function ($path) { return rtrim(str_replace('\\', '/', $path), '/'); };
        $site = $normalize(realpath(ABSPATH));
        $content = $normalize(realpath(WP_CONTENT_DIR));
        if (!$site || !$content || is_link(WP_CONTENT_DIR) || $content !== $site . '/wp-content') {
            throw new RuntimeException('unsafe content directory');
        }
        $fingerprint = static function ($path) use ($normalize) {
            if (is_link($path)) {
                return false;
            }
            if (is_file($path)) {
                if (filesize($path) > 64 * 1024 * 1024) {
                    return false;
                }
                $digest = hash_file('sha256', $path);
                return $digest === false ? false : array('.' => $digest);
            }
            if (!is_dir($path)) {
                return false;
            }
            $root = $normalize(realpath($path));
            $files = array();
            $bytes = 0;
            $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
            foreach ($iterator as $entry) {
                if ($entry->isLink() || (!$entry->isDir() && !$entry->isFile()) || count($files) >= 10000) {
                    return false;
                }
                $actual = $normalize($entry->getPathname());
                if (strpos($actual, $root . '/') !== 0) {
                    return false;
                }
                $relative = substr($actual, strlen($root) + 1);
                if ($entry->isDir()) {
                    $files[$relative . '/'] = '';
                } else {
                    $bytes += $entry->getSize();
                    if ($bytes > 64 * 1024 * 1024) {
                        return false;
                    }
                    $digest = hash_file('sha256', $actual);
                    if ($digest === false) {
                        return false;
                    }
                    $files[$relative] = $digest;
                }
            }
            ksort($files, SORT_STRING);
            return $files;
        };
        $remove = static function ($path) {
            if (is_link($path)) {
                return false;
            }
            if (is_file($path)) {
                return @unlink($path);
            }
            $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
            foreach ($iterator as $entry) {
                if ($entry->isLink() || (!$entry->isDir() && !$entry->isFile())) {
                    return false;
                }
                if (!($entry->isDir() ? @rmdir($entry->getPathname()) : @unlink($entry->getPathname()))) {
                    return false;
                }
            }
            return @rmdir($path);
        };
        $active = (array) get_option('active_plugins', array());
        foreach ($manifest['plugins'] as $slug => $expected) {
            if (!in_array($slug, array('akismet', 'hello.php'), true)) {
                continue;
            }
            $main = $slug === 'akismet' ? 'akismet/akismet.php' : 'hello.php';
            if (in_array($main, $active, true)) {
                $result['errors'][] = 'active plugin retained: ' . $slug;
                continue;
            }
            $root = $content . '/plugins';
            $path = $root . '/' . $slug;
            if (is_link($root) || $normalize(realpath($root)) !== $root || $fingerprint($path) !== $expected) {
                $result['errors'][] = 'modified or unsafe plugin retained: ' . $slug;
                continue;
            }
            if ($remove($path)) {
                $result['removed_plugins'][] = $slug;
            } else {
                $result['errors'][] = 'plugin cleanup failed: ' . $slug;
            }
        }

        $stylesheet = get_stylesheet();
        $template = get_template();
        $result['retained_themes'] = array_values(array_unique(array($stylesheet, $template)));
        $root = $content . '/themes';
        if (!is_string($stylesheet) || !is_string($template) || !$stylesheet || !$template ||
            is_link($root) || $normalize(realpath($root)) !== $root ||
            !is_dir($root . '/' . $stylesheet) || !is_dir($root . '/' . $template)) {
            throw new RuntimeException('active theme could not be verified; themes retained');
        }
        foreach ($manifest['themes'] as $slug => $expected) {
            if (in_array($slug, $result['retained_themes'], true)) {
                continue;
            }
            $path = $root . '/' . $slug;
            if (!preg_match('/^[a-z]+$/D', $slug) || $fingerprint($path) !== $expected) {
                $result['errors'][] = 'modified or unsafe theme retained: ' . $slug;
                continue;
            }
            if ($remove($path)) {
                $result['removed_themes'][] = $slug;
            } else {
                $result['errors'][] = 'theme cleanup failed: ' . $slug;
            }
        }
        if (function_exists('wp_clean_themes_cache')) {
            wp_clean_themes_cache(false);
        }
    } catch (Throwable $error) {
        $result['errors'][] = $error->getMessage();
    }
    if ($result['errors']) {
        $result['status'] = 'partial';
        error_log('OLS WPanel new-install default cleanup: ' . implode('; ', $result['errors']));
    }
    update_option($option, $result, false);
}, PHP_INT_MAX);
