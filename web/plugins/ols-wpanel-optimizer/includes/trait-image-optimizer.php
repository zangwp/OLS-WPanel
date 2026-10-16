<?php
/**
 * OLS WPanel Optimizer upload image processing.
 * Re-encodes JPEG/PNG uploads or converts them to WebP in upload and sideload prefilters.
 * Processing precedes attachment creation so WordPress generates metadata from the final file.
 */

if (!defined('ABSPATH')) exit;

trait OLSW_Optimizer_Image_Trait {

    const OPTION_IMAGE_MODE          = 'olsw_optimizer_image_mode';
    const OPTION_IMAGE_JPEG_QUALITY  = 'olsw_optimizer_image_jpeg_quality';
    const OPTION_IMAGE_WEBP_QUALITY  = 'olsw_optimizer_image_webp_quality';
    const OPTION_IMAGE_SKIPPED_COUNT = 'olsw_optimizer_image_skipped_count';

    const IMAGE_MODE_OFF      = 'off';
    const IMAGE_MODE_OPTIMIZE = 'optimize';
    const IMAGE_MODE_WEBP     = 'webp';

    // Bound file size and pixel count before GD decoding to limit decompression bombs.
    // WordPress has no core pixel-limit constant; this fixed limit approximates memory_limit / 4.
    const IMAGE_MAX_UPLOAD_BYTES = 26214400;  // 25MB
    const IMAGE_MAX_PIXELS       = 100000000; // 100 million pixels, for example 10000x10000.

    /**
     * Check upload processing support. EXIF may be unavailable on a default install.
     * Like WordPress maybe_exif_rotate(), require exif_read_data so conversion
     * cannot silently lose orientation correction.
     */
    public static function image_optimizer_env_ready() {
        return is_callable('exif_read_data')
            && function_exists('imagecreatefromjpeg')
            && function_exists('imagecreatefrompng')
            && function_exists('imagejpeg')
            && function_exists('imagepng')
            && function_exists('imagerotate')
            && function_exists('imageflip');
    }

    public static function image_optimizer_mode() {
        if (!self::image_optimizer_env_ready()) {
            return self::IMAGE_MODE_OFF;
        }
        $mode = get_option(self::OPTION_IMAGE_MODE, self::IMAGE_MODE_OFF);
        if (!in_array($mode, [self::IMAGE_MODE_OFF, self::IMAGE_MODE_OPTIMIZE, self::IMAGE_MODE_WEBP], true)) {
            return self::IMAGE_MODE_OFF;
        }
        return $mode;
    }

    public static function image_optimizer_init() {
        // Run after other upload validators so rejected files never reach expensive GD decoding.
        add_filter('wp_handle_upload_prefilter', [__CLASS__, 'convert_uploaded_image'], PHP_INT_MAX);
        add_filter('wp_handle_sideload_prefilter', [__CLASS__, 'convert_uploaded_image'], PHP_INT_MAX);

        // The panel runs batch jobs because they require runuser and system binaries
        // unavailable to LSPHP. Forward actions to /api/sites/image-optimizer/* using
        // X-OLS-WPanel-Key authentication; the panel owns job state.
        add_action('wp_ajax_olsw_optimizer_image_batch_start', [__CLASS__, 'ajax_image_batch_start']);
        add_action('wp_ajax_olsw_optimizer_image_batch_status', [__CLASS__, 'ajax_image_batch_status']);
        add_action('wp_ajax_olsw_optimizer_image_batch_stop', [__CLASS__, 'ajax_image_batch_stop']);
    }

    public static function ajax_image_batch_start() {
        check_ajax_referer('olsw_optimizer_settings');
        if (!current_user_can('manage_options')) {
            wp_send_json(['success' => false, 'data' => ['message' => __('Insufficient permissions', 'ols-wpanel-optimizer')]]);
            return;
        }
        $domain = wp_parse_url(home_url(), PHP_URL_HOST);
        self::relay_image_batch_response(
            self::api_request_public('POST', '/api/sites/image-optimizer/start', ['domain' => $domain])
        );
    }

    public static function ajax_image_batch_status() {
        check_ajax_referer('olsw_optimizer_settings');
        if (!current_user_can('manage_options')) {
            wp_send_json(['success' => false, 'data' => ['message' => __('Insufficient permissions', 'ols-wpanel-optimizer')]]);
            return;
        }
        $domain = wp_parse_url(home_url(), PHP_URL_HOST);
        self::relay_image_batch_response(
            self::api_request_public('GET', '/api/sites/image-optimizer/status?domain=' . urlencode($domain))
        );
    }

    public static function ajax_image_batch_stop() {
        check_ajax_referer('olsw_optimizer_settings');
        if (!current_user_can('manage_options')) {
            wp_send_json(['success' => false, 'data' => ['message' => __('Insufficient permissions', 'ols-wpanel-optimizer')]]);
            return;
        }
        $domain = wp_parse_url(home_url(), PHP_URL_HOST);
        self::relay_image_batch_response(
            self::api_request_public('POST', '/api/sites/image-optimizer/stop', ['domain' => $domain])
        );
    }

    private static function relay_image_batch_response($resp) {
        if (is_wp_error($resp)) {
            wp_send_json(['success' => false, 'data' => ['message' => $resp->get_error_message()]]);
            return;
        }
        $data = json_decode($resp, true);
        if (!is_array($data) || empty($data['success'])) {
            wp_send_json(['success' => false, 'data' => ['message' => ($data['message'] ?? __('The panel returned an error', 'ols-wpanel-optimizer'))]]);
            return;
        }
        wp_send_json(['success' => true, 'data' => $data['data'] ?? null]);
    }

    /**
     * Upload and sideload prefilter callback.
     * Return the original $file on any processing failure so uploads can continue.
     */
    public static function convert_uploaded_image($file) {
        $mode = self::image_optimizer_mode();
        if ($mode === self::IMAGE_MODE_OFF) {
            return $file;
        }

        // Preserve existing upload errors, including strings set by other plugins.
        // intval() would turn a string error into zero and incorrectly permit processing.
        if (!empty($file['error'])) {
            return $file;
        }
        if (empty($file['tmp_name']) || empty($file['name']) || !is_readable($file['tmp_name'])) {
            return $file;
        }

        // REST binary sideloads may omit size; fall back to filesize().
        $size = (isset($file['size']) && $file['size'] > 0) ? intval($file['size']) : @filesize($file['tmp_name']);
        if (!$size || $size > self::IMAGE_MAX_UPLOAD_BYTES) {
            return $file;
        }

        // Inspect headers without decoding; only process JPEG and PNG.
        $imageInfo = @getimagesize($file['tmp_name']);
        if (!$imageInfo || empty($imageInfo['mime'])) {
            return $file;
        }
        $sourceMime = $imageInfo['mime'];
        if ($sourceMime === 'image/webp') {
            return $file;
        }
        if (!in_array($sourceMime, ['image/jpeg', 'image/png'], true)) {
            return $file;
        }

        // Reject excessive pixel counts before the expensive full GD decode.
        $width  = isset($imageInfo[0]) ? intval($imageInfo[0]) : 0;
        $height = isset($imageInfo[1]) ? intval($imageInfo[1]) : 0;
        if ($width <= 0 || $height <= 0 || ($width * $height) > self::IMAGE_MAX_PIXELS) {
            return $file;
        }

        $image = ($sourceMime === 'image/jpeg')
            ? @imagecreatefromjpeg($file['tmp_name'])
            : @imagecreatefrompng($file['tmp_name']);
        if (!$image) {
            // Unsupported variants, such as CMYK JPEG, may fail GD decoding.
            self::bump_image_skipped_count();
            return $file;
        }

        if ($sourceMime === 'image/jpeg') {
            self::apply_exif_orientation($image, $file['tmp_name']);
        }

        $targetMime = ($mode === self::IMAGE_MODE_WEBP) ? 'image/webp' : $sourceMime;
        $encoded = self::encode_image($image, $targetMime);
        imagedestroy($image);

        if ($encoded === false || $encoded === '') {
            self::bump_image_skipped_count();
            return $file;
        }

        // Compare sizes before overwriting tmp_name so larger output leaves the original intact.
        if (strlen($encoded) >= $size) {
            self::bump_image_skipped_count();
            return $file;
        }

        // Keep the original tmp_name path: wp_handle_upload later checks is_uploaded_file(),
        // which would reject a newly created replacement file.
        //
        // file_put_contents truncates before writing and can fail midway, for example on a full disk.
        // Keep the size-bounded original bytes in memory and attempt restoration on write failure.
        $originalBytes = @file_get_contents($file['tmp_name']);
        if ($originalBytes === false) {
            self::bump_image_skipped_count();
            return $file;
        }
        if (@file_put_contents($file['tmp_name'], $encoded) === false) {
            @file_put_contents($file['tmp_name'], $originalBytes);
            self::bump_image_skipped_count();
            return $file;
        }

        if ($targetMime !== $sourceMime) {
            $newName = preg_replace('/\.(jpe?g|png)$/i', '.webp', $file['name']);
            if (!$newName || $newName === $file['name']) {
                $newName = $file['name'] . '.webp';
            }
            $file['name'] = $newName;
        }
        $file['type'] = $targetMime;

        return $file;
    }

    /**
     * Apply EXIF orientations 2-8 using WP_Image_Editor::maybe_exif_rotate() semantics.
     * Orientations 5 and 7 combine a 90-degree rotation with a flip.
     */
    private static function apply_exif_orientation(&$image, $path) {
        $exif = @exif_read_data($path);
        if (!$exif || empty($exif['Orientation'])) {
            return;
        }

        $orientation = intval($exif['Orientation']);
        switch ($orientation) {
            case 2:
                imageflip($image, IMG_FLIP_HORIZONTAL);
                break;
            case 3:
                imageflip($image, IMG_FLIP_BOTH);
                break;
            case 4:
                imageflip($image, IMG_FLIP_VERTICAL);
                break;
            case 5:
                $rotated = imagerotate($image, 90, 0);
                if ($rotated !== false) {
                    $image = $rotated;
                    imageflip($image, IMG_FLIP_VERTICAL);
                }
                break;
            case 6:
                $rotated = imagerotate($image, 270, 0);
                if ($rotated !== false) {
                    $image = $rotated;
                }
                break;
            case 7:
                $rotated = imagerotate($image, 90, 0);
                if ($rotated !== false) {
                    $image = $rotated;
                    imageflip($image, IMG_FLIP_HORIZONTAL);
                }
                break;
            case 8:
                $rotated = imagerotate($image, 90, 0);
                if ($rotated !== false) {
                    $image = $rotated;
                }
                break;
        }
    }

    /**
     * Encode the GD image to bytes, or return false on failure.
     * The caller can compare sizes before overwriting tmp_name.
     */
    private static function encode_image($image, $targetMime) {
        ob_start();
        $ok = false;
        if ($targetMime === 'image/webp') {
            $quality = self::clamp_image_quality(get_option(self::OPTION_IMAGE_WEBP_QUALITY, 82));
            $ok = function_exists('imagewebp') && imagewebp($image, null, $quality);
        } elseif ($targetMime === 'image/jpeg') {
            $quality = self::clamp_image_quality(get_option(self::OPTION_IMAGE_JPEG_QUALITY, 85));
            $ok = imagejpeg($image, null, $quality);
        } elseif ($targetMime === 'image/png') {
            imagesavealpha($image, true);
            $ok = imagepng($image, null, 9);
        }
        $data = ob_get_clean();
        return $ok ? $data : false;
    }

    private static function clamp_image_quality($value) {
        $value = intval($value);
        if ($value < 1) return 1;
        if ($value > 100) return 100;
        return $value;
    }

    /**
     * Count skipped conversions, including validation, codec, and size-regression failures,
     * for the settings page.
     */
    private static function bump_image_skipped_count() {
        $count = intval(get_option(self::OPTION_IMAGE_SKIPPED_COUNT, 0));
        update_option(self::OPTION_IMAGE_SKIPPED_COUNT, $count + 1, false);
    }
}
