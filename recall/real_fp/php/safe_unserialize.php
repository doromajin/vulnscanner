<?php
/**
 * Confirmed FP fixed in commit bfda722.
 *
 * DESER-004 previously fired on all unserialize() calls.
 * PHP 7.0+ safe form with allowed_classes=false prevents object injection.
 * Source: snipe-it ActionlogsTransformer.php.
 */
function loadActionLog($serialized) {
    return unserialize($serialized, ['allowed_classes' => false]);
}

class CacheManager {
    public function retrieve(string $key): mixed {
        $cached = $this->store->get($key);
        return $cached !== null
            ? unserialize($cached, ['allowed_classes' => false])
            : null;
    }
}
?>
