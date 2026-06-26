<?php
// Negative: PHP deserialization patterns that are suppressed by DESER-004 guards.

// PHP 7.0+ allowed_classes=false — object injection is impossible
function loadCachedEntry($serialized) {
    return unserialize($serialized, ['allowed_classes' => false]);
}

// Private method named unserialize() — user-defined wrapper, not PHP's built-in.
// DESER-004 skips function definitions and method-call forms.
class DataStore {
    private function unserialize($data) {
        return json_decode($data, true);
    }

    public function load($path) {
        $raw = file_get_contents($path);
        return $this->unserialize($raw);
    }
}

// Multi-line safe unserialize
function safeLoad($data) {
    return unserialize(
        $data,
        ['allowed_classes' => false]
    );
}
?>
