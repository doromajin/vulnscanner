<?php
/**
 * Confirmed FP fixed in commit bfda722.
 *
 * DESER-004 previously fired on user-defined methods named unserialize().
 * The rule now skips: (a) function definitions, (b) method-call forms ($this->unserialize).
 * Source: bludit dbjson.class.php — private method wrapping json_decode().
 */
class DbJson {
    private function unserialize($data) {
        return json_decode($data, true);
    }

    public function loadFile($path) {
        $raw = file_get_contents($path);
        return $this->unserialize($raw);
    }
}
?>
