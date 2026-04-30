- [x] TLS fingerprinting (JA4) — internal/tlsfp/ + middleware/ja3.go
      JA4 replaces JA3: sorts before hashing, immune to order randomisation.
      Native peek listener for direct TLS; X-JA4-Hash header for nginx mode.
- [x] IP reputation with own dataset — internal/reputation/
      Group scoring across /24 subnet, JA4 fingerprint, ASN (optional MaxMind).
      Lazy exponential decay. Outermost middleware observes all 403/429s and
      propagates penalties to groups. New IPs inherit group suspicion.
- [x] maybe not hardcode html — challenges/templates/ with disk-override
      via challenges.template_dir config option
