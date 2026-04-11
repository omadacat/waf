- [x] TLS fingerprinting (JA4) — internal/tlsfp/ + middleware/ja3.go
      JA4 replaces JA3: sorts ciphers/extensions before hashing so
      order-randomisation attacks don't work. Native peek listener for
      direct TLS mode; X-JA4-Hash header fallback for nginx-fronted mode.
- [ ] IP reputation with own dataset — CrowdSec dropped; rolling our own
- [x] maybe not hardcode html — challenges/templates/ with disk-override
      via challenges.template_dir config option
