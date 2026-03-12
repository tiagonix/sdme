# sdme WordPress Pod Verification Report

## System Info

| Field | Value |
|-------|-------|
| Date | 2026-03-12T12:53:53+00:00 |
| Hostname | lima-default |
| Kernel | 6.17.0-14-generic |
| systemd | systemd 257 (257.9-0ubuntu2.1) |
| sdme | 0.3.1 |
| Base FS | ubuntu |

## Summary

| Result | Count |
|--------|-------|
| PASS | 14 |
| FAIL | 0 |
| SKIP | 0 |
| Total | 14 |

## Results

| Test | Result |
|------|--------|
| create/kube | PASS |
| setup/nginx-config | PASS |
| setup/validate-script | PASS |
| start/pod | PASS |
| service/mysql | PASS |
| service/wordpress | PASS |
| service/nginx | PASS |
| ready/mysql | PASS |
| ready/wordpress | PASS |
| ready/nginx | PASS |
| validate/wp-install | PASS |
| validate/xmlrpc-create-post | PASS |
| validate/rest-api-read-post | PASS |
| validate/post-title-match | PASS |

