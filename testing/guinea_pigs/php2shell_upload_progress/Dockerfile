# Deliberately vulnerable target for php2shell (CVE-2026-109618 / CVE-2026-109619):
# the session upload-progress heap use-after-free in ext/session. 8.4.26 is the
# last pre-fix build on the 8.4 branch; 8.4.27 is the patched release.
FROM php:8.4.26-apache

# Reproduce the public PoC's "bookworm" target profile. memory_limit stays well
# below the oversized multipart field so that field forces the OOM path the leak
# stage reads back; post/upload caps stay above it so the body is still accepted.
COPY php2shell.ini /usr/local/etc/php/conf.d/zzz-php2shell.ini

# One prefork worker. The exploit grooms a single worker's heap, so a single,
# non-recycling child is what makes the grooming deterministic.
COPY prefork-single.conf /etc/apache2/mods-available/mpm_prefork.conf

COPY index.php /var/www/html/index.php

EXPOSE 80
