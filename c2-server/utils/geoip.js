"use strict";

const https = require("https");

const PRIVATE = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|::1$|fc|fd|::ffff:10\.|::ffff:192\.168\.|::ffff:127\.)/i;

function isPrivate(ip) {
    return !ip || PRIVATE.test(ip.replace(/^::ffff:/, ""));
}

/**
 * Look up city-level coordinates for a public IP using ip-api.com (free, no key).
 * Returns {lat, lon, city, country, isp} or null if private/unavailable.
 * Rate limit: 45 req/min on the free tier — fine for check-in use.
 */
function geoIp(ip) {
    const clean = (ip || "").split(",")[0].trim().replace(/^::ffff:/, "");
    if (isPrivate(clean)) return Promise.resolve(null);

    return new Promise(resolve => {
        const url = `https://ip-api.com/json/${encodeURIComponent(clean)}?fields=status,lat,lon,city,country,isp,org`;
        const req = https.get(url, res => {
            let raw = "";
            res.on("data", d => raw += d);
            res.on("end", () => {
                try {
                    const j = JSON.parse(raw);
                    if (j.status === "success") {
                        resolve({ lat: j.lat, lon: j.lon, city: j.city, country: j.country, isp: j.isp || j.org || "" });
                    } else {
                        resolve(null);
                    }
                } catch { resolve(null); }
            });
        });
        req.on("error", () => resolve(null));
        req.setTimeout(5000, () => { req.destroy(); resolve(null); });
    });
}

module.exports = { geoIp, isPrivate };
