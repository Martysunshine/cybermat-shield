/** @type {import('next').NextConfig} */
const nextConfig = {
  // VULNERABLE: No security headers configured — scanner should flag this
  // VULNERABLE: Source maps exposed in production
  productionBrowserSourceMaps: true,
};

module.exports = nextConfig;
