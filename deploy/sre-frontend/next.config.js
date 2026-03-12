/** @type {import('next').NextConfig} */
const nextConfig = {
  basePath: '/portal',
  output: 'standalone',
  trailingSlash: true,
  env: {
    AUTH_SECRET: process.env.AUTH_SECRET,
  },
};

module.exports = nextConfig;
