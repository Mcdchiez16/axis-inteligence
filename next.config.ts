import type { NextConfig } from 'next';

const config: NextConfig = {
  poweredByHeader: false,
  // build a self-contained server bundle (.next/standalone) for the Docker image
  output: 'standalone',
  // pdfkit reads its font metrics from its own package folder at runtime
  serverExternalPackages: ['pdfkit'],
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
        ],
      },
    ];
  },
};

export default config;
