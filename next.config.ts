import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  experimental: {
    // ppr: 'incremental', // allows you to adopt PPR for specific routes.
    // Limiter la taille des payloads Server Actions (sécurité CVE-2025-55183/55184)
    serverActions: {
      bodySizeLimit: '1mb' // Protection contre les attaques DoS
    }
  },
  
  // Headers de sécurité renforcés (protection CVE)
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff'
          },
          {
            key: 'X-Frame-Options',
            value: 'DENY'
          },
          {
            key: 'X-XSS-Protection',
            value: '1; mode=block'
          },
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin'
          },
          {
            key: 'Content-Security-Policy',
            value: "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https:; font-src 'self' data:; connect-src 'self' https:;"
          }
        ]
      }
    ]
  }
};

export default nextConfig;
