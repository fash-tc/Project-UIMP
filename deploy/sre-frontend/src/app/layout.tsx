import type { Metadata } from 'next';
import './globals.css';
import { AuthProviderWrapper } from './AuthProviderWrapper';
import AppChrome from './AppChrome';

export const metadata: Metadata = {
  title: 'UIP - SRE Command Center',
  description: 'Unified Incident Management Platform',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-bg">
        <AuthProviderWrapper>
          <AppChrome>{children}</AppChrome>
        </AuthProviderWrapper>
      </body>
    </html>
  );
}
