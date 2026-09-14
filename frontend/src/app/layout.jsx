import './globals.css';

export const metadata = {
  title: 'NetShield AI — Network Anomaly Detection & Threat Monitoring',
  description: 'Enterprise Security Operations Center (SOC) Terminal Platform',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body className="bg-bg text-text-main font-sans antialiased min-h-screen">
        {children}
      </body>
    </html>
  );
}
