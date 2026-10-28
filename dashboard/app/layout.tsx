import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "sudo-lab · Panel de laboratorio",
  description:
    "Diagnóstico de exposición y mitigación de vulnerabilidades de sudo en un entorno de laboratorio aislado.",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="es">
      <body>{children}</body>
    </html>
  );
}
