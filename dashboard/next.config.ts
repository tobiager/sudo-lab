import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Las API routes ejecutan `docker exec` contra el contenedor del laboratorio.
  // Se fuerza runtime Node (no edge) en cada route con `export const runtime`.
};

export default nextConfig;
