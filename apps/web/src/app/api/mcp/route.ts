import { getLiveAttackariumMcpHandler } from "@/lib/mcp-server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request): Promise<Response> {
  return getLiveAttackariumMcpHandler()(request);
}

export async function POST(request: Request): Promise<Response> {
  return getLiveAttackariumMcpHandler()(request);
}
