"""Fake bank – an offline MCP server for the lookfirst demo. Synthetic data only, nothing real.
Tools: kontostand (read-only), ueberweisung (destructive)."""
import anyio
import mcp.types as t
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

KONTO = {"saldo": 1250.00, "buchungen": []}
# Synthetic statement for the Schleuse demo: standard example IBAN (valid checksum, no real account), invented names.
UMSAETZE = [{"datum": "2026-10-20", "betrag": -89.90, "empfaenger": "Erika Mustermann", "iban": "DE89 3704 0044 0532 0130 00"},
            {"datum": "2026-10-22", "betrag": -12.50, "empfaenger": "Max Beispiel", "iban": "GB82WEST12345698765432"}]


async def list_tools(ctx, params):
    return t.ListToolsResult(tools=[
        t.Tool(name="kontostand", description="Returns the current balance (EUR).", inputSchema={"type": "object", "properties": {}},
               annotations=t.ToolAnnotations(readOnlyHint=True)),
        t.Tool(name="umsaetze", description="Lists recent transactions.", inputSchema={"type": "object", "properties": {}},
               annotations=t.ToolAnnotations(readOnlyHint=True)),
        t.Tool(name="ueberweisung", description="Transfers money from the account.",
               inputSchema={"type": "object", "properties": {"an": {"type": "string"}, "betrag": {"type": "number"}, "zweck": {"type": "string"}}, "required": ["an", "betrag"]},
               annotations=t.ToolAnnotations(destructiveHint=True)),
    ])


async def call_tool(ctx, params):
    if params.name == "kontostand":
        return t.CallToolResult(content=[t.TextContent(type="text", text=f"Saldo: {KONTO['saldo']:.2f} EUR")], structuredContent={"saldo": KONTO["saldo"], "buchungen": len(KONTO["buchungen"])})
    if params.name == "umsaetze":
        text = "; ".join(f"{u['datum']} {u['betrag']:.2f} EUR {u['empfaenger']} {u['iban']}" for u in UMSAETZE)
        return t.CallToolResult(content=[t.TextContent(type="text", text=text)], structuredContent={"umsaetze": UMSAETZE})
    if params.name == "ueberweisung":
        a = params.arguments or {}
        betrag = float(a["betrag"])
        if betrag <= 0 or betrag > KONTO["saldo"]:
            return t.CallToolResult(content=[t.TextContent(type="text", text="abgelehnt: Betrag ungültig oder Saldo zu niedrig")], isError=True)
        KONTO["saldo"] = round(KONTO["saldo"] - betrag, 2)
        KONTO["buchungen"].append({"an": a["an"], "betrag": betrag, "zweck": a.get("zweck", "")})
        return t.CallToolResult(content=[t.TextContent(type="text", text=f"Überwiesen: {betrag:.2f} EUR an {a['an']}")], structuredContent={"saldo": KONTO["saldo"], "buchungen": len(KONTO["buchungen"])})
    return t.CallToolResult(content=[t.TextContent(type="text", text="unknown tool")], isError=True)


server = Server("fake-bank", version="0.1", on_list_tools=list_tools, on_call_tool=call_tool)


async def main():
    async with stdio_server() as (r, w):
        await server.run(r, w, server.create_initialization_options())


if __name__ == "__main__":
    anyio.run(main)
