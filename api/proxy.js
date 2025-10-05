// proxy.js — Universal Resolver Proxy (正式W3C準拠)
export default {
  async fetch(request) {
    const url = new URL(request.url);
    const did = url.searchParams.get("did");
    if (!did) return new Response(JSON.stringify({ error: "Missing DID" }), { status: 400 });

    try {
      const res = await fetch(`https://dev.uniresolver.io/1.0/identifiers/${did}`);
      if (!res.ok) throw new Error(`Resolver returned ${res.status}`);
      const data = await res.text();

      return new Response(data, {
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
        },
      });
    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), {
        status: 500,
        headers: { "Access-Control-Allow-Origin": "*" },
      });
    }
  },
};