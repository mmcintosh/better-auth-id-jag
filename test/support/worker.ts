// The workerd project's main module. Tests build their own hosts; nothing is served from here.
export default { fetch: () => new Response(null, { status: 404 }) };
