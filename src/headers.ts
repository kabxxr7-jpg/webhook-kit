/** Node's `req.headers`, a plain object, or the Web `Headers` class (Next.js, Hono, Workers). */
export type HeadersLike =
  | Headers
  | Readonly<Record<string, string | readonly string[] | undefined>>;

/** Case-insensitive single-value lookup. Repeated headers use the first value. */
export function getHeader(headers: HeadersLike, name: string): string | undefined {
  if (typeof (headers as Headers).get === "function") {
    return (headers as Headers).get(name) ?? undefined;
  }
  const wanted = name.toLowerCase();
  for (const [key, value] of Object.entries(headers as Record<string, string | readonly string[] | undefined>)) {
    if (key.toLowerCase() !== wanted) continue;
    if (Array.isArray(value)) return value[0] as string | undefined;
    return value as string | undefined;
  }
  return undefined;
}
