export function containsSentinel(url: string, values: Iterable<string>, marker: string): boolean {
  if (url.includes(marker)) return true;
  try {
    if (decodeURIComponent(url).includes(marker)) return true;
  } catch {
    // Malformed percent escapes must not suppress a header-carried placeholder.
  }
  return [...values].some((value) => value.includes(marker));
}
