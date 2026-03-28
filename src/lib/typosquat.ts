/**
 * Generates common typosquatted domain variants for a given domain.
 * Produces up to ~20 candidates; caller should trim to desired count.
 */

export function generateTyposquats(domain: string): string[] {
  // Strip TLD for manipulation
  const parts = domain.split(".");
  const tld = parts.slice(-1)[0];
  const name = parts.slice(0, -1).join(".");

  const variants = new Set<string>();

  // 1. Character omissions (remove each char once)
  for (let i = 0; i < name.length; i++) {
    const v = name.slice(0, i) + name.slice(i + 1);
    if (v) variants.add(`${v}.${tld}`);
  }

  // 2. Adjacent key transpositions
  for (let i = 0; i < name.length - 1; i++) {
    const v =
      name.slice(0, i) + name[i + 1] + name[i] + name.slice(i + 2);
    variants.add(`${v}.${tld}`);
  }

  // 3. Character doublings (most common typo)
  for (let i = 0; i < name.length; i++) {
    const v = name.slice(0, i) + name[i] + name[i] + name.slice(i + 1);
    variants.add(`${v}.${tld}`);
  }

  // 4. Homoglyph substitutions
  const homoglyphs: Record<string, string> = {
    a: "4", e: "3", i: "1", o: "0", s: "5", l: "1",
  };
  for (const [char, sub] of Object.entries(homoglyphs)) {
    if (name.includes(char)) {
      variants.add(`${name.replace(char, sub)}.${tld}`);
    }
  }

  // 5. Common prefix/suffix additions
  for (const affix of ["secure-", "login-", "-verify", "-online", "-official"]) {
    variants.add(
      affix.startsWith("-")
        ? `${name}${affix}.${tld}`
        : `${affix}${name}.${tld}`
    );
  }

  // 6. TLD swaps
  for (const altTld of ["com", "net", "org", "co", "io"].filter((t) => t !== tld)) {
    variants.add(`${name}.${altTld}`);
  }

  // Remove the original domain and return
  variants.delete(domain);
  return Array.from(variants).slice(0, 20);
}
