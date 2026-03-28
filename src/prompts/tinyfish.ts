export function buildTinyfishGoal(url: string, interact: boolean): string {
  const interactionInstructions = interact
    ? [
        "Act as a phishing investigator imitating a cautious victim.",
        "Explore the landing page and relevant internal flows.",
        "Click suspicious calls to action, login buttons, reset-password links, or payment prompts when visible.",
        "If a form appears, inspect it and you may type obviously fake bait values like test@example.com, fake passwords, or dummy names.",
        "Do not use real secrets, do not complete irreversible purchases, and do not intentionally submit harmful payloads.",
      ].join(" ")
    : [
        "Act as a phishing investigator.",
        "Observe the page without aggressive interaction.",
        "Inspect visible forms, links, branding, and phishing cues.",
      ].join(" ");

  return [
    interactionInstructions,
    `Target URL: ${url}.`,
    "Return strict JSON only with this exact shape:",
    "{",
    '  "final_url": "string",',
    '  "page_title": "string",',
    '  "dom_text": "string",',
    '  "form_fields": ["string"],',
    '  "form_action": "string or null",',
    '  "external_links": ["string"],',
    '  "screenshot": "string"',
    "}",
    "Rules:",
    "- final_url must be the final loaded page URL.",
    "- dom_text should contain balanced visible text: include both phishing-looking content AND legitimacy signals (e.g. 'About Us', privacy policy links, real contact details). Do not cherry-pick only suspicious text.",
    "- form_fields should list every input type collected by any form on the page. Use short labels from this set: email, username, password, otp, phone, credit_card, cvv, ssn, name, address, search, message, other. Only include forms that POST data — exclude read-only or search-only forms. If there are no data-collecting forms, return an empty array.",
    "- form_action should be the 'action' attribute of the most sensitive form on the page (the one collecting the most sensitive fields). Return null if there are no forms.",
    "- external_links should include outbound or suspicious link destinations visible on the page.",
    "- screenshot should be a base64 PNG string if available, otherwise an empty string.",
    "- If a field cannot be determined, return a safe empty value instead of adding extra keys.",
  ].join("\n");
}
