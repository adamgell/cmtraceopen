/** Test helper: narrows a DOM query result, failing with a message that names what was missing. */
export function requireElement<T extends Element>(
  value: T | null | undefined,
  what: string,
): T {
  if (value === null || value === undefined) {
    throw new Error(`Expected ${what} to be in the document, but it was not found`);
  }
  return value;
}

export function requireSelector<T extends Element = HTMLElement>(selector: string): T {
  return requireElement(document.querySelector<T>(selector), `an element matching ${selector}`);
}

/**
 * jsdom does no layout. Stubs `getBoundingClientRect().width` for elements by id and a single
 * `clientWidth` for every element, so measurement hooks see a laid-out page. Returns a restore.
 */
export function stubLayout(renderedWidths: Record<string, number>, clientWidth: number): () => void {
  const proto = HTMLElement.prototype;
  const originalRect = proto.getBoundingClientRect;
  const originalClient = Object.getOwnPropertyDescriptor(Element.prototype, "clientWidth");
  proto.getBoundingClientRect = function getBoundingClientRect(this: HTMLElement) {
    const width = renderedWidths[this.id] ?? 0;
    return { width, height: 0, top: 0, left: 0, right: width, bottom: 0, x: 0, y: 0, toJSON() {} };
  };
  Object.defineProperty(Element.prototype, "clientWidth", {
    configurable: true,
    get: () => clientWidth,
  });
  return () => {
    proto.getBoundingClientRect = originalRect;
    if (originalClient) Object.defineProperty(Element.prototype, "clientWidth", originalClient);
    else delete (Element.prototype as unknown as Record<string, unknown>).clientWidth;
  };
}
