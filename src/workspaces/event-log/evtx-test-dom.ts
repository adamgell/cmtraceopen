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

export interface LayoutStub {
  /** Restores the real layout methods. */
  (): void;
  /** Changes the stubbed widths (the next measurement sees them). */
  set(renderedWidths: Record<string, number>, clientWidth: number): void;
}

/**
 * jsdom does no layout. Stubs `getBoundingClientRect().width`: elements whose id is in
 * `renderedWidths` get that (fractional) width and every other element, which includes the body
 * row, gets `rowWidth`. Call the result to restore; `set` changes the widths, as a window resize
 * would.
 */
export function stubLayout(initialWidths: Record<string, number>, initialClientWidth: number): LayoutStub {
  let renderedWidths = initialWidths;
  let clientWidth = initialClientWidth;
  const proto = HTMLElement.prototype;
  const originalRect = proto.getBoundingClientRect;
  const originalClient = Object.getOwnPropertyDescriptor(Element.prototype, "clientWidth");
  proto.getBoundingClientRect = function getBoundingClientRect(this: HTMLElement) {
    const width = renderedWidths[this.id] ?? clientWidth;
    return { width, height: 0, top: 0, left: 0, right: width, bottom: 0, x: 0, y: 0, toJSON() {} };
  };
  Object.defineProperty(Element.prototype, "clientWidth", {
    configurable: true,
    get: () => clientWidth,
  });
  const restore = () => {
    proto.getBoundingClientRect = originalRect;
    if (originalClient) Object.defineProperty(Element.prototype, "clientWidth", originalClient);
    else delete (Element.prototype as unknown as Record<string, unknown>).clientWidth;
  };
  return Object.assign(restore, {
    set(widths: Record<string, number>, client: number) {
      renderedWidths = widths;
      clientWidth = client;
    },
  });
}
