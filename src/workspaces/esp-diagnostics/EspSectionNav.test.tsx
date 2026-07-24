import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { EspSectionNav } from "./EspSectionNav";

afterEach(() => {
  document.body.innerHTML = "";
});

describe("EspSectionNav", () => {
  it("scrolls a section heading into view when its pill is clicked", () => {
    const scrollIntoView = vi.fn();
    // jsdom does not implement scrollIntoView.
    Element.prototype.scrollIntoView = scrollIntoView;
    const target = document.createElement("div");
    target.id = "esp-workloads-heading";
    document.body.appendChild(target);

    render(
      <EspSectionNav
        sections={[{ id: "esp-workloads-heading", label: "Workloads" }]}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Workloads" }));
    expect(scrollIntoView).toHaveBeenCalledTimes(1);
  });

  it("always offers a Top button", () => {
    render(<EspSectionNav sections={[]} />);
    expect(screen.getByRole("button", { name: /Top/ })).toBeInTheDocument();
  });
});
