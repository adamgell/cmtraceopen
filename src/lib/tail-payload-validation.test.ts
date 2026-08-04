import { describe, expect, it } from "vitest";
import type { LogEntry, TailEntryAmendment, TailPayload } from "../types/log";
import { parseTailPayload } from "./tail-payload-validation";

function entry(overrides: Partial<LogEntry> = {}): LogEntry {
  return {
    id: 0,
    lineNumber: 1,
    message: "started",
    component: null,
    timestamp: null,
    timestampDisplay: null,
    severity: "Info",
    thread: null,
    threadDisplay: null,
    sourceFile: null,
    format: "Timestamped",
    filePath: "/logs/Log_1.log",
    timezoneOffset: null,
    ...overrides,
  };
}

function amendment(
  overrides: Partial<TailEntryAmendment> = {},
): TailEntryAmendment {
  return {
    entryId: 0,
    entryLineNumber: 1,
    continuationStartLine: 2,
    continuationEndLine: 2,
    messageUtf16Start: 7,
    messageSuffix: "\ncontinued",
    errorCodeSpans: [],
    ...overrides,
  };
}

function payload(overrides: Partial<TailPayload> = {}): TailPayload {
  return {
    entries: [],
    amendments: [],
    filePath: "/logs/Log_1.log",
    parseErrors: 0,
    observedThroughLine: null,
    reset: false,
    ...overrides,
  };
}

describe("parseTailPayload", () => {
  it.each([
    {
      name: "entry start line",
      value: payload({
        entries: [entry({ lineNumber: 3 })],
        observedThroughLine: 2,
      }),
    },
    {
      name: "entry message physical span",
      value: payload({
        entries: [entry({ lineNumber: 2, message: "first\nsecond" })],
        observedThroughLine: 2,
      }),
    },
    {
      name: "amendment physical span",
      value: payload({
        amendments: [amendment({ continuationEndLine: 3, messageSuffix: "\na\nb" })],
        observedThroughLine: 2,
      }),
    },
    {
      name: "missing observation for an entry",
      value: payload({ entries: [entry()] }),
    },
    {
      name: "missing observation for an amendment",
      value: payload({ amendments: [amendment()] }),
    },
  ])("rejects observedThroughLine below the $name", ({ value }) => {
    expect(parseTailPayload(value)).toBeNull();
  });

  it.each([
    {
      name: "continuation at the entry start line",
      value: amendment({ continuationStartLine: 1, continuationEndLine: 1 }),
    },
    {
      name: "span before the appended suffix",
      value: amendment({
        errorCodeSpans: [
          {
            start: 6,
            end: 7,
            codeHex: "0x0",
            codeDecimal: "0",
            description: "success",
            category: "Win32",
          },
        ],
      }),
    },
    {
      name: "span after the appended suffix",
      value: amendment({
        errorCodeSpans: [
          {
            start: 8,
            end: 18,
            codeHex: "0x0",
            codeDecimal: "0",
            description: "success",
            category: "Win32",
          },
        ],
      }),
    },
  ])("rejects an amendment with $name", ({ value }) => {
    expect(
      parseTailPayload(
        payload({
          amendments: [value],
          observedThroughLine: value.continuationEndLine,
        }),
      ),
    ).toBeNull();
  });

  const validOptionalFields: Record<string, unknown> = {
    errorCodeSpans: [
      {
        start: 0,
        end: 7,
        codeHex: "0x00000000",
        codeDecimal: "0",
        description: "success",
        category: "Win32",
      },
    ],
    ipAddress: "192.0.2.1",
    hostName: "device",
    macAddress: "00-11-22-33-44-55",
    resultCode: "0x00000000",
    gleCode: "0x00000000",
    setupPhase: "SetupPhaseInstall",
    operationName: "Apply Drivers",
    httpMethod: "GET",
    uriStem: "/health",
    uriQuery: "full=true",
    statusCode: 200,
    subStatus: 0,
    timeTakenMs: 25,
    clientIp: "192.0.2.2",
    serverIp: "192.0.2.3",
    userAgent: "CMTraceOpen",
    serverPort: 443,
    username: "CONTOSO\\user",
    win32Status: 0,
    queryName: "example.test",
    queryType: "A",
    responseCode: "NOERROR",
    dnsDirection: "Rcv",
    dnsProtocol: "UDP",
    sourceIp: "192.0.2.4",
    dnsFlags: "8180",
    dnsEventId: 257,
    zoneName: "example.test",
    entryKind: "Log",
    whatif: false,
    sectionName: "Detection",
    sectionColor: "#5b9aff",
    iteration: "1",
    tags: ["test", "tail"],
  };

  it("accepts every serialized optional LogEntry field", () => {
    const value = payload({
      entries: [entry({ message: "success", ...validOptionalFields })],
      observedThroughLine: 1,
    });

    expect(parseTailPayload(value)).toEqual(value);
  });

  it("preserves nullable optional LogEntry fields", () => {
    const nullableFields = Object.fromEntries(
      [
        ...Object.keys(validOptionalFields).filter(
          (field) =>
            ![
              "errorCodeSpans",
              "entryKind",
              "whatif",
              "sectionName",
              "sectionColor",
              "iteration",
              "tags",
            ].includes(field),
        ),
      ].map((field) => [field, null]),
    );
    const value = payload({
      entries: [entry(nullableFields)],
      observedThroughLine: 1,
    });

    expect(parseTailPayload(value)).toEqual(value);
  });

  it("validates message spans in JavaScript UTF-16 offsets", () => {
    const value = payload({
      entries: [
        entry({
          message: "🙂",
          errorCodeSpans: [
            {
              start: 0,
              end: 2,
              codeHex: "0x0",
              codeDecimal: "0",
              description: "success",
              category: "Win32",
            },
          ],
        }),
      ],
      observedThroughLine: 1,
    });

    expect(parseTailPayload(value)).toEqual(value);
  });

  it.each(
    Object.keys(validOptionalFields).map((field) => [
      field,
      field === "tags" ? ["valid", 1] : {},
    ]),
  )("rejects an invalid optional LogEntry %s", (field, invalidValue) => {
    expect(
      parseTailPayload(
        payload({
          entries: [
            {
              ...entry(),
              [field]: invalidValue,
            },
          ],
          observedThroughLine: 1,
        }),
      ),
    ).toBeNull();
  });

  it.each([
    {
      name: "status code above u16",
      entry: entry({ statusCode: 65_536 }),
    },
    {
      name: "Win32 status above u32",
      entry: entry({ win32Status: 4_294_967_296 }),
    },
    {
      name: "error span beyond the message",
      entry: entry({
        message: "short",
        errorCodeSpans: [
          {
            start: 0,
            end: 6,
            codeHex: "0x0",
            codeDecimal: "0",
            description: "success",
            category: "Win32",
          },
        ],
      }),
    },
  ])("rejects a LogEntry $name", ({ entry: invalidEntry }) => {
    expect(
      parseTailPayload(
        payload({
          entries: [invalidEntry],
          observedThroughLine: 1,
        }),
      ),
    ).toBeNull();
  });
});
