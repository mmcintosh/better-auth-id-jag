// SAML subject tokens (D-B26, D-B27): decoding (P3-S8, our half: the encoding; the XML hardening is
// better-auth-saml-idp's), the duck-typed capability, the `saml` option and the startup check.
import { betterAuth, type BetterAuthPlugin } from "better-auth";
import { jwt } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { IdJagRefusal } from "../../src/core";
import { assertionExchangeErrorCode, decodeSaml2SubjectToken, getSamlIdpExchange, idJagIssuer, type IdJagIssuerOptions, MAX_ASSERTION_BYTES, MAX_SAML2_TOKEN_LENGTH, resolveIssuerOptions } from "../../src/issuer";
import { BASE, FakeAssertionExchangeError, FakeSamlIdp, SECRET, samlToken, samlTokenStd } from "../support/issuer-host";

/** The refusal's audit detail, or "accepted". */
function outcome(token: string): string {
  try {
    decodeSaml2SubjectToken(token);
    return "accepted";
  } catch (e) {
    expect(e).toBeInstanceOf(IdJagRefusal);
    expect((e as IdJagRefusal).reason).toBe("invalid_subject_token");
    return (e as IdJagRefusal).detail ?? "";
  }
}

const XML = '<saml:Assertion ID="_a" Version="2.0">é ✓ 𝄞</saml:Assertion>';

describe("decodeSaml2SubjectToken (P3-S8)", () => {
  it("accepts base64url (unpadded or correctly padded) and padded standard base64, all to the same UTF-8 text", () => {
    const url = samlToken(XML);
    const std = samlTokenStd(XML);
    expect(url).not.toContain("=");
    expect(std).toMatch(/[+/=]/);
    const padded = url.padEnd(Math.ceil(url.length / 4) * 4, "=");
    for (const t of [url, padded, std]) expect(decodeSaml2SubjectToken(t)).toBe(XML);
    // A leading BOM is kept, not silently stripped: the SAML IdP's parser decides.
    expect(decodeSaml2SubjectToken(samlToken(`﻿${XML}`))).toBe(`﻿${XML}`);
  });

  it("refuses anything else: no alphabet mixing, whitespace, bad padding, truncation, stray bits or invalid UTF-8", () => {
    const std = samlTokenStd(XML);
    const url = samlToken(XML);
    expect(outcome("")).toBe("saml2: empty");
    expect(outcome(`${url} `)).toBe("saml2: not base64url or base64");
    expect(outcome(`${url.slice(0, 8)}\n${url.slice(8)}`)).toBe("saml2: not base64url or base64");
    expect(outcome(`${url}+-`)).toBe("saml2: not base64url or base64");
    expect(outcome(`a=b${url}`)).toBe("saml2: not base64url or base64");
    expect(outcome(`<saml:Assertion/>`)).toBe("saml2: not base64url or base64");
    // Standard base64 needs its padding; base64url doesn't.
    void std;
    // "+/8=" is 0xfb 0xff; without its "=" it is standard-alphabet base64 missing its padding.
    expect(btoa(String.fromCharCode(0xfb, 0xff))).toBe("+/8=");
    expect(outcome("+/8")).toBe("saml2: base64 without padding");
    expect(outcome("-_8")).toBe("saml2: not UTF-8");
    expect(outcome("QUJD=")).toBe("saml2: wrong padding");
    expect(outcome("QUI")).toBe("accepted");
    expect(outcome("QUI==")).toBe("saml2: wrong padding");
    expect(outcome("QUJDR")).toBe("saml2: truncated");
    expect(outcome("QUJDRQ==A")).toBe("saml2: not base64url or base64");
    expect(outcome("Q===")).toBe("saml2: not base64url or base64");
    // "QUJ" and "QUI" decode to "AB"; "QUJ" has stray low bits set.
    expect(outcome("QUJ")).toBe("saml2: not canonical");
    expect(outcome("QUJ=")).toBe("saml2: not canonical");
    // 0xff 0xfe 0xfd is not UTF-8; neither is an unpaired surrogate's encoding.
    expect(outcome(btoa(String.fromCharCode(0xff, 0xfe, 0xfd)))).toBe("saml2: not UTF-8");
    expect(outcome(btoa(String.fromCharCode(0xed, 0xa0, 0x80)))).toBe("saml2: not UTF-8");
  });

  it("caps at the SAML IdP's 65536 XML bytes: 87384 characters (padded base64 of 65536 bytes), and the decoded bytes too", () => {
    expect(MAX_ASSERTION_BYTES).toBe(65_536);
    expect(MAX_SAML2_TOKEN_LENGTH).toBe(87_384);
    // Exactly 65536 bytes, padded: accepted. One more byte: refused.
    const atCap = samlTokenStd("A".repeat(MAX_ASSERTION_BYTES));
    expect(atCap).toHaveLength(MAX_SAML2_TOKEN_LENGTH);
    expect(decodeSaml2SubjectToken(atCap)).toHaveLength(MAX_ASSERTION_BYTES);
    expect(decodeSaml2SubjectToken(samlToken("A".repeat(MAX_ASSERTION_BYTES)))).toHaveLength(MAX_ASSERTION_BYTES);
    expect(outcome(samlToken("A".repeat(MAX_ASSERTION_BYTES + 1)))).toBe(`saml2: longer than ${MAX_ASSERTION_BYTES} bytes`);
    // Multi-byte characters count as bytes, not characters.
    expect(outcome(samlToken("é".repeat(MAX_ASSERTION_BYTES / 2 + 1)))).toBe(`saml2: longer than ${MAX_ASSERTION_BYTES} bytes`);
    // 87384 unpadded characters decode to 65538 bytes: refused after decoding.
    expect(outcome("A".repeat(MAX_SAML2_TOKEN_LENGTH))).toBe(`saml2: longer than ${MAX_ASSERTION_BYTES} bytes`);
    // One character over the cap: refused before decoding.
    expect(outcome(`${atCap}A`)).toBe(`saml2: longer than ${MAX_SAML2_TOKEN_LENGTH} characters`);
    expect(outcome("!".repeat(MAX_SAML2_TOKEN_LENGTH + 1))).toBe(`saml2: longer than ${MAX_SAML2_TOKEN_LENGTH} characters`);
  });

  it("fuzz: any string either decodes or is refused as invalid_subject_token, never anything else", () => {
    const b64ish = fc.string({ unit: fc.constantFrom(..."ABCabc019+/-_= \n%".split("")), maxLength: 64 });
    fc.assert(
      fc.property(fc.oneof(fc.string({ maxLength: 80 }), b64ish), (s) => {
        const o = outcome(s);
        if (o === "accepted") expect(typeof decodeSaml2SubjectToken(s)).toBe("string");
      }),
      { numRuns: 3000 },
    );
  });

  it("fuzz: any text round-trips through either encoding", () => {
    fc.assert(
      fc.property(fc.string({ unit: "grapheme", minLength: 1, maxLength: 60 }), (s) => {
        expect(decodeSaml2SubjectToken(samlToken(s))).toBe(s);
        expect(decodeSaml2SubjectToken(samlTokenStd(s))).toBe(s);
      }),
      { numRuns: 1000 },
    );
  });
});

describe("the SAML IdP's capability, duck-typed", () => {
  it("getSamlIdpExchange: version 1 with a verifyIssuedAssertion function, nothing else", () => {
    const verifyIssuedAssertion = async () => ({});
    expect(getSamlIdpExchange({ context: { samlIdpExchange: { version: 1, verifyIssuedAssertion } } })?.version).toBe(1);
    for (const x of [undefined, null, 1, "x", {}, { version: 2, verifyIssuedAssertion }, { version: "1", verifyIssuedAssertion }, { version: 1 }, { version: 1, verifyIssuedAssertion: "f" }])
      expect(getSamlIdpExchange({ context: { samlIdpExchange: x } }), JSON.stringify(x)).toBeUndefined();
    expect(getSamlIdpExchange({ context: undefined })).toBeUndefined();
  });

  it("assertionExchangeErrorCode: only the nine codes, on an object named AssertionExchangeError (any module copy: no instanceof)", () => {
    for (const code of ["MALFORMED", "NOT_OURS", "BAD_SIGNATURE", "NOT_YET_VALID", "EXPIRED", "NOT_EXCHANGEABLE", "WRONG_CLIENT", "ALREADY_EXCHANGED", "ACCOUNT_INACTIVE"]) {
      expect(assertionExchangeErrorCode(new FakeAssertionExchangeError(code))).toBe(code);
      // Another copy's class: same name and code, a different prototype.
      expect(assertionExchangeErrorCode({ name: "AssertionExchangeError", code, message: "x" })).toBe(code);
    }
    const coded = Object.assign(new Error("EXPIRED"), { code: "EXPIRED" });
    for (const e of [new Error("EXPIRED"), coded, { code: "EXPIRED" }, new FakeAssertionExchangeError("expired"), new FakeAssertionExchangeError("OTHER"), { name: "AssertionExchangeError", code: 1 }, null, undefined, "EXPIRED"])
      expect(assertionExchangeErrorCode(e)).toBeUndefined();
  });
});

const provider = () => oauthProvider({ loginPage: "/login", consentPage: "/consent" }) as unknown as BetterAuthPlugin;
const issuer = (o: IdJagIssuerOptions) => idJagIssuer({ authorize: () => ({ decision: "deny" }), ...o }) as unknown as BetterAuthPlugin;
async function boot(plugins: BetterAuthPlugin[]) {
  const auth = betterAuth({ baseURL: BASE, secret: SECRET, telemetry: { enabled: false }, plugins });
  return auth.$context.then(
    () => "ok",
    (e: Error) => e.message,
  );
}

describe("the saml option: startup", () => {
  it("any saml option needs the SAML IdP's capability (version 1) on the context, installed before the issuer", async () => {
    const idp = new FakeSamlIdp();
    for (const saml of [{ subjectTokens: true }, { refreshTokens: {} }, { subjectTokens: false, refreshTokens: false as const }, {}]) {
      expect(await boot([jwt(), provider(), issuer({ saml })]), JSON.stringify(saml)).toMatch(/samlIdpExchange \(version 1\) is missing/);
      expect(await boot([jwt(), provider(), idp.plugin(), issuer({ saml })])).toBe("ok");
    }
    // After the issuer: its init hasn't run yet when ours checks.
    expect(await boot([jwt(), provider(), issuer({ saml: { subjectTokens: true } }), idp.plugin()])).toMatch(/installed before idJagIssuer\(\)/);
    // Another version, or no function.
    const v2 = new FakeSamlIdp();
    v2.capability = { ...v2.capability, version: 2 };
    expect(await boot([jwt(), provider(), v2.plugin(), issuer({ saml: { subjectTokens: true } })])).toMatch(/is missing/);
    const noFn = new FakeSamlIdp();
    noFn.capability = { version: 1 };
    expect(await boot([jwt(), provider(), noFn.plugin(), issuer({ saml: { refreshTokens: {} } })])).toMatch(/is missing/);
    // Without saml, the capability is neither needed nor used.
    expect(await boot([jwt(), provider(), issuer({})])).toBe("ok");
  });

  it("validates the option strictly", () => {
    for (const bad of [
      { saml: { subjectToken: true } },
      { saml: { subjectTokens: "yes" } },
      { saml: { refreshTokens: true } },
      { saml: { refreshTokens: { scope: ["openid", "offline_access"] } } },
      { saml: { refreshTokens: { scopes: ["openid"] } } },
      { saml: { refreshTokens: { scopes: ["offline_access", "profile"] } } },
      { saml: { refreshTokens: { scopes: ["openid", "offline_access", "two words"] } } },
      { saml: { refreshTokens: { scopes: ["openid", "offline_access", ""] } } },
      { saml: { refreshTokens: { scopes: ["openid", "offline_access", 'q"'] } } },
      { saml: true },
      { events: { onRefreshIssue: () => {} } },
    ])
      expect(() => resolveIssuerOptions(bad as never), JSON.stringify(bad)).toThrow(/idJagIssuer: invalid options/);
    expect(resolveIssuerOptions({})).toMatchObject({ samlSubjectTokens: false, samlRefreshScopes: undefined });
    expect(resolveIssuerOptions({ saml: { subjectTokens: true, refreshTokens: false } })).toMatchObject({ samlSubjectTokens: true, samlRefreshScopes: undefined });
    expect(resolveIssuerOptions({ saml: { refreshTokens: {} } })).toMatchObject({ samlSubjectTokens: false, samlRefreshScopes: ["openid", "offline_access", "profile", "email"] });
    expect(resolveIssuerOptions({ saml: { refreshTokens: { scopes: ["offline_access", "openid", "openid"] } } }).samlRefreshScopes).toEqual(["offline_access", "openid"]);
    expect(resolveIssuerOptions({ events: { onRefreshIssued: () => {} } }).events?.onRefreshIssued).toBeTypeOf("function");
  });
});
