--[[
PASETO V2 Test Vectors
https://github.com/paseto-standard/test-vectors
commit c2c4aac085a9036c94f24f65c73777d512d9b131

ISC License

Copyright (c) 2021
Paragon Initiative Enterprises <security at paragonie dot com>

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
]]

-- 2-E-1
assert(paseto.v2_local_encrypt("{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}", "k2.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8", "", DecodeHex("000000000000000000000000000000000000000000000000")) == "v2.local.97TTOvgwIxNGvV80XKiGZg_kD3tsXM_-qB4dZGHOeN1cTkgQ4PnW8888l802W8d9AvEGnoNBY3BnqHORy8a5cC8aKpbA0En8XELw2yDk2f1sVODyfnDbi6rEGMY3pSfCbLWMM2oHJxvlEl2XbQ", "2-E-1: Encryption")
assert(paseto.v2_local_decrypt("v2.local.97TTOvgwIxNGvV80XKiGZg_kD3tsXM_-qB4dZGHOeN1cTkgQ4PnW8888l802W8d9AvEGnoNBY3BnqHORy8a5cC8aKpbA0En8XELw2yDk2f1sVODyfnDbi6rEGMY3pSfCbLWMM2oHJxvlEl2XbQ", "k2.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8", "") == "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}", "2-E-1: Decryption")
-- 2-E-2
assert(paseto.v2_local_encrypt("{\"data\":\"this is a secret message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}", "k2.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8", "", DecodeHex("000000000000000000000000000000000000000000000000")) == "v2.local.CH50H-HM5tzdK4kOmQ8KbIvrzJfjYUGuu5Vy9ARSFHy9owVDMYg3-8rwtJZQjN9ABHb2njzFkvpr5cOYuRyt7CRXnHt42L5yZ7siD-4l-FoNsC7J2OlvLlIwlG06mzQVunrFNb7Z3_CHM0PK5w", "2-E-2: Encryption")
assert(paseto.v2_local_decrypt("v2.local.CH50H-HM5tzdK4kOmQ8KbIvrzJfjYUGuu5Vy9ARSFHy9owVDMYg3-8rwtJZQjN9ABHb2njzFkvpr5cOYuRyt7CRXnHt42L5yZ7siD-4l-FoNsC7J2OlvLlIwlG06mzQVunrFNb7Z3_CHM0PK5w", "k2.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8", "") == "{\"data\":\"this is a secret message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}", "2-E-2: Decryption")
-- 2-E-3
assert(paseto.v2_local_encrypt("{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}", "k2.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8", "", DecodeHex("45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b")) == "v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-O5xRBN076fSDPo5xUCPpBA", "2-E-3: Encryption")
assert(paseto.v2_local_decrypt("v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-O5xRBN076fSDPo5xUCPpBA", "k2.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8", "") == "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}", "2-E-3: Decryption")
-- 2-E-4
assert(paseto.v2_local_encrypt("{\"data\":\"this is a secret message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}", "k2.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8", "", DecodeHex("45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b")) == "v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DPbIxtjGvNRAwsLK7LcV8oQ", "2-E-4: Encryption")
assert(paseto.v2_local_decrypt("v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DPbIxtjGvNRAwsLK7LcV8oQ", "k2.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8", "") == "{\"data\":\"this is a secret message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}", "2-E-4: Decryption")
-- 2-E-5
assert(paseto.v2_local_encrypt("{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}", "k2.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8", "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}", DecodeHex("45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b")) == "v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-zSLIrxZqOLwcFLYbVK1SrQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9", "2-E-5: Encryption")
assert(paseto.v2_local_decrypt("v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-zSLIrxZqOLwcFLYbVK1SrQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9", "k2.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8", "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}") == "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}", "2-E-5: Decryption")
-- 2-E-6
assert(paseto.v2_local_encrypt("{\"data\":\"this is a secret message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}", "k2.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8", "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}", DecodeHex("45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b")) == "v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DnMXKdHn_Smp6L_NfaEnZ-A.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9", "2-E-6: Encryption")
assert(paseto.v2_local_decrypt("v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DnMXKdHn_Smp6L_NfaEnZ-A.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9", "k2.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8", "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}") == "{\"data\":\"this is a secret message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}", "2-E-6: Decryption")
-- 2-E-7
assert(paseto.v2_local_encrypt("{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}", "k2.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8", "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}", DecodeHex("45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b")) == "v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-zSLIrxZqOLwcFLYbVK1SrQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9", "2-E-7: Encryption")
assert(paseto.v2_local_decrypt("v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-zSLIrxZqOLwcFLYbVK1SrQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9", "k2.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8", "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}") == "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}", "2-E-7: Decryption")
-- 2-E-8
assert(paseto.v2_local_encrypt("{\"data\":\"this is a secret message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}", "k2.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8", "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}", DecodeHex("45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b")) == "v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DnMXKdHn_Smp6L_NfaEnZ-A.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9", "2-E-8: Encryption")
assert(paseto.v2_local_decrypt("v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DnMXKdHn_Smp6L_NfaEnZ-A.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9", "k2.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8", "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}") == "{\"data\":\"this is a secret message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}", "2-E-8: Decryption")
-- 2-E-9
assert(paseto.v2_local_encrypt("{\"data\":\"this is a secret message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}", "k2.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8", "arbitrary-string-that-isn't-json", DecodeHex("45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b")) == "v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DoOJbyKBGPZG50XDZ6mbPtw.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24", "2-E-9: Encryption")
assert(paseto.v2_local_decrypt("v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DoOJbyKBGPZG50XDZ6mbPtw.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24", "k2.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8", "arbitrary-string-that-isn't-json") == "{\"data\":\"this is a secret message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}", "2-E-9: Decryption")
-- 2-S-1: skipped
-- 2-S-2: skipped
-- 2-S-3: skipped
-- 2-F-1: skipped
-- 2-F-2
assert(not paseto.v2_local_decrypt("v2.public.eyJpbnZhbGlkIjoidGhpcyBzaG91bGQgbmV2ZXIgZGVjb2RlIn1kgrdAMxcO3wFKXJrLa1cq-DB6V_b25KQ1hV_jpOS-uYBmsg8EMS4j6kl2g83iRsh73knLGr7Ik1AEOvUgyw0P.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9", "k2.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHaImKi4yNjo8", "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}"), "2-F-2: Expected failure")
-- 2-F-3
assert(not paseto.v2_local_decrypt("v1.local.vXWMCh8nxf_RMqrLREJVOWyu01yRzb-miB6mkG1zQ8LS4_W5nQdTOpexZq482ReJ0sv5uFfAWRGpJaONiMqFaAAo-dsbWG2vo63xUmwFGxHNhu9plfFav2SaGDERFGn7IQ20gNQl87eOLaxf2GDsWdfu5hrFaQ.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24", "k2.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHaImKi4yNjo8", "arbitrary-string-that-isn't-json"), "2-F-3: Expected failure")


local key = paseto.v2_local_keygen()
local token = paseto.v2_local_encrypt("foo", key, "plaintext-footer")

-- succeeds when footer is not given
assert(paseto.v2_local_decrypt(token, key))
-- and when footer is given
assert(paseto.v2_local_decrypt(token, key, "plaintext-footer"))
-- and fails when footer is not as expected
assert(not paseto.v2_local_decrypt(token, key, "modified-footer"))
