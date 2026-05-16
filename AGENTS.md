# AGENTS.md — iPhone_NFC Project Knowledge Base

## Project Purpose

Identify which NFC protocol a campus card (校园卡) uses, on iPhone 16 Pro Max (iOS 26.5). The card's protocol is unknown — the entire project exists to discover it. All code should prioritize fast validation over production polish.

## Architecture Decision Records

### ADR-001: Use NFCTagReaderSession (not NFCNDEFReaderSession)

**Context**: Two session types exist. NFCNDEFReaderSession only reads NDEF messages — limited, no raw protocol access. NFCTagReaderSession provides raw tag access including APDU commands.

**Decision**: Use `NFCTagReaderSession` exclusively. Campus cards likely use ISO 7816 (smart card protocol) which requires APDU-level communication. NDEF-only session cannot identify or communicate with the card at protocol level.

**Consequence**: Requires additional entitlement (`com.apple.developer.nfc.readersession.formats`) and AID list in Info.plist. More setup friction, but the only path that works.

### ADR-002: Combine all PollingOptions for initial detection

**Context**: Campus card protocol unknown. Could be ISO 14443 (MIFARE/ISO 7816), ISO 15693, or FeliCa.

**Decision**: First scan uses all three polling options simultaneously: `[.iso14443, .iso15693, .iso18092]`. After identifying the protocol, narrow to the specific option for focused testing.

**Consequence**: Initial session detects maximum tag types. Once protocol identified, optimize by reducing polling options to just the match.

## Critical Setup Requirements (CRASH-CAUSING if missed)

### Entitlements — app WILL NOT launch or session WILL fail

These are NOT optional. Missing any = crash, silent failure, or signing error.

1. **Near Field Communication Tag Reading** capability
   - Add via Xcode: Target → Signing & Capabilities → "+ Capability" → "Near Field Communication Tag Reading"
   - This auto-updates App ID and generates entitlements

2. **Tag Reader Session Formats Entitlement** (`com.apple.developer.nfc.readersession.formats`)
   - Required for `NFCTagReaderSession`
   - Value must include `NDEF` and `TAG` (both, not just one)
   - Without `TAG` format: session starts but `didDetect` delegate never fires for non-NDEF tags

3. **ISO 7816 Select Identifiers** (`com.apple.developer.nfc.readersession.iso7816.select-identifiers`)
   - **Array of AID strings** in Info.plist — hex strings like `A000000151000000`
   - iOS uses this list to auto-SELECT AID before handing tag to your app
   - **If your card's AID is NOT in this list**: `NFCTagReaderSession` may not detect the tag at all, or tag connects but APDU commands fail
   - For campus card discovery: include common AIDs AND an empty string `""` as catch-all (allows any AID selection)
   - Example Info.plist entry:
     ```xml
     <key>com.apple.developer.nfc.readersession.iso7816.select-identifiers</key>
     <array>
       <string></string>  <!-- catch-all: accept any AID -->
     </array>
     ```

4. **NFCReaderUsageDescription** in Info.plist
   - **MISSING = app exits/crashes immediately** when NFC session starts
   - Required by iOS privacy framework
   - Example: `<string>Need NFC to read your campus card</string>`

### Known Signing Pitfall

When adding ISO 7816 entitlements, Xcode signing may fail with:
> "Provisioning profile doesn't match entitlements file value for com.apple.developer.nfc.readersession.formats"

**Fix**: Go to Apple Developer Portal → Certificates, Identifiers & Profiles → your App ID → enable NFC Tag Reading capability → regenerate provisioning profile. The portal must have the same capabilities as your local entitlements file.

## iPhone vs Android NFC Limitations (MUST KNOW)

| Feature | iPhone (CoreNFC) | Android |
|---|---|---|
| MIFARE Classic | ❌ **NOT supported** — no Crypto-1 auth | ✅ Full support |
| Card Emulation (HCE) | ❌ No (only via Apple Pay SE) | ✅ Full HCE API |
| Background tag reading | NDEF-only (iOS 14+) | Full protocol access |
| ISO 7816 APDU | ✅ Since iOS 13 | ✅ IsoDep API |
| ISO 15693 | ✅ Since iOS 14 | ✅ NfcV API |
| FeliCa | ✅ Since iOS 13 (Japan focus) | ✅ NfcF API |
| MIFARE DESFire | ✅ Via ISO 7816 APDU | ✅ Via MIFARE & IsoDep |
| Simulator testing | ❌ **NO** — must use physical iPhone | ✅ Via ACR122U emulation |
| NFC-B (ISO 14443-4B) | ⚠️ Limited — some tags detected by NDEF session but NOT by TagReaderSession | ✅ Full support |

**Critical implication**: If campus card uses MIFARE Classic, **iPhone cannot read it at all**. Must verify card type early. Consider keeping an Android device as backup for MIFARE Classic detection.

**No simulator**: CoreNFC does NOT work in iOS Simulator. Every test requires a physical NFC-capable iPhone (7+). Plan testing around this constraint.

## Protocol Detection Strategy

### Step 1: Broad Scan (all protocols)

```swift
let session = NFCTagReaderSession(
    pollingOption: [.iso14443, .iso15693, .iso18092],
    delegate: self
)
session.alertMessage = "Hold campus card near iPhone top"
session.begin()
```

### Step 2: In `didDetect tags`, identify protocol type

```swift
func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
    guard let tag = tags.first else { return }
    
    switch tag {
    case .iso7816(let isoTag):
        // ISO 7816 compatible (most campus cards, DESFire, etc.)
        // Access: isoTag.identifier, isoTag.initialSelectedAID
        // Send APDUs: isoTag.sendCommand(apdu: ...)
        
    case .miFare(let miFareTag):
        // MIFARE (DESFire, Ultralight — NOT Classic)
        // Access: miFareTag.identifier, miFareTag.mifareFamily
        // Send: miFareTag.sendMiFareCommand(commandPacket: ...)
        
    case .iso15693(let isoTag):
        // ISO 15693 (long-range tags, some access cards)
        // Access: isoTag.identifier
        
    case .felica(let felicaTag):
        // FeliCa (Japanese transit/pay cards, unlikely for Chinese campus)
        // Access: felicaTag.currentSystemCode, felicaTag.currentIDm
        
    @unknown default:
        // Unknown tag type
    }
}
```

### Step 3: Read card metadata

Once connected, immediately read:
- **identifier** (UID — card serial number, hex bytes)
- **initialSelectedAID** (for ISO 7816 — what applet iOS auto-selected)
- **historicalBytes** / **applicationData** (ISO 7816 ATR-like info)

These alone often reveal the card type. Log them all.

### Step 4: Probe with APDU commands (ISO 7816)

```swift
// SELECT Master File (discover file structure)
let selectMF = NFCISO7816APDU(
    instructionClass: 0x00,
    instructionCode: 0xA4,
    p1Parameter: 0x00,
    p2Parameter: 0x00,
    data: Data([0x3F, 0x00]),  // MF ID
    expectedResponseLength: 256
)

isoTag.sendCommand(apdu: selectMF) { data, sw1, sw2, error in
    // sw1=0x90, sw2=0x00 → success
    // sw1=0x6A → file not found / wrong parameters
    // data → response data (file structure info)
}
```

## Common Campus Card NFC Types (Chinese Universities)

| Card Type | Protocol | iPhone Detectable | Notes |
|---|---|---|---|
| MIFARE Classic 1K/4K | ISO 14443-3A (Crypto-1) | ❌ NO | Most common campus card in China. **Dead end on iPhone.** |
| MIFARE DESFire EV1/EV2/EV3 | ISO 14443-4 (ISO 7816) | ✅ YES | APDU-based, requires authentication keys |
| MIFARE Ultralight / NTAG | ISO 14443-3A | ✅ YES | Simple memory cards, less secure |
| ISO 7816 smart card | ISO 14443-4 | ✅ YES | Java Card / MULTOS based |
| ISO 15693 card | ISO 15693 | ✅ YES | Long-range, less common for campus |
| FeliCa | JIS X 6319-4 | ✅ YES | Japan-focused, very unlikely in China |

**Most likely scenario**: Chinese campus cards are MIFARE Classic → iPhone CANNOT read encrypted sectors. Can only read UID and non-encrypted sector 0. This is the primary risk for this project.

## Session Lifecycle Rules (MUST follow)

1. **Session is single-shot**: After `session.begin()`, one tag detection cycle. Once you invalidate or the user dismisses the scan sheet, session ends permanently. No restart — must create new session.

2. **60-second timeout**: If no tag detected within 60 seconds, session auto-invalidates. Show `alertMessage` with clear instructions.

3. **Connect before communicate**: MUST call `session.connect(to: tag)` before sending any commands. Failure to connect → all commands fail with "tag is not connected" error.

4. **One tag at a time**: iOS detects tags, but `didDetect` may fire multiple times. Handle the FIRST tag, then call `session.invalidate()` to end. Or call `session.restartPolling()` to continue scanning.

5. **No concurrent sessions**: Only ONE active NFCReaderSession at a time. Starting a second while first is active → error.

6. **Session invalidated unexpectedly**: This error occurs if you try to start a new session too quickly after the previous one ended. iOS enforces a cooldown. Wait ~1 second before creating new session.

7. **Alert message required**: `session.alertMessage = "..."` MUST be set before `session.begin()`. Empty alert → confusing UX.

## Entitlements Template

### Info.plist additions

```xml
<!-- CRITICAL: missing this = crash -->
<key>NFCReaderUsageDescription</key>
<string>需要读取校园卡NFC信息以识别卡片协议类型</string>

<!-- ISO 7816 AID list — empty string = catch-all -->
<key>com.apple.developer.nfc.readersession.iso7816.select-identifiers</key>
<array>
    <string></string>
</array>
```

### Entitlements file (.entitlements)

```xml
<key>com.apple.developer.nfc.readersession.formats</key>
<array>
    <string>NDEF</string>
    <string>TAG</string>
</array>
```

## Debugging Checklist

When NFC session fails, check in this order:

1. ✅ `NFCNDEFReaderSession.readingAvailable` returns true? (device has NFC hardware)
2. ✅ `NFCReaderUsageDescription` in Info.plist? (missing = crash)
3. ✅ Entitlements file has both `NDEF` and `TAG` under `readersession.formats`?
4. ✅ ISO 7816 `select-identifiers` list includes empty string or target AID?
5. ✅ Provisioning profile regenerated after adding entitlements? (signing error otherwise)
6. ✅ Physical iPhone device, not Simulator? (Simulator = no NFC)
7. ✅ No phone case blocking NFC antenna? (top back of iPhone)
8. ✅ Card physically close to iPhone NFC antenna zone? (top center, back side)
9. ✅ Not starting session too quickly after previous one? (1-second cooldown)
10. ✅ `alertMessage` set before `session.begin()`?

## Key Error Codes

| NFCError Code | Meaning | Fix |
|---|---|---|
| 104 | Tag is not connected | Call `session.connect(to:)` first |
| 200 | Session invalidated unexpectedly | Wait before new session, don't dismiss scan sheet |
| 300 | Reader session invalidation — user canceled | User tapped cancel on scan sheet |
| 401 | Feature not supported | Check device NFC capability with `.readingAvailable` |

## Testing Workflow

### Prerequisites
- Physical iPhone 7+ (iPhone 16 Pro Max preferred)
- Apple Developer account with NFC capability enabled on App ID
- Campus card physically available
- Xcode project with all entitlements configured

### Test Matrix (run sequentially)

| Test # | PollingOption | Expected Result | What to Log |
|---|---|---|---|
| 1 | `[.iso14443, .iso15693, .iso18092]` | Detect card + identify type | `tag.type`, `identifier` (hex), AID (if ISO 7816) |
| 2 | `[.iso14443]` only | If test 1 found ISO 7816/MIFARE | `initialSelectedAID`, `historicalBytes` |
| 3 | `[.iso15693]` only | If test 1 found ISO 15693 | `identifier`, `manufacturerCode`, `dsfID` |
| 4 | APDU: SELECT MF (3F00) | If ISO 7816 detected | Response data + SW1/SW2 status words |
| 5 | APDU: GET CHALLENGE | If ISO 7816 + want auth test | Random number from card (auth possible) |

### If MIFARE Classic Detected

**Stop. iPhone cannot read encrypted sectors.** Options:
- Use Android device with MIFARE Classic support
- Use external USB NFC reader (ACR122U) on Mac
- Read only UID from non-encrypted block 0
- Accept partial-read limitation and document it

## File Structure Convention

```
iPhone_NFC/
├── AGENTS.md              ← this file
├── README.md               ← project description (fix typo: iPone → iPhone)
├── iPhone_NFC.xcodeproj/   ← Xcode project
├── iPhone_NFC/             ← main app source
│   ├── AppDelegate.swift
│   ├── NFCScanner.swift    ← NFCTagReaderSession delegate + protocol detection
│   ├── APDUCommands.swift  ← ISO 7816 APDU command builder
│   ├── TagInfo.swift       ← detected tag metadata model
│   └── Info.plist          ← NFCReaderUsageDescription + AID list
├── iPhone_NFC.entitlements ← NFC entitlements
└── tests/                  ← unit tests for APDU command construction
```

## Swift Conventions for This Project

- **No SwiftUI required**: This is a utility/debug app. UIKit is simpler for NFC session lifecycle.
- **All NFC operations on main thread**: CoreNFC delegate callbacks arrive on main queue. Don't dispatch away.
- **Log everything**: Every tag detection, APDU response, error — log to console with hex formatting. This is a discovery project; data is the output.
- **Hex formatting helper**: Always format Data as hex string for logging. UID, AID, APDU data — all hex.
  ```swift
  extension Data {
      var hexString: String {
          map { String(format: "%02X", $0) }.joined()
      }
  }
  ```
- **Don't abstract prematurely**: First version should be a flat NFCScanner that logs everything. Refactor into clean architecture AFTER protocol is identified.

## References

- Apple CoreNFC docs: https://developer.apple.com/documentation/corenfc
- NFCFYI iOS guide: https://nfcfyi.com/guide/ios-core-nfc-programming/
- NFCPassportReader (real ISO 7816 APDU usage): https://github.com/AndyQ/NFCPassportReader
- CoreExtendedNFC (transport abstraction): https://github.com/Lakr233/CoreExtendedNFC
- flutter-nfc-manager (cross-platform NFC patterns): https://github.com/okadan/flutter-nfc-manager