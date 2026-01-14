# MAC1 Debugging Guide

## Current Status

The server is rejecting the client's MAC1 authentication tag. The debug output shows they're calculating completely different MAC1 values.

## What is MAC1?

MAC1 is a pre-handshake authentication tag that:
1. Protects against DoS attacks
2. Is computed as HMAC-BLAKE2s over the first 116 bytes of the initiation message
3. Uses a key derived from the server's public key: `MAC1Key = BLAKE2s(LabelMAC1 || ServerPublicKey)`

## Message Structure

```
Offset  Size  Field
------  ----  -----
0       1     Type (0x01 for Initiation)
1       3     Reserved (zeros)
4       4     SenderIndex
8       32    Ephemeral Public Key
40      48    EncryptedStatic (32 bytes key + 16 bytes tag)
88      28    EncryptedTimestamp (12 bytes timestamp + 16 bytes tag)
116     16    MAC1
132     16    MAC2
```

MAC1 is computed over bytes 0-115 (the "MAC1Data").

## Debug Output Analysis

### Server Output (from your test):
```
[DEBUG] MAC1 Verification (Server):
  Local Static (pub): eTSIoGvoDYRGkB78uGrWZBPehOvoh18QAaqMcPlcHGk=
  MAC1 Key: 30cc430da3b3365d651c40105afc8f7fd263868b0e2101d2e89139f6393583e8
  Received MAC1: 63cf2c73a77bff60dab581731fb39cd4
  Expected MAC1: d22b8e247749ab1720f7f7a65a5557bf60f9ca58562d5879b2b41b1ace9db51b
  Ephemeral: e4e17cc5c9025739be888108e0b76736649421bc78c5ba0e733c86c1720ad55b
  SenderIndex: 478655144
  EncryptedStatic: fbd1c3e722411fd85edc47130694ad0b27acf066f0515d195e958bd3f8053efbe793ca97bf842d6d2e1ae189932b48b3
  EncryptedTimestamp: 0531381e7ceb36ffbd470f801dfee6d3dcfe282d37e61c7c8cd1ce8e
  MAC1Data (first 32 bytes): 01000000a8b2871ce4e17cc5c9025739be888108e0b76736649421bc78c5ba0e
```

Breaking down MAC1Data:
- `01` = MessageTypeInitiation ✓
- `000000` = Reserved bytes (zeros) ✓
- `a8b2871c` = SenderIndex (478655144 in little-endian) ✓
- `e4e17cc5...` = Start of Ephemeral key ✓

## What to Check

Run the updated binaries and compare these values:

1. **Server Public Key Match**
   - Client sends initiation to server
   - Server's local key should match the key the client is using
   - Both should show same public key in base64

2. **MAC1 Key Match**
   - Both derive from: `BLAKE2s(LabelMAC1 + ServerPublicKey)`
   - Should be identical on client and server
   - If different: server public key mismatch

3. **Message Data Match**
   - First 32 bytes of MAC1Data should be identical
   - If different: message corruption or different ephemeral key

4. **HMAC Result**
   - Given same MAC1Key and MAC1Data
   - Should produce same HMAC result
   - If different: HMAC implementation issue

## Testing Steps

### Terminal 1 (Server):
```bash
./noctwg-server-linux --port 51820 --private-key "yL+0aSHTNU5nc/7EFnhBcZIThAZM8iTcHEbozoVuGXg=" 2>&1 | tee server_debug.log
```

### Terminal 2 (Client - Windows):
```powershell
.\noctwg-client.exe 2>&1 | tee-object client_debug.log
```

Then connect via GUI to `localhost:8081` and click "Connect".

## Analysis Checklist

After running both and connecting, check:

```
☐ Server public key matches between client and server logs
☐ MAC1 Key is identical on both sides
☐ MAC1Data first 32 bytes match
☐ Client logs "Generated MAC1"
☐ Server logs "Expected MAC1"
☐ Compare Generated vs Expected hex values byte-by-byte
☐ If different at specific positions, check what data is at that offset
```

## Expected Success Output

When it works:
```
[DEBUG] MAC1 Verification (Server):
  ...
  Received MAC1: XXXXX
  Expected MAC1: XXXXX  <- Should match Received
  ...
  [DEBUG] MAC1 verification SUCCESS!
```

## Possible Root Causes

### 1. Wrong Server Public Key on Client
**Symptom**: Different MAC1 Keys on client vs server
**Fix**: Verify client is configured with correct server public key

### 2. Message Corruption in Transit
**Symptom**: MAC1Data first 32 bytes don't match
**Fix**: Check network path (UDP packets may be corrupted)

### 3. Different Ephemeral Keys
**Symptom**: Ephemeral value is different
**Fix**: Should not happen with same message - network issue

### 4. SenderIndex Truncation
**Symptom**: SenderIndex shows as different value
**Fix**: Check binary.LittleEndian encoding

### 5. EncryptedStatic/Timestamp Corruption  
**Symptom**: Those fields don't match between client TX and server RX
**Fix**: Network packet corruption or MTU issue

## Next Steps

1. Copy updated binaries to server and client
2. Run test with debug logging enabled
3. Compare the byte-by-byte output
4. Report which values match and which don't
5. We can then identify the exact point of divergence
