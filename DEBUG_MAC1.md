# MAC1 Debug Logging Guide

## Overview
Added comprehensive debug logging to both client and server to diagnose MAC1 verification failures.

## Client-Side Logging (CreateInitiation)
When the client creates a connection message, it logs:
- **Remote Static (pub)**: Server's public key
- **MAC1 Key**: Derived key using BLAKE2s HMAC of server pubkey
- **Generated MAC1**: The computed 16-byte authentication tag
- **Ephemeral**: Client's ephemeral public key
- **SenderIndex**: Connection index

## Server-Side Logging (ConsumeInitiation)
When the server receives a connection message, it logs:
- **Local Static (pub)**: Server's own public key
- **MAC1 Key**: Derived key using BLAKE2s HMAC of its own pubkey
- **Received MAC1**: What the client sent
- **Expected MAC1**: What the server calculated
- **Ephemeral**: Client's ephemeral key
- **SenderIndex**: Connection index
- **EncryptedStatic**: Encrypted client public key
- **EncryptedTimestamp**: Encrypted timestamp
- **MAC1Data (first 32 bytes)**: Raw message bytes used for HMAC

## Testing Steps

### 1. Start Server with Debug Output
```bash
./noctwg-server-linux --port 51820 --private-key "yL+0aSHTNU5nc/7EFnhBcZIThAZM8iTcHEbozoVuGXg=" 2>&1 | tee server.log
```

### 2. Run Client in Another Terminal
```bash
# Windows PowerShell
.\noctwg-client.exe
```

### 3. Connect via GUI or API
Open browser to `http://localhost:8081` and click "Connect" or:
```bash
curl -X POST http://localhost:8081/api/connect \
  -H "Content-Type: application/json" \
  -d '{"server_addr":"YOUR_SERVER_IP:51820","server_public_key":"base64_encoded_key"}'
```

## Comparing Debug Output

When comparing client vs server logs, verify:

1. **MAC1 Keys Match**
   - Client: MAC1 Key derived from `server_public_key`
   - Server: MAC1 Key derived from its own `local_public_key`
   - These MUST be the same (same key for both)

2. **Ephemeral Keys Match**
   - Client sends: `Ephemeral`
   - Server receives: `Ephemeral`
   - These MUST be identical (in hex)

3. **SenderIndex Matches**
   - Client: `SenderIndex = X`
   - Server: `SenderIndex = X`
   - These MUST be the same

4. **EncryptedStatic Matches**
   - Client sends encrypted form of its static key
   - Server receives the same `EncryptedStatic` bytes
   - Must match exactly

5. **EncryptedTimestamp Matches**
   - Client sends encrypted timestamp
   - Server receives the same `EncryptedTimestamp` bytes
   - Must match exactly

6. **Generated vs Received MAC1**
   - Server: `Received MAC1` should equal `Expected MAC1`
   - If not, the issue is in:
     - Different MAC1 keys being used
     - Different ephemeral keys
     - Different SenderIndex
     - Message corruption

## Common Issues

### Issue 1: MAC1 Keys Don't Match
**Cause**: Different public keys being used
**Check**: Verify both sides have the correct server public key
**Client should use**: Server's public key (from server's --private-key)
**Server automatically uses**: Its own public key from --private-key

### Issue 2: Ephemeral Keys Don't Match
**Cause**: Client ephemeral key generation issue or message corruption
**Check**: Verify network connectivity
**Solution**: Ensure message reaches server intact

### Issue 3: SenderIndex Different
**Cause**: Multiple concurrent attempts or timing issue
**Check**: Clear old connections before testing
**Solution**: Ensure only one client connects at a time

### Issue 4: EncryptedStatic/Timestamp Don't Match
**Cause**: Cipher synchronization issue
**Check**: Verify chain key derivation
**Solution**: May indicate issue in handshake key mixing

### Issue 5: Received ≠ Expected MAC1 but Keys/Ephemeral Match
**Cause**: HMAC computation differs or message corruption
**Check**: Verify MAC1 data (first 32 bytes) matches
**Solution**: Issue in MAC1 computation algorithm or message format

## Debug Log Example

```
[DEBUG] MAC1 Creation (Client):
  Remote Static (pub): e7c...xyz (base64)
  MAC1 Key: ab12cd34...
  Generated MAC1: 1234567890abcdef1234567890abcdef
  Ephemeral: fedcba0987654321fedcba0987654321
  SenderIndex: 1

[DEBUG] MAC1 Verification (Server):
  Local Static (pub): e7c...xyz (base64)
  MAC1 Key: ab12cd34...
  Received MAC1: 1234567890abcdef1234567890abcdef
  Expected MAC1: 1234567890abcdef1234567890abcdef
  Ephemeral: fedcba0987654321fedcba0987654321
  SenderIndex: 1
  EncryptedStatic: ...
  EncryptedTimestamp: ...
  MAC1Data (first 32 bytes): ...

[DEBUG] MAC1 verification SUCCESS!
```

## What to Report

When you see the MAC1 issue, please provide:
1. Complete client debug output (MAC1 Creation)
2. Complete server debug output (MAC1 Verification)
3. Which values match and which don't
4. Any error messages that follow

This will help identify the exact point of divergence between client and server.
