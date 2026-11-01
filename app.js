'use strict';

/*
 * Mansaa Smart Shine Serverless Web Bluetooth Controller
 *
 * Security Architecture Notes:
 * - Purely client-side Web Bluetooth controller operating over HTTPS / localhost PWA.
 * - TODO(security): User authentication, OAuth, MFA, session cookies, and CSRF tokens
 *   are intentionally omitted in serverless mode because there is no remote backend,
 *   multi-tenant user data, or account state; hardware access is gated by physical BLE
 *   proximity and browser-enforced Web Bluetooth user-gesture pairing permissions.
 */

// BLE GATT UUIDs (Bluetooth SIG 128-bit Base)
const SERVICE_LED_UUID = '0000ffb0-0000-1000-8000-00805f9b34fb';
const CHAR_MODE_UUID = '0000ffb1-0000-1000-8000-00805f9b34fb';
const CHAR_DATA_UUID = '0000ffb2-0000-1000-8000-00805f9b34fb';
const CHAR_TIME_UUID = '0000ffb3-0000-1000-8000-00805f9b34fb';
const CHAR_NAME_UUID = '0000ffb7-0000-1000-8000-00805f9b34fb';
const CHAR_R_ARRAY_UUID = '0000ffb9-0000-1000-8000-00805f9b34fb';
const CHAR_G_ARRAY_UUID = '0000ffba-0000-1000-8000-00805f9b34fb';
const CHAR_B_ARRAY_UUID = '0000ffbb-0000-1000-8000-00805f9b34fb';
const CHAR_LAST_SAVED_UUID = '0000ffbe-0000-1000-8000-00805f9b34fb';

const SERVICE_AES_UUID = '0000fc60-0000-1000-8000-00805f9b34fb';
const CHAR_AES_CHECK_UUID = '0000fc64-0000-1000-8000-00805f9b34fb';
const SERVICE_DEV_INFO_UUID = '0000180a-0000-1000-8000-00805f9b34fb';

// Default Manufacturer ID observed on Mansaa bulb MAN_V11400009 (scanRecord[9..10] LE)
const DEFAULT_MANSAA_COMPANY_ID = 0xde19;
const DEFAULT_MANSAA_COMPANY_ID_BE = 0x19de;

// Hardcoded "CheckAes" ASCII key from decompiled BLEDevice.java / HomeActivity.java
const CRC_PASSWORD = [67, 104, 101, 99, 107, 65, 101, 115];

// All 12 official dynamic effects from decompiled com.mansaa.smartshine.util.Util
const EFFECTS = {
  stop: {
    mode: [0x00, 0x00, 0x00, 0x1e]
  },
  police: {
    r: [0xff, 0x2b, 0xff, 0x2b, 0xff, 0x2b, 0xff, 0x2b],
    g: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    b: [0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff],
    mode: [0x01, 0x00, 0x02, 0x04]
  },
  slow_music: {
    r: [0xff, 0xff, 0x55, 0x00, 0x08, 0xc8, 0xd4, 0xff],
    g: [0x00, 0x80, 0xff, 0xff, 0x00, 0x00, 0xff, 0x00],
    b: [0x00, 0x00, 0x00, 0x5e, 0xff, 0xff, 0x00, 0xc8],
    mode: [0x01, 0x00, 0x05, 0x35]
  },
  aliens: {
    r: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    g: [0xff, 0xcc, 0xa6, 0x80, 0x66, 0x4d, 0x33, 0x1a],
    b: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    mode: [0x01, 0x00, 0x02, 0x05]
  },
  fantasy: {
    r: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    g: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    b: [0x1a, 0x33, 0x4d, 0x66, 0x80, 0xa6, 0xcc, 0xff],
    mode: [0x01, 0x00, 0x05, 0x09]
  },
  magic: {
    r: [0x00, 0x80, 0x00, 0x66, 0x00, 0x33, 0x00, 0x1a],
    g: [0x00, 0x80, 0x00, 0x66, 0x00, 0x33, 0x00, 0x1a],
    b: [0x33, 0x80, 0x66, 0x66, 0x99, 0x33, 0xcc, 0x1a],
    mode: [0x01, 0x00, 0x02, 0x10]
  },
  fire_cracker: {
    r: [0x80, 0xff, 0xcc, 0xff, 0x80, 0xff, 0xcc, 0xff],
    g: [0x80, 0xce, 0x00, 0x81, 0x80, 0xce, 0x00, 0x81],
    b: [0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00],
    mode: [0x01, 0x00, 0x03, 0x02]
  },
  romance: {
    r: [0xff, 0xff, 0x99, 0xff, 0xff, 0xff, 0xff, 0x99],
    g: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    b: [0x00, 0xb4, 0x00, 0x00, 0xb4, 0x00, 0xb4, 0x00],
    mode: [0x01, 0x00, 0x05, 0x99]
  },
  kite_festival: {
    r: [0xff, 0x00, 0x15, 0xff, 0xff, 0x00, 0xa3, 0xa1],
    g: [0x81, 0x38, 0xff, 0x00, 0xf4, 0xff, 0x00, 0x35],
    b: [0x00, 0x80, 0x00, 0xce, 0x00, 0xd2, 0xff, 0xc7],
    mode: [0x01, 0x00, 0x05, 0x10]
  },
  dance: {
    r: [0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0xff],
    g: [0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00],
    b: [0x00, 0xff, 0x00, 0xe7, 0x00, 0xff, 0x00, 0xe7],
    mode: [0x01, 0x00, 0x03, 0x03]
  },
  dim_slow_music: {
    r: [0x40, 0x40, 0x15, 0x00, 0x02, 0x32, 0x35, 0x40],
    g: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    b: [0x00, 0x00, 0x00, 0x17, 0x40, 0x40, 0x00, 0x32],
    mode: [0x01, 0x00, 0x05, 0x35]
  },
  dim_fantasy: {
    r: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    g: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    b: [0x08, 0x0f, 0x17, 0x1f, 0x26, 0x2e, 0x36, 0x3d],
    mode: [0x01, 0x00, 0x05, 0x12]
  },
  dim_romance: {
    r: [0x40, 0x26, 0x1a, 0x40, 0x26, 0x40, 0x26, 0x1a],
    g: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    b: [0x00, 0x1b, 0x00, 0x00, 0x1b, 0x00, 0x1b, 0x00],
    mode: [0x01, 0x00, 0x05, 0x99]
  }
};

// Runtime State
let bluetoothDevice = null;
let gattServer = null;
let charData = null;
let charMode = null;
let charTime = null;
let charR = null;
let charG = null;
let charB = null;
let charName = null;
let charLastSaved = null;

let authorizedDevices = [];
let customMacFilters = [];
let customCompanyId = null;
let deferredInstallPrompt = null;

let isPoweredOn = false;
let currentR = 255;
let currentG = 255;
let currentB = 255;
let currentBrightness = 100;

let writeQueue = Promise.resolve();
let pendingColorPayload = null;
let isColorWriteInFlight = false;

// DOM References
const envBanner = document.getElementById('envBanner');
const installAppBtn = document.getElementById('installAppBtn');
const statusBadge = document.getElementById('statusBadge');
const statusText = document.getElementById('statusText');
const deviceNameEl = document.getElementById('deviceName');

const reconnectBtn = document.getElementById('reconnectBtn');
const connectBtn = document.getElementById('connectBtn');
const connectAllBtn = document.getElementById('connectAllBtn');
const disconnectBtn = document.getElementById('disconnectBtn');

const macInput = document.getElementById('macInput');
const companyIdInput = document.getElementById('companyIdInput');
const applyMacBtn = document.getElementById('applyMacBtn');
const clearMacBtn = document.getElementById('clearMacBtn');
const macFilterStatus = document.getElementById('macFilterStatus');

const powerBtn = document.getElementById('powerBtn');
const brightnessSlider = document.getElementById('brightnessSlider');
const brightnessVal = document.getElementById('brightnessVal');
const tempSlider = document.getElementById('tempSlider');
const tempVal = document.getElementById('tempVal');
const colorPicker = document.getElementById('colorPicker');
const colorPreview = document.getElementById('colorPreview');
const hexVal = document.getElementById('hexVal');
const saveDefaultBtn = document.getElementById('saveDefaultBtn');

const lampNameInput = document.getElementById('lampNameInput');
const saveNameBtn = document.getElementById('saveNameBtn');
const consoleLog = document.getElementById('consoleLog');
const clearLogBtn = document.getElementById('clearLogBtn');

// Safe identifier masking (avoids surfacing full hardware IDs in UI labels)
function maskIdentifier(rawId) {
  if (!rawId || typeof rawId !== 'string') return 'Unknown';
  const clean = rawId.trim();
  if (clean.length <= 4) return '****';
  return `***-${clean.slice(-4)}`;
}

function log(msg, type = 'info') {
  const allowedTypes = ['info', 'success', 'warn', 'error'];
  const safeType = allowedTypes.includes(type) ? type : 'info';
  const line = document.createElement('div');
  line.className = `log-line log-${safeType}`;
  const time = new Date().toLocaleTimeString();
  line.textContent = `[${time}] ${msg}`;
  consoleLog.appendChild(line);
  consoleLog.scrollTop = consoleLog.scrollHeight;
}

clearLogBtn.addEventListener('click', (e) => {
  e.preventDefault();
  consoleLog.replaceChildren();
});

function showBanner(text, variant = 'warn') {
  envBanner.textContent = text;
  envBanner.className = `banner banner-${variant}`;
}

function hideBanner() {
  envBanner.className = 'banner hidden';
  envBanner.textContent = '';
}

function clampByte(n) {
  return Math.max(0, Math.min(255, Math.round(Number(n) || 0)));
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => (b & 0xff).toString(16).padStart(2, '0').toUpperCase())
    .join(' ');
}

/*
 * Exact reverse-engineered Mansaa "CheckAes" advertisement encoder
 * from HomeActivity.CRC_Checksum() + BLEDevice.encodeArray()
 *
 * Given 7 decoded bytes [mac0..mac5, 0xD0], produces 8 encoded bytes:
 *   encode[0] = crc
 *   encode[1..7] = decode[0..6] ^ crc
 * In BLE Manufacturer Specific Data (0xFF):
 *   companyIdentifier = encode[0] | (encode[1] << 8)  (little-endian uint16)
 *   dataPrefix        = encode[2..7]                  (6 bytes)
 */
function mansaaCrcChecksum(bytes7) {
  let crc = 0;
  for (let i = 0; i < bytes7.length; i++) {
    let temp = bytes7[i] & 0xff;
    for (let j = 0; j < 8; j++) {
      if ((temp & 1) === 1) {
        crc = (CRC_PASSWORD[j] ^ crc) & 0xff;
      }
      temp = temp >> 1;
    }
  }
  return crc & 0xff;
}

function encodeMansaaAdvertisement(mac6Bytes) {
  const decode = [
    mac6Bytes[0] & 0xff,
    mac6Bytes[1] & 0xff,
    mac6Bytes[2] & 0xff,
    mac6Bytes[3] & 0xff,
    mac6Bytes[4] & 0xff,
    mac6Bytes[5] & 0xff,
    0xd0 // TYPE_HUE (208 / -48 signed)
  ];
  const crc = mansaaCrcChecksum(decode);
  const encoded = new Uint8Array(8);
  encoded[0] = crc;
  for (let i = 0; i < 7; i++) {
    encoded[i + 1] = (decode[i] ^ crc) & 0xff;
  }
  const companyIdentifier = encoded[0] | (encoded[1] << 8);
  const dataPrefix = encoded.slice(2, 8);
  return { companyIdentifier, dataPrefix, encoded };
}

function parseMacAddress(input) {
  if (!input || typeof input !== 'string') return null;
  const trimmed = input.trim();
  if (!/^[0-9A-Fa-f]{2}([:-]?[0-9A-Fa-f]{2}){5}$/.test(trimmed)) {
    return null;
  }
  const hexOnly = trimmed.replace(/[:-]/g, '');
  const bytes = [];
  for (let i = 0; i < 12; i += 2) {
    bytes.push(parseInt(hexOnly.slice(i, i + 2), 16));
  }
  return bytes;
}

function parseCompanyId(input) {
  if (!input || typeof input !== 'string') return null;
  const trimmed = input.trim();
  if (!/^(0x)?[0-9A-Fa-f]{1,4}$/.test(trimmed)) {
    return null;
  }
  const clean = trimmed.replace(/^0x/i, '');
  return parseInt(clean, 16) & 0xffff;
}

applyMacBtn.addEventListener('click', () => {
  customMacFilters = [];
  customCompanyId = null;

  const macRaw = macInput.value.trim();
  const cidRaw = companyIdInput.value.trim();
  const summaries = [];

  if (macRaw) {
    const macBytes = parseMacAddress(macRaw);
    if (!macBytes) {
      macFilterStatus.textContent = 'Invalid MAC format. Expected 6 hex pairs (e.g. C7:12:34:56:78:9A).';
      macFilterStatus.classList.remove('hidden');
      log('Invalid MAC address format entered.', 'error');
      return;
    }

    const forward = encodeMansaaAdvertisement(macBytes);
    const reversed = encodeMansaaAdvertisement([...macBytes].reverse());
    customMacFilters.push(forward, reversed);

    const fwdCid = '0x' + forward.companyIdentifier.toString(16).padStart(4, '0').toUpperCase();
    const revCid = '0x' + reversed.companyIdentifier.toString(16).padStart(4, '0').toUpperCase();
    summaries.push(`MAC CheckAes Filter Active -> CompanyID ${fwdCid} [${bytesToHex(forward.dataPrefix)}] | Reversed ${revCid}`);
  }

  if (cidRaw) {
    const parsedCid = parseCompanyId(cidRaw);
    if (parsedCid === null) {
      macFilterStatus.textContent = 'Invalid Company ID. Expected 1-4 hex digits (e.g. 0xDE19).';
      macFilterStatus.classList.remove('hidden');
      log('Invalid Company ID format entered.', 'error');
      return;
    }
    customCompanyId = parsedCid;
    summaries.push(`Custom CompanyID: 0x${parsedCid.toString(16).padStart(4, '0').toUpperCase()}`);
  }

  if (summaries.length === 0) {
    macFilterStatus.textContent = 'Default signature active: CompanyID 0xDE19 + Service 0xFFB0.';
  } else {
    macFilterStatus.textContent = summaries.join(' • ');
    log('Applied custom Mansaa advertisement signature filter.', 'success');
  }
  macFilterStatus.classList.remove('hidden');
});

clearMacBtn.addEventListener('click', () => {
  macInput.value = '';
  companyIdInput.value = '';
  customMacFilters = [];
  customCompanyId = null;
  macFilterStatus.textContent = 'Reset to default Mansaa signature (CompanyID 0xDE19 + Service 0xFFB0).';
  macFilterStatus.classList.remove('hidden');
  log('Cleared custom MAC filter; using default 0xDE19 signature.');
});

function buildSmartFilters() {
  const filters = [];

  // 1. User-supplied MAC CheckAes exact byte-prefix filters (both endiannesses)
  for (const mf of customMacFilters) {
    filters.push({
      manufacturerData: [{
        companyIdentifier: mf.companyIdentifier,
        dataPrefix: mf.dataPrefix
      }]
    });
    filters.push({
      manufacturerData: [{
        companyIdentifier: mf.companyIdentifier
      }]
    });
  }

  // 2. User-supplied custom Company ID
  if (customCompanyId !== null) {
    filters.push({
      manufacturerData: [{ companyIdentifier: customCompanyId }]
    });
  }

  // 3. Discovered Mansaa hardware Company ID 0xDE19 (and byte-swapped 0x19DE safety)
  filters.push({
    manufacturerData: [{ companyIdentifier: DEFAULT_MANSAA_COMPANY_ID }]
  });
  filters.push({
    manufacturerData: [{ companyIdentifier: DEFAULT_MANSAA_COMPANY_ID_BE }]
  });

  // 4. GATT Service UUIDs (if included in scan response)
  filters.push({ services: [SERVICE_LED_UUID] });
  filters.push({ services: [SERVICE_AES_UUID] });

  // 5. Known Mansaa / SmartShine name prefixes
  for (const prefix of ['MAN', 'Mansaa', 'SmartShine', 'LED', 'Lamp']) {
    filters.push({ namePrefix: prefix });
  }

  return filters;
}

function setControlsEnabled(enabled) {
  powerBtn.disabled = !enabled;
  brightnessSlider.disabled = !enabled;
  tempSlider.disabled = !enabled;
  colorPicker.disabled = !enabled;
  saveDefaultBtn.disabled = !enabled;
  lampNameInput.disabled = !enabled;
  saveNameBtn.disabled = !enabled;
  document.querySelectorAll('.scene-pill').forEach((btn) => { btn.disabled = !enabled; });
  document.querySelectorAll('.effect-btn').forEach((btn) => { btn.disabled = !enabled; });
}

function queueWrite(fn) {
  writeQueue = writeQueue.then(fn).catch((err) => {
    log(`BLE write error: ${err && err.message ? err.message : 'Operation failed'}`, 'error');
  });
  return writeQueue;
}

async function sendGattWrite(characteristic, byteArray) {
  if (!characteristic) return;
  const data = new Uint8Array(byteArray);
  const shortUuid = characteristic.uuid.substring(4, 8).toUpperCase();
  log(`GATT TX (0x${shortUuid}): ${bytesToHex(data)}`);
  if (typeof characteristic.writeValueWithResponse === 'function') {
    await characteristic.writeValueWithResponse(data.buffer);
  } else {
    await characteristic.writeValue(data.buffer);
  }
}

// Coalesces rapid slider inputs so Android BLE never backlogs GATT packets
function scheduleColorWrite(sr, sg, sb) {
  pendingColorPayload = [0xd0, clampByte(sr), clampByte(sg), clampByte(sb)];
  if (isColorWriteInFlight) {
    return;
  }
  isColorWriteInFlight = true;
  queueWrite(async () => {
    try {
      while (pendingColorPayload !== null) {
        const nextBytes = pendingColorPayload;
        pendingColorPayload = null;
        if (charData) {
          await sendGattWrite(charData, nextBytes);
        }
      }
    } finally {
      isColorWriteInFlight = false;
    }
  });
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Establish GATT services, handshake, clock sync, and state read
async function setupGattConnection(device) {
  bluetoothDevice = device;
  bluetoothDevice.removeEventListener('gattserverdisconnected', onDisconnected);
  bluetoothDevice.addEventListener('gattserverdisconnected', onDisconnected);

  const maskedId = maskIdentifier(bluetoothDevice.id);
  log(`Selected bulb: ${bluetoothDevice.name || 'Unnamed Mansaa Bulb'} (${maskedId})`, 'success');

  statusText.textContent = 'Connecting…';

  // Retry GATT connect up to 2 times for Android BLE stability (avoids transient GATT 133 errors)
  let lastErr = null;
  for (let attempt = 1; attempt <= 2; attempt++) {
    try {
      gattServer = await bluetoothDevice.gatt.connect();
      lastErr = null;
      break;
    } catch (err) {
      lastErr = err;
      log(`GATT connect attempt ${attempt} failed, retrying…`, 'warn');
      await sleep(400);
    }
  }
  if (lastErr || !gattServer) {
    throw lastErr || new Error('Failed to open GATT connection');
  }

  log('GATT connected ✓', 'success');
  log('Discovering primary LED service 0xFFB0…');
  const ledService = await gattServer.getPrimaryService(SERVICE_LED_UUID);

  charData = await ledService.getCharacteristic(CHAR_DATA_UUID);
  log('Bound color/power characteristic 0xFFB2 ✓', 'success');

  try { charMode = await ledService.getCharacteristic(CHAR_MODE_UUID); } catch (_) { charMode = null; }
  try { charTime = await ledService.getCharacteristic(CHAR_TIME_UUID); } catch (_) { charTime = null; }
  try { charR = await ledService.getCharacteristic(CHAR_R_ARRAY_UUID); } catch (_) { charR = null; }
  try { charG = await ledService.getCharacteristic(CHAR_G_ARRAY_UUID); } catch (_) { charG = null; }
  try { charB = await ledService.getCharacteristic(CHAR_B_ARRAY_UUID); } catch (_) { charB = null; }
  try { charName = await ledService.getCharacteristic(CHAR_NAME_UUID); } catch (_) { charName = null; }
  try { charLastSaved = await ledService.getCharacteristic(CHAR_LAST_SAVED_UUID); } catch (_) { charLastSaved = null; }

  // Optional 0xFC60 / 0xFC64 XOR challenge handshake
  try {
    const aesService = await gattServer.getPrimaryService(SERVICE_AES_UUID);
    const aesChar = await aesService.getCharacteristic(CHAR_AES_CHECK_UUID);
    log('Optional handshake 0xFC64 detected — sending challenge…');
    const rndBytes = new Uint8Array(1);
    crypto.getRandomValues(rndBytes);
    const rnd = rndBytes[0] % 100;
    const raw = [0x99, (rnd >> 8) & 0xff, rnd & 0xff, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67];
    const crc = 0x11;
    const encoded = [crc, ...raw.map((b) => b ^ crc)];
    await sendGattWrite(aesChar, encoded);
    log('Handshake complete ✓', 'success');
  } catch (_) {
    log('Direct GATT mode (no 0xFC60 handshake required).');
  }

  // Sync bulb clock (0xFFB3)
  if (charTime) {
    const now = new Date();
    queueWrite(() => sendGattWrite(charTime, [
      now.getFullYear() & 0xff,
      (now.getFullYear() >> 8) & 0xff,
      now.getMonth() + 1,
      now.getDate(),
      now.getHours(),
      now.getMinutes(),
      now.getSeconds()
    ]));
  }

  // Read lamp name from 0xFFB7 if available
  let resolvedName = bluetoothDevice.name || '';
  if (charName) {
    try {
      const nameVal = await charName.readValue();
      const decoded = new TextDecoder('utf-8')
        .decode(new Uint8Array(nameVal.buffer))
        .replace(/\0/g, '')
        .trim();
      if (decoded) {
        resolvedName = decoded;
        lampNameInput.value = decoded;
      }
    } catch (_) {
      // Non-fatal if bulb firmware restricts reading 0xFFB7
    }
  }

  // Read current RGB/power state from 0xFFB2
  try {
    const stateVal = await charData.readValue();
    const raw = new Uint8Array(stateVal.buffer);
    log(`Initial state (0xFFB2): ${bytesToHex(raw)}`);
    if (raw.length >= 4 && raw[0] === 0xd0) {
      if (raw[1] === 0 && raw[2] === 0 && raw[3] === 0) {
        updatePowerUI(false);
      } else {
        currentR = raw[1];
        currentG = raw[2];
        currentB = raw[3];
        updatePowerUI(true);
        updateColorUI(currentR, currentG, currentB);
      }
    } else {
      updatePowerUI(true);
    }
  } catch (_) {
    log('Initial state read skipped — ready for commands.');
    updatePowerUI(true);
  }

  statusBadge.classList.add('connected');
  statusText.textContent = 'Connected (Direct BLE)';
  deviceNameEl.textContent = `${resolvedName || 'Mansaa Smart Shine'} (${maskedId})`;

  reconnectBtn.classList.add('hidden');
  connectBtn.classList.add('hidden');
  connectAllBtn.classList.add('hidden');
  disconnectBtn.classList.remove('hidden');
  setControlsEnabled(true);

  await refreshAuthorizedDevices(false);
}

// Reconnect to a previously granted Web Bluetooth device without opening the chooser
async function reconnectSavedDevice(device) {
  if (!device) return;
  try {
    statusText.textContent = 'Reconnecting…';
    log(`Attempting direct reconnect to saved bulb (${maskIdentifier(device.id)})…`);

    // On Chrome Android/macOS, watchAdvertisements wakes the BLE scan cache before gatt.connect()
    if (typeof device.watchAdvertisements === 'function') {
      const abortController = new AbortController();
      try {
        const seenAdv = new Promise((resolve) => {
          device.addEventListener('advertisementreceived', () => resolve(true), {
            once: true,
            signal: abortController.signal
          });
        });
        await device.watchAdvertisements({ signal: abortController.signal });
        await Promise.race([seenAdv, sleep(2500)]);
      } catch (_) {
        // Proceed directly to gatt.connect() if watchAdvertisements is unsupported
      } finally {
        abortController.abort();
      }
    }

    await setupGattConnection(device);
  } catch (err) {
    statusText.textContent = 'Disconnected';
    log(`Direct reconnect did not find bulb in range (${err.message || 'timeout'}). Use "Connect Mansaa Bulb".`, 'warn');
  }
}

async function refreshAuthorizedDevices(attemptAutoConnect = false) {
  if (!navigator.bluetooth || typeof navigator.bluetooth.getDevices !== 'function') {
    return;
  }
  try {
    const devices = await navigator.bluetooth.getDevices();
    authorizedDevices = devices || [];
    if (authorizedDevices.length > 0 && (!gattServer || !gattServer.connected)) {
      const target = authorizedDevices[0];
      const label = target.name || 'Saved Mansaa Bulb';
      reconnectBtn.textContent = `⚡ Instant Reconnect: ${label} (${maskIdentifier(target.id)})`;
      reconnectBtn.classList.remove('hidden');
      if (attemptAutoConnect) {
        await reconnectSavedDevice(target);
      }
    } else if (authorizedDevices.length === 0) {
      reconnectBtn.classList.add('hidden');
    }
  } catch (_) {
    // getDevices() requires chrome://flags/#enable-web-bluetooth-new-permissions-backend
  }
}

reconnectBtn.addEventListener('click', async () => {
  if (authorizedDevices.length > 0) {
    await reconnectSavedDevice(authorizedDevices[0]);
  }
});

// Primary Connect: Uses Manufacturer ID 0xDE19 + MAC CheckAes signature + Service UUIDs
connectBtn.addEventListener('click', async () => {
  if (!navigator.bluetooth) {
    log('Web Bluetooth API unavailable in this browser/context.', 'error');
    return;
  }
  try {
    const filters = buildSmartFilters();
    log('Opening Bluetooth selector with Mansaa 0xDE19 hardware signature filter…');
    log('Tip: Even if listed as "Unknown or Unsupported Device", select it — this filter matches your bulb!');
    const device = await navigator.bluetooth.requestDevice({
      filters,
      optionalServices: [SERVICE_LED_UUID, SERVICE_AES_UUID, SERVICE_DEV_INFO_UUID]
    });
    await setupGattConnection(device);
  } catch (err) {
    if (err && err.name !== 'NotFoundError' && err.name !== 'NotAllowedError') {
      log(`Connection failed: ${err.message}`, 'error');
    } else {
      log('Selector closed without pairing. Ensure the bulb is ON, disconnected from Mac/other apps, and Android Location is ON.', 'warn');
    }
    if (!gattServer || !gattServer.connected) {
      resetDisconnectedUI();
    }
  }
});

// Fallback Connect: acceptAllDevices
connectAllBtn.addEventListener('click', async () => {
  if (!navigator.bluetooth) {
    log('Web Bluetooth API unavailable in this browser/context.', 'error');
    return;
  }
  try {
    log('Opening unfiltered BLE device list… look for MAN_V11400009 or Unnamed device.');
    const device = await navigator.bluetooth.requestDevice({
      acceptAllDevices: true,
      optionalServices: [SERVICE_LED_UUID, SERVICE_AES_UUID, SERVICE_DEV_INFO_UUID]
    });
    await setupGattConnection(device);
  } catch (err) {
    if (err && err.name !== 'NotFoundError' && err.name !== 'NotAllowedError') {
      log(`Connection failed: ${err.message}`, 'error');
    } else {
      log('Unfiltered selector closed.', 'warn');
    }
    if (!gattServer || !gattServer.connected) {
      resetDisconnectedUI();
    }
  }
});

disconnectBtn.addEventListener('click', () => {
  if (bluetoothDevice && bluetoothDevice.gatt && bluetoothDevice.gatt.connected) {
    bluetoothDevice.gatt.disconnect();
  } else {
    onDisconnected();
  }
});

function resetDisconnectedUI() {
  statusBadge.classList.remove('connected');
  statusText.textContent = 'Disconnected';
  deviceNameEl.textContent = 'No bulb connected';
  connectBtn.classList.remove('hidden');
  connectAllBtn.classList.remove('hidden');
  disconnectBtn.classList.add('hidden');
  if (authorizedDevices.length > 0) {
    reconnectBtn.classList.remove('hidden');
  }
  setControlsEnabled(false);
  updatePowerUI(false);
}

function onDisconnected() {
  charData = null;
  charMode = null;
  charTime = null;
  charR = null;
  charG = null;
  charB = null;
  charName = null;
  charLastSaved = null;
  gattServer = null;
  log('Bulb disconnected.', 'warn');
  resetDisconnectedUI();
}

function updatePowerUI(on) {
  isPoweredOn = Boolean(on);
  if (isPoweredOn) {
    powerBtn.classList.add('on');
  } else {
    powerBtn.classList.remove('on');
  }
}

function updateColorUI(r, g, b) {
  const cr = clampByte(r);
  const cg = clampByte(g);
  const cb = clampByte(b);
  const hex = '#' + [cr, cg, cb].map((x) => x.toString(16).padStart(2, '0')).join('');
  colorPicker.value = hex;
  colorPreview.style.backgroundColor = hex;
  colorPreview.textContent = hex.toUpperCase();
  hexVal.textContent = hex.toUpperCase();

  const luminance = (0.299 * cr + 0.587 * cg + 0.114 * cb) / 255;
  colorPreview.style.color = luminance > 0.52 ? '#000000' : '#ffffff';
}

// Power Toggle
powerBtn.addEventListener('click', () => {
  document.querySelectorAll('.effect-btn').forEach((b) => b.classList.remove('active'));
  if (!isPoweredOn) {
    if (currentR === 0 && currentG === 0 && currentB === 0) {
      currentR = 255;
      currentG = 255;
      currentB = 255;
    }
    applyColor(currentR, currentG, currentB);
    updatePowerUI(true);
  } else {
    pendingColorPayload = null;
    if (charData) {
      queueWrite(() => sendGattWrite(charData, [0xd0, 0x00, 0x00, 0x00]));
    }
    updatePowerUI(false);
  }
});

function applyColor(r, g, b) {
  currentR = clampByte(r);
  currentG = clampByte(g);
  currentB = clampByte(b);

  const scale = Math.max(1, Math.min(100, currentBrightness)) / 100.0;
  const sr = clampByte(currentR * scale);
  const sg = clampByte(currentG * scale);
  const sb = clampByte(currentB * scale);

  scheduleColorWrite(sr, sg, sb);
  updatePowerUI(true);
  updateColorUI(currentR, currentG, currentB);
}

colorPicker.addEventListener('input', (e) => {
  const hex = String(e.target.value || '');
  if (!/^#[0-9A-Fa-f]{6}$/.test(hex)) return;
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  document.querySelectorAll('.effect-btn').forEach((btn) => btn.classList.remove('active'));
  applyColor(r, g, b);
});

brightnessSlider.addEventListener('input', (e) => {
  const val = parseInt(e.target.value, 10);
  if (Number.isNaN(val)) return;
  currentBrightness = Math.max(1, Math.min(100, val));
  brightnessVal.textContent = `${currentBrightness}%`;
  applyColor(currentR, currentG, currentB);
});

function kelvinToRGB(kelvin) {
  const clamped = Math.max(2200, Math.min(6500, kelvin));
  const temp = clamped / 100;
  let red;
  let green;
  let blue;

  if (temp <= 66) {
    red = 255;
    green = 99.4708025861 * Math.log(temp) - 161.1195681661;
    blue = temp <= 19 ? 0 : 138.5177312231 * Math.log(temp - 10) - 305.0447927307;
  } else {
    red = 329.698727446 * Math.pow(temp - 60, -0.1332047592);
    green = 288.1221695283 * Math.pow(temp - 60, -0.0755148492);
    blue = 255;
  }
  return [clampByte(red), clampByte(green), clampByte(blue)];
}

tempSlider.addEventListener('input', (e) => {
  const k = parseInt(e.target.value, 10);
  if (Number.isNaN(k)) return;
  const safeK = Math.max(2200, Math.min(6500, k));
  tempVal.textContent = `${safeK}K`;
  const [r, g, b] = kelvinToRGB(safeK);
  document.querySelectorAll('.effect-btn').forEach((btn) => btn.classList.remove('active'));
  applyColor(r, g, b);
});

// Save Current Color to Bulb NVRAM (0xFFBE)
saveDefaultBtn.addEventListener('click', () => {
  if (!charLastSaved) {
    log('Characteristic 0xFFBE not exposed by this bulb firmware.', 'warn');
    return;
  }
  const scale = currentBrightness / 100.0;
  let sr = clampByte(currentR * scale);
  let sg = clampByte(currentG * scale);
  let sb = clampByte(currentB * scale);
  if (sr === 0 && sg === 0 && sb === 0) {
    sr = 255; sg = 255; sb = 255;
  }
  queueWrite(async () => {
    await sendGattWrite(charLastSaved, [0xd0, sr, sg, sb]);
    log('Saved current color to bulb power-on NVRAM (0xFFBE) ✓', 'success');
  });
});

// Rename Bulb (0xFFB7)
saveNameBtn.addEventListener('click', () => {
  const rawName = lampNameInput.value.trim();
  if (!rawName || rawName.length > 16 || !/^[\x20-\x7E]+$/.test(rawName)) {
    log('Enter a valid ASCII name between 1 and 16 characters.', 'error');
    return;
  }
  if (!charName) {
    log('Lamp name characteristic 0xFFB7 not available.', 'warn');
    return;
  }
  const encoded = new TextEncoder().encode(rawName);
  queueWrite(async () => {
    await sendGattWrite(charName, encoded);
    deviceNameEl.textContent = `${rawName} (${maskIdentifier(bluetoothDevice ? bluetoothDevice.id : '')})`;
    log(`Updated bulb GATT name to "${rawName}" (0xFFB7) ✓`, 'success');
  });
});

// Preset Scenes
document.querySelectorAll('.scene-pill').forEach((btn) => {
  btn.addEventListener('click', () => {
    const parts = (btn.dataset.rgb || '').split(',').map(Number);
    if (parts.length !== 3 || parts.some(Number.isNaN)) return;
    document.querySelectorAll('.effect-btn').forEach((b) => b.classList.remove('active'));
    applyColor(parts[0], parts[1], parts[2]);
  });
});

// Dynamic Lighting Effects
document.querySelectorAll('.effect-btn').forEach((btn) => {
  btn.addEventListener('click', () => {
    const effectName = btn.dataset.effect;
    if (!effectName || !Object.prototype.hasOwnProperty.call(EFFECTS, effectName)) {
      return;
    }
    const effect = EFFECTS[effectName];

    document.querySelectorAll('.effect-btn').forEach((b) => b.classList.remove('active'));
    if (effectName !== 'stop') {
      btn.classList.add('active');
    }

    queueWrite(async () => {
      log(`Applying dynamic effect: ${effectName}…`);
      if (!charMode) {
        log('Effect characteristic 0xFFB1 not available.', 'warn');
        return;
      }

      if (effectName === 'stop') {
        await sendGattWrite(charMode, effect.mode);
        log('Dynamic effect stopped ✓', 'success');
        return;
      }

      await sendGattWrite(charMode, [0x00, 0x00, 0x00, 0x1e]);
      await sleep(500);

      if (charR && effect.r) {
        await sendGattWrite(charR, effect.r);
        await sleep(100);
      }
      if (charG && effect.g) {
        await sendGattWrite(charG, effect.g);
        await sleep(100);
      }
      if (charB && effect.b) {
        await sendGattWrite(charB, effect.b);
        await sleep(100);
      }

      await sendGattWrite(charMode, effect.mode);
      updatePowerUI(true);
      log(`Dynamic effect "${effectName}" active ✓`, 'success');
    });
  });
});

// PWA Install Prompt & Offline Service Worker Registration
window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  deferredInstallPrompt = e;
  installAppBtn.classList.remove('hidden');
});

installAppBtn.addEventListener('click', async () => {
  if (!deferredInstallPrompt) return;
  deferredInstallPrompt.prompt();
  await deferredInstallPrompt.userChoice;
  deferredInstallPrompt = null;
  installAppBtn.classList.add('hidden');
});

if ('serviceWorker' in navigator && (window.location.protocol === 'https:' || window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('./sw.js').then(() => {
      log('Offline PWA Service Worker ready ✓', 'info');
    }).catch(() => {});
  });
}

// Startup Diagnostics & Auto-Reconnect Check
async function initApp() {
  if (!window.isSecureContext) {
    showBanner(
      'Web Bluetooth is disabled by Chrome on insecure HTTP/file URLs. Host these static files on HTTPS (e.g. GitHub Pages, Cloudflare Pages, Netlify) or open via http://localhost to connect directly from your phone without a server.',
      'warn'
    );
    log('Insecure origin detected — Web Bluetooth requires HTTPS or localhost.', 'warn');
  } else if (!navigator.bluetooth) {
    showBanner(
      'This browser does not support Web Bluetooth. Use Google Chrome, Edge, or Brave on Android or macOS (on iOS, use the Bluefy browser).',
      'warn'
    );
    log('navigator.bluetooth is not available in this browser.', 'warn');
  } else {
    hideBanner();
    log('Web Bluetooth ready (Mansaa 0xDE19 hardware signature filter enabled).', 'info');
    await refreshAuthorizedDevices(true);
  }
}

initApp();
