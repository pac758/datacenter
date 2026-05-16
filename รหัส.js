// ===================================================================
// ⚙️ Code.gs - FIXED v15.0 (Token-based Auth)
// ✅ ลบ Session.getActiveUser() ทั้งหมด
// ✅ ใช้ Token-based Authentication แทน
// ✅ รองรับ Multi Google Account
// ===================================================================

const DEFAULT_CONFIG = {
  schoolName: 'ชื่อโรงเรียนของคุณ',
  schoolShort: 'ชื่อย่อ',
  schoolAddress: 'ที่อยู่โรงเรียน',
  adminEmail: 'admin@school.ac.th',
  spreadsheetId: '', // ปล่อยว่างไว้เพื่อให้ระบบบังคับตั้งค่าครั้งแรก
  sheetName: 'การตอบแบบฟอร์ม 1',
  folderId: '', // ปล่อยว่างไว้เพื่อให้ระบบบังคับตั้งค่าครั้งแรก
  googleFormUrl: '',
  lineNotifyToken: '', // เพิ่มช่องสำหรับ LINE Notify ของแต่ละโรงเรียน
  lineChannelAccessToken: '', // LINE Bot Channel Access Token (Messaging API)
  lineChannelSecret: '', // LINE Bot Channel Secret
  primaryColor: '#6366f1', // สีหลัก (Indigo)
  secondaryColor: '#4f46e5',
  version: '16.0',
  credit: '© 2568 @pthk — RKT School Data Center',
  logoFileId: ''
};

const DEFAULT_ADMIN_PASSWORD = '3333';
const ADMIN_PASSWORD_HASH_KEY = 'ADMIN_PASSWORD_HASH';
const ADMIN_PASSWORD_SALT_KEY = 'ADMIN_PASSWORD_SALT';
const DOCS_CACHE_KEY = 'RKT_DOCS_CACHE_V1';
const DOCS_CACHE_TTL_SECONDS = 300;
const SUBMITTERS_SHEET_NAME = 'ผู้ส่ง';
const SETUP_SHEET_NAME = 'setup';
const DELETE_LOG_SHEET_NAME = 'Delete_Log';
const AUDIT_LOG_SHEET_NAME = 'Audit_Log';

// ✅ [NEW] Token Configuration
const TOKEN_EXPIRY_HOURS = 24;

function hashPassword_(password, salt) {
  var raw = String(salt || '') + '|' + String(password || '');
  var bytes = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, raw, Utilities.Charset.UTF_8);
  return bytes.map(function(b) {
    var v = (b < 0 ? b + 256 : b);
    return ('0' + v.toString(16)).slice(-2);
  }).join('');
}

function ensureAdminPasswordInitialized_() {
  var props = PropertiesService.getScriptProperties();
  var hash = props.getProperty(ADMIN_PASSWORD_HASH_KEY);
  var salt = props.getProperty(ADMIN_PASSWORD_SALT_KEY);
  if (!hash || !salt) {
    salt = Utilities.getUuid();
    hash = hashPassword_(DEFAULT_ADMIN_PASSWORD, salt);
    props.setProperty(ADMIN_PASSWORD_SALT_KEY, salt);
    props.setProperty(ADMIN_PASSWORD_HASH_KEY, hash);
  }
  return { salt: salt, hash: hash };
}

function verifyAdminPassword_(password) {
  var init = ensureAdminPasswordInitialized_();
  return hashPassword_(password, init.salt) === init.hash;
}

function setAdminPassword(token, newPassword) {
  return requireAuth_(token, function(username) {
    if (username !== 'admin') {
      return { success: false, error: 'FORBIDDEN', message: 'ไม่มีสิทธิ์' };
    }
    newPassword = String(newPassword || '').trim();
    if (newPassword.length < 6) {
      return { success: false, error: 'WEAK_PASSWORD', message: 'รหัสผ่านต้องยาวอย่างน้อย 6 ตัวอักษร' };
    }
    var props = PropertiesService.getScriptProperties();
    var salt = Utilities.getUuid();
    var hash = hashPassword_(newPassword, salt);
    props.setProperty(ADMIN_PASSWORD_SALT_KEY, salt);
    props.setProperty(ADMIN_PASSWORD_HASH_KEY, hash);
    resetTokenSecret();
    return { success: true, message: 'เปลี่ยนรหัสผ่านเรียบร้อย' };
  });
}

// ===================================================================
// 🔐 TOKEN-BASED AUTHENTICATION SYSTEM
// ===================================================================

/**
 * ✅ ดึง Secret Key จาก Script Properties (สร้างอัตโนมัติถ้ายังไม่มี)
 */
function getTokenSecret_() {
  var props = PropertiesService.getScriptProperties();
  var secret = props.getProperty('TOKEN_SECRET');
  
  if (!secret) {
    secret = Utilities.getUuid() + '-' + Utilities.getUuid();
    props.setProperty('TOKEN_SECRET', secret);
    Logger.log('🔐 New TOKEN_SECRET generated');
  }
  
  return secret;
}

/**
 * ✅ สร้าง Auth Token
 */
function generateAuthToken(username) {
  try {
    var secret = getTokenSecret_();
    var timestamp = Date.now();
    var expiry = timestamp + (TOKEN_EXPIRY_HOURS * 60 * 60 * 1000);
    var data = username + '|' + expiry + '|' + timestamp;
    
    var signature = Utilities.base64Encode(
      Utilities.computeHmacSha256Signature(data, secret)
    ).replace(/[+/=]/g, function(c) { 
      return { '+': '-', '/': '_', '=': '' }[c]; 
    });
    
    var encodedData = Utilities.base64Encode(data).replace(/[+/=]/g, function(c) { 
      return { '+': '-', '/': '_', '=': '' }[c]; 
    });
    
    return encodedData + '.' + signature.substring(0, 32);
  } catch (e) {
    Logger.log('❌ generateAuthToken error: ' + e.message);
    return null;
  }
}

/**
 * ✅ ตรวจสอบ Auth Token
 */
function verifyAuthToken(token) {
  try {
    if (!token || typeof token !== 'string') {
      return { valid: false, reason: 'NO_TOKEN' };
    }
    
    var parts = token.split('.');
    if (parts.length !== 2) {
      return { valid: false, reason: 'INVALID_FORMAT' };
    }
    
    var secret = getTokenSecret_();
    
    var encodedData = parts[0].replace(/-/g, '+').replace(/_/g, '/');
    var data = Utilities.newBlob(Utilities.base64Decode(encodedData)).getDataAsString();
    var providedSig = parts[1];
    
    var expectedSig = Utilities.base64Encode(
      Utilities.computeHmacSha256Signature(data, secret)
    ).replace(/[+/=]/g, function(c) { 
      return { '+': '-', '/': '_', '=': '' }[c]; 
    }).substring(0, 32);
    
    if (providedSig !== expectedSig) {
      return { valid: false, reason: 'INVALID_SIGNATURE' };
    }
    
    var dataParts = data.split('|');
    if (dataParts.length < 2) {
      return { valid: false, reason: 'INVALID_DATA' };
    }
    
    var username = dataParts[0];
    var expiry = parseInt(dataParts[1]);
    
    if (Date.now() > expiry) {
      return { valid: false, reason: 'EXPIRED', username: username };
    }
    
    return { valid: true, username: username, expiry: expiry };
  } catch (e) {
    Logger.log('❌ verifyAuthToken error: ' + e.message);
    return { valid: false, reason: 'ERROR', message: e.message };
  }
}

/**
 * ✅ [API] ตรวจสอบ token จาก client
 */
function validateToken(token) {
  var result = verifyAuthToken(token);
  return {
    valid: result.valid,
    username: result.username || null,
    reason: result.reason || null
  };
}

/**
 * ✅ [API] Refresh token (ต่ออายุ)
 */
function refreshToken(oldToken) {
  var result = verifyAuthToken(oldToken);
  if (result.valid) {
    var newToken = generateAuthToken(result.username);
    return {
      success: true,
      token: newToken,
      username: result.username
    };
  }
  return {
    success: false,
    reason: result.reason,
    message: 'Token ไม่ถูกต้องหรือหมดอายุ'
  };
}

/**
 * ✅ [API] Admin Login - ตรวจสอบรหัสผ่านและสร้าง token
 */
function adminLogin(password) {
  if (verifyAdminPassword_((password || '').toString().trim())) {
    var token = generateAuthToken('admin');
    return {
      success: true,
      message: 'เข้าสู่ระบบสำเร็จ',
      token: token,
      username: 'admin',
      role: 'admin'
    };
  }
  return {
    success: false,
    message: 'รหัสผ่านไม่ถูกต้อง'
  };
}

/**
 * ✅ [ADMIN] รีเซ็ต Secret Key (Force logout ทุกคน)
 */
function resetTokenSecret() {
  var props = PropertiesService.getScriptProperties();
  var newSecret = Utilities.getUuid() + '-' + Utilities.getUuid();
  props.setProperty('TOKEN_SECRET', newSecret);
  Logger.log('🔐 TOKEN_SECRET has been reset');
  return { success: true, message: 'Token secret reset. All users must login again.' };
}

// ===================================================================
// 🛡️ PROTECTED API WRAPPER
// ===================================================================

/**
 * ✅ Helper - ตรวจสอบ token ก่อนทำงาน
 */
function requireAuth_(token, callback) {
  var authResult = verifyAuthToken(token);
  
  if (!authResult.valid) {
    return {
      success: false,
      error: 'UNAUTHORIZED',
      reason: authResult.reason,
      message: 'กรุณาเข้าสู่ระบบใหม่'
    };
  }
  
  return callback(authResult.username);
}

// ===================================================================
// 🌐 WEB APP ENTRY POINT
// ===================================================================

function doGet(e) {
  var template = HtmlService.createTemplateFromFile('index');
  var config = getSchoolConfig();
  
  var output = template.evaluate()
    .setTitle('ระบบศูนย์กลางข้อมูล ' + (config.schoolName || ''))
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL)
    .addMetaTag('viewport', 'width=device-width, initial-scale=1');
  
  // ✅ สำคัญ! ตั้ง Sandbox Mode ให้รองรับหลายบัญชี
  // IFRAME mode ทำงานได้ดีกว่ากับ multi-account
  output.setSandboxMode(HtmlService.SandboxMode.IFRAME);
  
  return output;
}

function include(filename) {
  return HtmlService.createHtmlOutputFromFile(filename).getContent();
}

// ===================================================================
// 🔐 CONFIG SYSTEM (ระบบตั้งค่า)
// ===================================================================

function getMasterSpreadsheetId_() {
  var ssId = PropertiesService.getScriptProperties().getProperty('MASTER_SPREADSHEET_ID');
  return ssId || DEFAULT_CONFIG.spreadsheetId;
}

function getOrCreateSetupSheet_(overrideSsId) {
  var ssId = overrideSsId || getMasterSpreadsheetId_();
  var ss = SpreadsheetApp.openById(ssId);
  var sheet = ss.getSheetByName(SETUP_SHEET_NAME);

  if (!sheet) {
    sheet = ss.insertSheet(SETUP_SHEET_NAME);
    var data = [
      ['การตั้งค่า', 'ค่า', 'คำอธิบาย'],
      ['schoolName', DEFAULT_CONFIG.schoolName, 'ชื่อโรงเรียน (เต็ม)'],
      ['spreadsheetId', ssId, 'Spreadsheet ID'],
      ['folderId', DEFAULT_CONFIG.folderId, 'Folder ID'],
      ['logoFileId', '', 'Logo File ID']
    ];
    sheet.getRange(1, 1, data.length, 3).setValues(data);
    sheet.getRange(1, 1, 1, 3).setBackground('#667eea').setFontColor('#fff').setFontWeight('bold');
    sheet.setColumnWidth(1, 150);
    sheet.setColumnWidth(2, 400);
  }
  return sheet;
}

function getSchoolConfig() {
  try {
    var sheet = getOrCreateSetupSheet_();
    var data = sheet.getDataRange().getValues();
    var config = Object.assign({}, DEFAULT_CONFIG);
    
    for (var i = 1; i < data.length; i++) {
      var key = String(data[i][0]).trim();
      var val = data[i][1];
      if (key && config.hasOwnProperty(key)) {
        config[key] = (val !== undefined && val !== null) ? String(val) : '';
      }
    }

    // ✅ เพิ่ม logoUrl เข้าไปในออบเจกต์ที่ส่งกลับ
    if (config.logoFileId) {
      config.logoUrl = "https://lh3.googleusercontent.com/d/" + config.logoFileId;
    } else {
      config.logoUrl = "";
    }

    return config;
  } catch (e) {
    var fallback = Object.assign({}, DEFAULT_CONFIG);
    fallback.logoUrl = fallback.logoFileId ? "https://lh3.googleusercontent.com/d/" + fallback.logoFileId : "";
    return fallback;
  }
}

function saveSchoolConfig(config, logoFileId) {
  try {
    if (!config || !config.spreadsheetId) return { success: false, error: 'กรุณาระบุ Spreadsheet ID' };
    
    PropertiesService.getScriptProperties().setProperty('MASTER_SPREADSHEET_ID', config.spreadsheetId);
    var sheet = getOrCreateSetupSheet_(config.spreadsheetId);
    
    var currentConfig = getSchoolConfig();
    if (logoFileId !== undefined) {
      config.logoFileId = logoFileId;
    } else if (!config.logoFileId && currentConfig.logoFileId) {
      config.logoFileId = currentConfig.logoFileId;
    }

    var dataToSave = [];
    for (var key in DEFAULT_CONFIG) {
      var val = config.hasOwnProperty(key) ? config[key] : DEFAULT_CONFIG[key];
      dataToSave.push([key, val]);
    }
    
    var header = sheet.getRange('A1:C1').getValues();
    sheet.clearContents();
    sheet.getRange('A1:C1').setValues(header).setFontWeight('bold');
    
    if (dataToSave.length > 0) {
      sheet.getRange(2, 1, dataToSave.length, 2).setValues(dataToSave);
    }
    
    clearDocumentCache();
    return { success: true, message: 'บันทึกเรียบร้อย', config: config };
  } catch (e) {
    return { success: false, error: e.toString() };
  }
}

function saveSchoolConfigSecured(token, config, logoFileId) {
  return requireAuth_(token, function(username) {
    if (username !== 'admin') {
      return { success: false, error: 'FORBIDDEN', message: 'ไม่มีสิทธิ์' };
    }
    return saveSchoolConfig(config, logoFileId);
  });
}

function resetSchoolConfig() {
  try {
    var current = getSchoolConfig();
    if (current.logoFileId) {
      try { DriveApp.getFileById(current.logoFileId).setTrashed(true); } catch(e){}
    }
    var reset = Object.assign({}, DEFAULT_CONFIG, { logoFileId: '' });
    saveSchoolConfig(reset);
    return { success: true, config: DEFAULT_CONFIG };
  } catch(e) {
    return { success: false, error: e.toString() };
  }
}

function resetSchoolConfigSecured(token) {
  return requireAuth_(token, function(username) {
    if (username !== 'admin') {
      return { success: false, error: 'FORBIDDEN', message: 'ไม่มีสิทธิ์' };
    }
    return resetSchoolConfig();
  });
}

/**
 * ✅ [MODIFIED] ตรวจสอบรหัส Admin - คืน token แทน boolean
 */
function checkAdminPassword(password) {
  return adminLogin(password);
}

// ===================================================================
// 📄 DOCUMENT READ (ระบบอ่านข้อมูล)
// ===================================================================

function _getSheetSafe_() {
  var config = getSchoolConfig();
  var ss = SpreadsheetApp.openById(config.spreadsheetId);
  var sheet = ss.getSheetByName(config.sheetName);
  if (!sheet) sheet = ss.getSheetByName('Form Responses 1');
  if (!sheet) sheet = ss.getSheetByName('การตอบแบบฟอร์ม 1');
  if (!sheet) sheet = ss.getSheets()[0];
  return sheet;
}

function _getColIndexMap_(headers) {
  var map = {};
  headers.forEach(function(h, i) {
    var key = String(h).trim();
    if (key) map[key] = i;
  });
  return map;
}

function _getValue_(row, map, possibleNames) {
  if (!Array.isArray(possibleNames)) possibleNames = [possibleNames];
  for (var j = 0; j < possibleNames.length; j++) {
    var idx = map[possibleNames[j]];
    if (idx !== undefined && row[idx] !== undefined) {
      return row[idx];
    }
  }
  return '';
}

function _getAllDocumentsCached_() {
  var cache = CacheService.getScriptCache();
  var cached = cache.get(DOCS_CACHE_KEY);
  if (cached) {
    try { return JSON.parse(cached); } catch(e) {}
  }

  var sheet = _getSheetSafe_();
  var data = sheet.getDataRange().getValues();
  if (data.length <= 1) {
      cache.put(DOCS_CACHE_KEY, JSON.stringify([]), DOCS_CACHE_TTL_SECONDS);
      return [];
  }

  var headers = data[0];
  var map = _getColIndexMap_(headers);
  var rows = data.slice(1);

  var docs = rows.map(function(row, index) {
    var ts = _getValue_(row, map, ['ประทับเวลา', 'Timestamp']);
    var docDate = _getValue_(row, map, ['วันที่เอกสาร', 'Date']);
    var rawCreated = _parseDate(ts);
    var docId = _getValue_(row, map, ['DocID']);
    
    return {
      id: index,
      docId: docId ? String(docId) : '',
      timestamp: _formatDateTH(ts),
      title: String(_getValue_(row, map, ['ชื่อเอกสาร', 'Title', 'Document Title'])),
      category: String(_getValue_(row, map, ['หมวดหมู่', 'Category'])),
      document_type: String(_getValue_(row, map, ['ประเภทเอกสาร', 'Type'])),
      document_date: _formatDateTH(docDate, true),
      _raw_doc_date: _parseDate(docDate).getTime(),
      submitter_name: String(_getValue_(row, map, ['ผู้ส่ง', 'Submitter', 'Name'])),
      tags: String(_getValue_(row, map, ['แท็ก', 'Tags'])),
      description: String(_getValue_(row, map, ['หมายเหตุ', 'Description'])),
      file_objects_json: _getValue_(row, map, ['อัปโหลดไฟล์', 'File Upload', 'Attachments']) || '[]',
      _raw_created: rawCreated.getTime()
    };
  });

  try { cache.put(DOCS_CACHE_KEY, JSON.stringify(docs), DOCS_CACHE_TTL_SECONDS); } catch(e) {}
  return docs;
}

function _invalidateDocsCache_() {
  CacheService.getScriptCache().remove(DOCS_CACHE_KEY);
}

function getDocumentsPaginated(page, pageSize, filters) {
  try {
    page = parseInt(page) || 1;
    pageSize = parseInt(pageSize) || 20;
    filters = filters || {};
    var sortOrder = filters.sortOrder === 'asc' ? 'asc' : 'desc';

    var allDocs = _getAllDocumentsCached_();
    var documents = allDocs.slice();

    if (filters.category) {
      documents = documents.filter(function(d) { return d.category === filters.category; });
    }
    if (filters.type) {
      documents = documents.filter(function(d) { return d.document_type === filters.type; });
    }
    if (filters.searchTerm) {
      var term = String(filters.searchTerm).toLowerCase();
      documents = documents.filter(function(d) {
        return (d.title || '').toLowerCase().includes(term) ||
          (d.submitter_name || '').toLowerCase().includes(term) ||
          (d.tags || '').toLowerCase().includes(term) ||
          (d.description || '').toLowerCase().includes(term);
      });
    }

    // ✅ #13 Advanced Search: filter ผู้ส่ง
    if (filters.submitter) {
      documents = documents.filter(function(d) { return d.submitter_name === filters.submitter; });
    }

    // ✅ #13 Advanced Search: filter แท็ก
    if (filters.tag) {
      var searchTag = filters.tag.toLowerCase();
      documents = documents.filter(function(d) {
        if (!d.tags) return false;
        var tags = d.tags.split(',').map(function(t) { return t.trim().toLowerCase(); });
        return tags.indexOf(searchTag) !== -1;
      });
    }

    // ✅ #13 Advanced Search: filter ชนิดไฟล์ (เช็คจาก file_objects_json)
    if (filters.fileType) {
      documents = documents.filter(function(doc) {
        if (!doc.file_objects_json) return false;
        try {
          var files = JSON.parse(doc.file_objects_json);
          if (!Array.isArray(files)) return false;
          return files.some(function(f) {
            var ext = (f.name || '').split('.').pop().toLowerCase();
            // matchFileType logic simplified for backend or reuse helper if available
            var videoExts = ['mp4', 'webm', 'ogg', 'mov', 'avi', 'mkv', 'wmv', 'm4v'];
            var audioExts = ['mp3', 'wav', 'ogg', 'aac', 'm4a', 'flac'];
            var imgExts = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp'];
            var docExts = ['doc', 'docx', 'txt', 'csv'];
            var xlsExts = ['xls', 'xlsx'];
            var pptExts = ['ppt', 'pptx'];
            
            if (filters.fileType === 'pdf') return ext === 'pdf';
            if (filters.fileType === 'doc') return docExts.indexOf(ext) !== -1;
            if (filters.fileType === 'xls') return xlsExts.indexOf(ext) !== -1;
            if (filters.fileType === 'ppt') return pptExts.indexOf(ext) !== -1;
            if (filters.fileType === 'image') return imgExts.indexOf(ext) !== -1;
            if (filters.fileType === 'video') return videoExts.indexOf(ext) !== -1;
            return false;
          });
        } catch (e) { return false; }
      });
    }

    // ✅ #13 Advanced Search: filter สถานะ
    if (filters.status) {
      documents = documents.filter(function(doc) {
        switch (filters.status) {
          case 'has-file': return doc.file_objects_json && doc.file_objects_json !== '[]' && doc.file_objects_json !== '';
          case 'no-file': return !doc.file_objects_json || doc.file_objects_json === '[]' || doc.file_objects_json === '';
          case 'has-note': return doc.description && doc.description.trim().length > 0;
          case 'no-note': return !doc.description || doc.description.trim().length === 0;
          default: return true;
        }
      });
    }

    // ✅ #13 Advanced Search: filter ช่วงวันที่
    if (filters.dateFrom) {
      var from = new Date(filters.dateFrom).getTime();
      documents = documents.filter(function(d) { return (d._raw_doc_date || d._raw_created) >= from; });
    }
    if (filters.dateTo) {
      var to = new Date(filters.dateTo);
      to.setHours(23, 59, 59, 999);
      documents = documents.filter(function(d) { return (d._raw_doc_date || d._raw_created) <= to.getTime(); });
    }

    documents.sort(function(a, b) {
      var av = a._raw_created || 0;
      var bv = b._raw_created || 0;
      return sortOrder === 'asc' ? av - bv : bv - av;
    });

    var totalDocs = documents.length;
    var totalPages = Math.ceil(totalDocs / pageSize) || 1;
    var startIndex = (page - 1) * pageSize;
    var paged = documents.slice(startIndex, startIndex + pageSize);

    var pagedData = paged.map(function(d) {
      var clone = Object.assign({}, d);
      delete clone._raw_created;
      return clone;
    });

    return {
      success: true,
      data: pagedData,
      total: totalDocs,
      page: page,
      pageSize: pageSize,
      totalPages: totalPages,
      hasNext: page < totalPages,
      hasPrev: page > 1
    };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

function getDocumentById(id) {
  try {
    var docs = _getAllDocumentsCached_();
    var doc = docs.find(function(d) { return String(d.id) === String(id); });
    
    if (!doc) return { success: false, error: 'Document not found' };
    
    var clone = JSON.parse(JSON.stringify(doc));
    delete clone._raw_created;
    return { success: true, data: clone };
  } catch (e) {
    return { success: false, error: e.toString() };
  }
}

function getStatistics() {
  try {
    var docs = _getAllDocumentsCached_();
    var categories = new Set(docs.map(function(d) { return (d.category || '').trim(); }).filter(Boolean));
    var submitters = new Set(docs.map(function(d) { return (d.submitter_name || '').toString().trim().toLowerCase(); }).filter(Boolean));
    var todayStr = _formatDateTH(new Date(), true);
    var todayDocs = docs.filter(function(d) { return (d.timestamp || '').startsWith(todayStr) || d.document_date === todayStr; }).length;

    return {
      success: true,
      data: {
        totalDocs: docs.length,
        todayDocs: todayDocs,
        categoriesCount: categories.size,
        submittersCount: submitters.size
      }
    };
  } catch (e) {
    return { success: false, error: e.toString() };
  }
}

function getSubmitters() {
  try {
    var config = getSchoolConfig();
    var ss = SpreadsheetApp.openById(config.spreadsheetId);
    var sheet = ss.getSheetByName(SUBMITTERS_SHEET_NAME);
    if (!sheet) return { success: true, data: [] };

    var data = sheet.getDataRange().getValues();
    var submitters = [];
    for (var i = 1; i < data.length; i++) {
      if (data[i][0]) {
        submitters.push({
          displayName: String(data[i][0]),
          position: String(data[i][1] || '')
        });
      }
    }
    return { success: true, data: submitters };
  } catch (e) {
    return { success: false, error: e.toString() };
  }
}

// ===================================================================
// ✍️ CRUD OPERATIONS
// ===================================================================

function addDocument(data) {
  try {
    var sheet = _getSheetSafe_();
    var headers = sheet.getRange(1, 1, 1, sheet.getLastColumn()).getValues()[0];
    var map = _getColIndexMap_(headers);
    var row = new Array(headers.length).fill('');

    var setVal = function(key, val) { if (map[key] !== undefined) row[map[key]] = val; };

    // ✅ #15 สร้าง DocID อัตโนมัติ
    var newDocId = Utilities.getUuid();
    setVal('DocID', newDocId);
    setVal('ประทับเวลา', new Date());
    setVal('ชื่อเอกสาร', data.title);
    setVal('หมวดหมู่', data.category);
    setVal('ประเภทเอกสาร', data.document_type);
    setVal('วันที่เอกสาร', data.document_date ? new Date(data.document_date) : new Date());
    setVal('ผู้ส่ง', data.submitter_name);
    setVal('แท็ก', data.tags);
    setVal('หมายเหตุ', data.description);
    setVal('อัปโหลดไฟล์', data.file_objects_json);

    sheet.appendRow(row);
    _invalidateDocsCache_();

    // ✅ #8 Audit Log
    saveAuditLog_('เพิ่มเอกสาร', { title: data.title, category: data.category, docId: newDocId }, data.submitter_name || 'ไม่ระบุ');

    // ✅ #10 LINE Notify
    try { sendLineNotify_('📄 เอกสารใหม่: ' + (data.title || '') + ' | หมวด: ' + (data.category || '') + ' | ผู้ส่ง: ' + (data.submitter_name || '')); } catch(lineErr) {}

    return { success: true, message: 'Saved successfully', docId: newDocId };
  } catch (e) {
    return { success: false, error: e.toString() };
  }
}

function updateDocument(id, data) {
  try {
    var sheet = _getSheetSafe_();
    var rowIndex = parseInt(id) + 2;
    
    // ตรวจสอบว่า row ยังอยู่ในขอบเขต
    if (rowIndex < 2 || rowIndex > sheet.getLastRow()) {
      return { success: false, error: 'ไม่พบเอกสาร ID: ' + id };
    }
    
    var headers = sheet.getRange(1, 1, 1, sheet.getLastColumn()).getValues()[0];
    var map = _getColIndexMap_(headers);

    var setVal = function(key, val) {
      if (map[key] !== undefined && val !== undefined) {
        sheet.getRange(rowIndex, map[key] + 1).setValue(val);
      }
    };

    // ✅ ใช้ !== undefined แทน if (data.field) เพื่อรองรับค่าว่าง
    if (data.title !== undefined) setVal('ชื่อเอกสาร', data.title);
    if (data.category !== undefined) setVal('หมวดหมู่', data.category);
    if (data.document_type !== undefined) setVal('ประเภทเอกสาร', data.document_type);
    
    // ✅ แก้ date: แปลงเป็น Date object ถ้ามีค่า, เป็นว่างถ้าไม่มี
    if (data.document_date !== undefined) {
      var dateVal = data.document_date ? new Date(data.document_date) : '';
      setVal('วันที่เอกสาร', dateVal);
    }
    
    if (data.submitter_name !== undefined) setVal('ผู้ส่ง', data.submitter_name);
    if (data.tags !== undefined) setVal('แท็ก', data.tags);
    if (data.description !== undefined) setVal('หมายเหตุ', data.description);
    
    // ✅ ใหม่: รองรับแก้ไขไฟล์แนบ
    if (data.file_objects_json !== undefined) setVal('อัปโหลดไฟล์', data.file_objects_json);

    _invalidateDocsCache_();

    // ✅ #8 Audit Log
    saveAuditLog_('แก้ไขเอกสาร', { id: id, title: data.title || '(ไม่ระบุ)' }, 'admin');

    return { success: true, message: 'อัปเดตเรียบร้อย' };
  } catch (e) {
    Logger.log('updateDocument error: ' + e.toString());
    return { success: false, error: e.toString() };
  }
}

/**
 * ✅ [MODIFIED] ลบเอกสาร - ใช้ token แทน password
 */
function deleteDocumentWithToken(id, token) {
  try {
    // ตรวจสอบ token
    var authResult = verifyAuthToken(token);
    if (!authResult.valid) {
      return { success: false, error: '❌ กรุณาเข้าสู่ระบบใหม่', reason: authResult.reason };
    }

    var sheet = _getSheetSafe_();
    var rowIndex = parseInt(id) + 2; 
    
    var docTitle = 'ไม่ระบุ', docCategory = 'ไม่ระบุ', docSubmitter = 'ไม่ระบุ';
    
    try {
      var lastCol = sheet.getLastColumn();
      var headers = sheet.getRange(1, 1, 1, lastCol).getValues()[0];
      var rowData = sheet.getRange(rowIndex, 1, 1, lastCol).getValues()[0];
      var map = _getColIndexMap_(headers);
      
      docTitle = _getValue_(rowData, map, ['ชื่อเอกสาร', 'Title', 'Document Title']);
      docCategory = _getValue_(rowData, map, ['หมวดหมู่', 'Category']);
      docSubmitter = _getValue_(rowData, map, ['ผู้ส่ง', 'Submitter', 'Name']);
    } catch(err) {
      Logger.log('Warning reading row data for log: ' + err);
    }

    // ✅ บันทึก Log ด้วย username จาก token แทน Session.getActiveUser()
    saveDeleteLog_({
      id: id,
      title: docTitle,
      category: docCategory,
      submitter: docSubmitter,
      deleter: authResult.username || 'admin'  // ✅ ใช้ username จาก token
    });

    // ✅ #8 Audit Log
    saveAuditLog_('ลบเอกสาร', { id: id, title: docTitle, category: docCategory }, authResult.username || 'admin');

    sheet.deleteRow(rowIndex);
    _invalidateDocsCache_();
    
    return { success: true, message: '✅ ลบเอกสารและบันทึกประวัติเรียบร้อย' };

  } catch (e) {
    return { success: false, error: e.toString() };
  }
}

/**
 * ✅ [LEGACY SUPPORT] ลบเอกสารด้วยรหัสผ่าน (backward compatible)
 */
function deleteDocumentWithPassword(id, password) {
  try {
    if ((password || '').toString().trim() !== ADMIN_PASSWORD) {
      return { success: false, error: '❌ รหัสผ่านไม่ถูกต้อง' };
    }

    var sheet = _getSheetSafe_();
    var rowIndex = parseInt(id) + 2; 
    
    var docTitle = 'ไม่ระบุ', docCategory = 'ไม่ระบุ', docSubmitter = 'ไม่ระบุ';
    
    try {
      var lastCol = sheet.getLastColumn();
      var headers = sheet.getRange(1, 1, 1, lastCol).getValues()[0];
      var rowData = sheet.getRange(rowIndex, 1, 1, lastCol).getValues()[0];
      var map = _getColIndexMap_(headers);
      
      docTitle = _getValue_(rowData, map, ['ชื่อเอกสาร', 'Title', 'Document Title']);
      docCategory = _getValue_(rowData, map, ['หมวดหมู่', 'Category']);
      docSubmitter = _getValue_(rowData, map, ['ผู้ส่ง', 'Submitter', 'Name']);
    } catch(err) {
      Logger.log('Warning reading row data for log: ' + err);
    }

    saveDeleteLog_({
      id: id,
      title: docTitle,
      category: docCategory,
      submitter: docSubmitter,
      deleter: 'Admin (password)'  // ✅ ไม่ใช้ Session.getActiveUser()
    });

    sheet.deleteRow(rowIndex);
    _invalidateDocsCache_();
    
    return { success: true, message: '✅ ลบเอกสารและบันทึกประวัติเรียบร้อย' };

  } catch (e) {
    return { success: false, error: e.toString() };
  }
}

function deleteDocument(id) {
  return deleteDocumentWithPassword(id, ADMIN_PASSWORD);
}

/**
 * 📝 ฟังก์ชันช่วยบันทึกประวัติการลบ
 */
function saveDeleteLog_(data) {
  try {
    var ssId = getMasterSpreadsheetId_();
    var ss = SpreadsheetApp.openById(ssId);
    var logSheet = ss.getSheetByName(DELETE_LOG_SHEET_NAME);
    
    if (!logSheet) {
      logSheet = ss.insertSheet(DELETE_LOG_SHEET_NAME);
      logSheet.appendRow(['วันเวลาที่ลบ', 'ID เอกสาร', 'ชื่อเอกสาร', 'หมวดหมู่', 'ผู้ส่งเดิม', 'ผู้สั่งลบ (Admin)']);
      logSheet.getRange(1, 1, 1, 6).setFontWeight('bold').setBackground('#fce8e6').setFontColor('#c0392b');
      logSheet.setColumnWidth(1, 150);
      logSheet.setColumnWidth(3, 250);
    }
    
    logSheet.appendRow([
      new Date(),
      data.id,
      data.title,
      data.category,
      data.submitter,
      data.deleter || 'Admin'
    ]);
  } catch (e) {
    Logger.log('Error saving delete log: ' + e);
  }
}

// ===================================================================
// ☁️ DRIVE & UPLOAD
// ===================================================================

function uploadSchoolLogo(base64Data, mimeType, fileName) {
  try {
    if (!base64Data) return { success: false, error: 'No data' };
    
    var config = getSchoolConfig();
    var blob = Utilities.newBlob(Utilities.base64Decode(base64Data), mimeType, fileName || 'logo.png');
    
    var folder = getSystemRootFolder();
    
    if (config.logoFileId) {
      try { DriveApp.getFileById(config.logoFileId).setTrashed(true); } catch (e) {}
    }
    
    var file = folder.createFile(blob);
    file.setName('school_logo_' + new Date().getTime() + getExtension(mimeType));
    try { file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW); } catch (shareErr) { Logger.log('⚠️ setSharing failed: ' + shareErr); }
    
    var newFileId = file.getId();
    config.logoFileId = newFileId;
    saveSchoolConfig(config);
    
    return { success: true, fileId: newFileId, fileUrl: file.getUrl() };
  } catch (e) {
    return { success: false, error: e.toString() };
  }
}

function uploadSchoolLogoSecured(token, base64Data, mimeType, fileName) {
  return requireAuth_(token, function(username) {
    if (username !== 'admin') {
      return { success: false, error: 'FORBIDDEN', message: 'ไม่มีสิทธิ์' };
    }
    return uploadSchoolLogo(base64Data, mimeType, fileName);
  });
}

function serveSchoolLogo() {
  try {
    var config = getSchoolConfig();
    if (!config.logoFileId) return { success: false, noLogo: true };
    var file = DriveApp.getFileById(config.logoFileId);
    var blob = file.getBlob();
    return {
      success: true,
      data: Utilities.base64Encode(blob.getBytes()),
      mimeType: blob.getContentType(),
      name: file.getName()
    };
  } catch (e) {
    return { success: false, error: e.toString() };
  }
}

function removeSchoolLogo() {
  try {
    var config = getSchoolConfig();
    if (config.logoFileId) {
      try { DriveApp.getFileById(config.logoFileId).setTrashed(true); } catch (e) {}
    }
    config.logoFileId = '';
    saveSchoolConfig(config);
    return { success: true };
  } catch (e) {
    return { success: false, error: e.toString() };
  }
}

function removeSchoolLogoSecured(token) {
  return requireAuth_(token, function(username) {
    if (username !== 'admin') {
      return { success: false, error: 'FORBIDDEN', message: 'ไม่มีสิทธิ์' };
    }
    return removeSchoolLogo();
  });
}

function uploadMultipleFilesFromUrls(data) {
  var results = [];
  var items = Array.isArray(data) ? data : [];

  items.forEach(function(item) {
    var url = (typeof item === 'object') ? item.url : item;
    var category = (typeof item === 'object') ? item.category : 'Uncategorized';
    
    if (!url) return;

    try {
      var extractedFileName = extractFileNameFromUrl(url);
      
      if (url.includes('drive.google.com')) {
        var driveFileId = extractGoogleDriveId(url);
        var driveFileName = extractedFileName || 'Google Drive File';
        
        if (driveFileId) {
          try {
            var driveFile = DriveApp.getFileById(driveFileId);
            driveFileName = driveFile.getName();
          } catch (e) {
            Logger.log('Cannot access Drive file: ' + e);
          }
        }
        
        results.push({ 
          success: true, 
          isLink: true, 
          fileUrl: url, 
          previewUrl: url,
          fileName: driveFileName,
          originalUrl: url
        });
        return;
      }
      
      var res = UrlFetchApp.fetch(url, { 
        muteHttpExceptions: true,
        followRedirects: true
      });
      
      if (res.getResponseCode() === 200) {
        var folder = getOrCreateCategoryFolder(category);
        var blob = res.getBlob();
        
        var finalFileName = blob.getName();
        if (!finalFileName || finalFileName === 'Blob' || finalFileName === 'blob') {
          finalFileName = extractedFileName || 'Downloaded_File_' + new Date().getTime();
        }
        
        blob.setName(finalFileName);
        
        var file = folder.createFile(blob);
        try { file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW); } catch (shareErr) { Logger.log('⚠️ setSharing failed: ' + shareErr); }
        
        results.push({ 
          success: true, 
          fileUrl: file.getUrl(), 
          previewUrl: file.getUrl(),
          fileName: file.getName(),
          mimeType: file.getMimeType(),
          originalUrl: url
        });
      } else {
        results.push({ 
          success: true, 
          isLink: true, 
          fileUrl: url, 
          previewUrl: url,
          fileName: extractedFileName || 'External Link',
          originalUrl: url
        });
      }
      
    } catch (e) {
      Logger.log('Error processing URL: ' + url + ' - ' + e);
      results.push({ 
        success: true, 
        isLink: true, 
        fileUrl: url, 
        previewUrl: url,
        fileName: extractFileNameFromUrl(url) || 'Link',
        originalUrl: url
      });
    }
  });

  return { success: true, data: results };
}

// ===================================================================
// 📤 CHUNKED FILE UPLOAD (สำหรับไฟล์ขนาดใหญ่)
// ===================================================================

/**
 * ⭐ เริ่มต้น Chunked Upload — สร้าง Drive API Resumable Upload Session โดยตรง (ไม่ใช้ temp folder)
 * @param {string} fileName - ชื่อไฟล์
 * @param {number} totalChunksOrSize - จำนวน chunks (legacy) หรือขนาดไฟล์ bytes (new)
 * @param {string} mimeType - MIME Type
 * @param {string} category - หมวดหมู่
 * @param {number} totalSize - ขนาดไฟล์ bytes (new parameter)
 * @returns {Object} - {success, uploadId, uploadUrl}
 */
function startChunkedUpload(fileName, totalChunksOrSize, mimeType, category, totalSize) {
  try {
    // totalSize มาจาก param ใหม่ หรือจาก totalChunksOrSize (ถ้า client ใหม่ส่ง totalBytes เป็น param 2)
    var fileSize = totalSize || totalChunksOrSize;
    var contentType = mimeType || 'application/octet-stream';
    var uploadId = 'upload_' + Date.now() + '_' + Math.random().toString(36).substring(2, 8);
    
    Logger.log('📤 startChunkedUpload: ' + fileName + ' (' + fileSize + ' bytes)');
    
    var destFolder = getOrCreateCategoryFolder(category || 'งานทั่วไป');
    var token = ScriptApp.getOAuthToken();
    
    // ⭐ สร้าง Drive API Resumable Upload Session
    var initRes = UrlFetchApp.fetch(
      'https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable',
      {
        method: 'post',
        contentType: 'application/json',
        headers: {
          'Authorization': 'Bearer ' + token,
          'X-Upload-Content-Type': contentType,
          'X-Upload-Content-Length': String(fileSize)
        },
        payload: JSON.stringify({
          name: fileName,
          parents: [destFolder.getId()]
        }),
        muteHttpExceptions: true
      }
    );
    
    if (initRes.getResponseCode() !== 200) {
      throw new Error('Drive API init failed (HTTP ' + initRes.getResponseCode() + '): ' + initRes.getContentText());
    }
    
    // ดึง Upload URL จาก Location header
    var resHeaders = initRes.getHeaders();
    var uploadUrl = null;
    for (var hk in resHeaders) {
      if (hk.toLowerCase() === 'location') { uploadUrl = resHeaders[hk]; break; }
    }
    if (!uploadUrl) throw new Error('No upload URL from Drive API');
    
    // เก็บ metadata สำหรับ cleanup
    PropertiesService.getScriptProperties().setProperty('UPLOAD_' + uploadId, JSON.stringify({
      uploadId: uploadId, fileName: fileName, mimeType: contentType,
      category: category, totalSize: fileSize, uploadUrl: uploadUrl, createdAt: Date.now()
    }));
    
    return { success: true, uploadId: uploadId, uploadUrl: uploadUrl };
  } catch (error) {
    Logger.log('❌ startChunkedUpload Error: ' + error.toString());
    return { success: false, error: error.toString() };
  }
}

/**
 * ⭐ อัปโหลด chunk ตรงไป Drive API (ไม่ผ่าน temp folder!)
 * @param {string} uploadId - ID จาก startChunkedUpload
 * @param {number} chunkIndex - ลำดับ chunk (0-based)
 * @param {string} chunkData - Base64 data ของ chunk นี้
 * @param {string} uploadUrl - Drive API resumable upload URL
 * @param {number} offset - byte offset ของ chunk นี้
 * @param {number} totalSize - ขนาดไฟล์ทั้งหมด bytes
 * @returns {Object} - {success, chunkIndex, status, ...fileInfo}
 */
function uploadChunk(uploadId, chunkIndex, chunkData, uploadUrl, offset, totalSize) {
  try {
    // ลบ data URL prefix ถ้ามี
    var base64 = chunkData;
    if (base64.indexOf(',') > -1) {
      base64 = base64.split(',')[1];
    }
    
    var chunkBytes = Utilities.base64Decode(base64);
    var chunkLen = chunkBytes.length;
    var rangeEnd = offset + chunkLen - 1;
    
    // ⭐ ส่งตรงไป Drive API!
    var putRes = UrlFetchApp.fetch(uploadUrl, {
      method: 'put',
      headers: { 'Content-Range': 'bytes ' + offset + '-' + rangeEnd + '/' + totalSize },
      payload: chunkBytes,
      muteHttpExceptions: true
    });
    
    var httpCode = putRes.getResponseCode();
    chunkBytes = null; // ช่วย GC
    
    if (httpCode === 308) {
      // ยังไม่เสร็จ ต้องส่ง chunk ต่อ
      return { success: true, chunkIndex: chunkIndex, status: 'incomplete' };
    } else if (httpCode === 200 || httpCode === 201) {
      // ⭐ อัปโหลดเสร็จ! ตั้งค่า sharing + cleanup
      var fileInfo = JSON.parse(putRes.getContentText());
      var finalFile = DriveApp.getFileById(fileInfo.id);
      try { finalFile.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW); } catch (shareErr) { Logger.log('⚠️ setSharing failed: ' + shareErr); }
      
      PropertiesService.getScriptProperties().deleteProperty('UPLOAD_' + uploadId);
      Logger.log('✅ Chunked upload complete: ' + fileInfo.name + ' (' + totalSize + ' bytes)');
      
      return {
        success: true, chunkIndex: chunkIndex, status: 'complete',
        fileUrl: finalFile.getUrl(), fileId: finalFile.getId(),
        fileName: finalFile.getName(), mimeType: finalFile.getMimeType(), size: totalSize
      };
    } else {
      throw new Error('Drive API HTTP ' + httpCode + ': ' + putRes.getContentText());
    }
  } catch (error) {
    Logger.log('❌ uploadChunk Error: ' + error.toString());
    return { success: false, error: error.toString(), chunkIndex: chunkIndex };
  }
}

/**
 * ⭐ Cleanup metadata (backward compat — ใน flow ใหม่ chunk สุดท้ายจะ complete เอง)
 */
function finishChunkedUpload(uploadId) {
  try {
    PropertiesService.getScriptProperties().deleteProperty('UPLOAD_' + uploadId);
    return { success: true };
  } catch (error) {
    return { success: false, error: error.toString() };
  }
}

/**
 * ⭐ ลบ temp upload ที่ค้างอยู่ (เรียกใช้เพื่อ cleanup)
 */
function cleanupStaleUploads() {
  try {
    var props = PropertiesService.getScriptProperties();
    var allProps = props.getProperties();
    var now = Date.now();
    var cleaned = 0;
    
    for (var key in allProps) {
      if (key.indexOf('UPLOAD_') === 0) {
        try {
          var meta = JSON.parse(allProps[key]);
          // ลบ upload ที่เก่ากว่า 1 ชั่วโมง
          if (now - meta.createdAt > 3600000) {
            props.deleteProperty(key);
            cleaned++;
          }
        } catch (e) {
          props.deleteProperty(key);
          cleaned++;
        }
      }
    }
    
    Logger.log('🧹 Cleaned up ' + cleaned + ' stale uploads');
    return { success: true, cleaned: cleaned };
  } catch (error) {
    return { success: false, error: error.toString() };
  }
}

// ===================================================================
// 📤 SINGLE FILE UPLOAD (สำหรับ Batch Upload)
// ===================================================================

/**
 * ⭐ อัปโหลดไฟล์เดี่ยว (รองรับการอัปโหลดแบบ Batch)
 * @param {string} fileData - Base64 Data URL (data:image/png;base64,...)
 * @param {string} fileName - ชื่อไฟล์
 * @param {string} mimeType - MIME Type (image/png, application/pdf, etc.)
 * @param {string} category - หมวดหมู่เอกสาร
 * @returns {Object} - {success, fileUrl, fileId, fileName, mimeType, size}
 */
function uploadSingleFile(fileData, fileName, mimeType, category) {
  try {
    Logger.log('📤 uploadSingleFile: ' + fileName);
    
    // ตรวจสอบข้อมูล
    if (!fileData) {
      return { success: false, error: 'ไม่มีข้อมูลไฟล์' };
    }
    
    // ลบ data URL prefix (data:image/png;base64,...)
    var base64Data = fileData;
    if (fileData.indexOf(',') > -1) {
      base64Data = fileData.split(',')[1];
    }
    
    // แปลง Base64 เป็น Blob
    var blob = Utilities.newBlob(
      Utilities.base64Decode(base64Data),
      mimeType || 'application/octet-stream',
      fileName
    );
    
    // หาโฟลเดอร์ตามหมวดหมู่
    var folder = getOrCreateCategoryFolder(category || 'งานทั่วไป');
    
    // อัปโหลดไฟล์
    var file = folder.createFile(blob);
    
    // ตั้งค่าสิทธิ์ให้ทุกคนดูได้ (อ่านอย่างเดียว)
    try { file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW); } catch (shareErr) { Logger.log('⚠️ setSharing failed: ' + shareErr); }
    
    Logger.log('✅ อัปโหลดสำเร็จ: ' + fileName);
    
    return {
      success: true,
      fileUrl: file.getUrl(),
      fileId: file.getId(),
      fileName: file.getName(),
      mimeType: file.getMimeType(),
      size: file.getSize()
    };
    
  } catch (error) {
    Logger.log('❌ uploadSingleFile Error: ' + error.toString());
    return {
      success: false,
      error: error.toString(),
      fileName: fileName
    };
  }
}

function extractFileNameFromUrl(url) {
  if (!url) return '';
  
  try {
    var urlWithoutQuery = url.split('?')[0];
    urlWithoutQuery = urlWithoutQuery.split('#')[0];
    var parts = urlWithoutQuery.split('/');
    var lastPart = parts[parts.length - 1];
    var decoded = decodeURIComponent(lastPart);
    
    if (decoded && decoded.includes('.')) {
      return decoded;
    }
    
    return '';
  } catch (e) {
    Logger.log('Error extracting filename: ' + e);
    return '';
  }
}

function extractGoogleDriveId(url) {
  if (!url) return null;
  
  try {
    var match1 = url.match(/\/d\/([a-zA-Z0-9_-]+)/);
    if (match1 && match1[1]) return match1[1];
    
    var match2 = url.match(/[?&]id=([a-zA-Z0-9_-]+)/);
    if (match2 && match2[1]) return match2[1];
    
    var match3 = url.match(/\/file\/d\/([a-zA-Z0-9_-]+)/);
    if (match3 && match3[1]) return match3[1];
    
    return null;
  } catch (e) {
    Logger.log('Error extracting Drive ID: ' + e);
    return null;
  }
}

function getOrCreateCategoryFolder(categoryName) {
  var root = getSystemRootFolder();
  var name = categoryName || 'Uncategorized';
  var folders = root.getFoldersByName(name);
  if (folders.hasNext()) return folders.next();
  return root.createFolder(name);
}

/**
 * ⭐ ดึงโฟลเดอร์หลักจาก config.folderId
 * ถ้าเข้าถึงไม่ได้ (ลบไปแล้ว, ไม่มีสิทธิ์) ให้สร้างใหม่ใน My Drive ยืนยันว่าไม่พัง
 */
function getSystemRootFolder() {
  var config = getSchoolConfig();
  var folderId = config.folderId || DEFAULT_CONFIG.folderId;
  
  if (folderId) {
    try {
      var folder = DriveApp.getFolderById(folderId);
      if (folder.isTrashed()) {
        folder.setTrashed(false);
      }
      return folder;
    } catch (e) {
      Logger.log('⚠️ ไม่สามารถเข้าถึง Folder ID: ' + folderId + ' (' + e.toString() + ')');
    }
  }
  
  var folderName = config.schoolName ? (config.schoolName + ' - ข้อมูลระบบ') : 'SchoolData_System';
  var newFolder = DriveApp.createFolder(folderName);
  var newId = newFolder.getId();
  
  config.folderId = newId;
  saveSchoolConfig(config);
  
  Logger.log('✅ สร้างโฟลเดอร์หลักใหม่แล้ว: ' + newId);
  return newFolder;
}

function uploadFile(data, name, type, category) {
  try {
    var folder = getOrCreateCategoryFolder(category);
    var blob = Utilities.newBlob(Utilities.base64Decode(data.split(',')[1]), type, name);
    var file = folder.createFile(blob);
    try { file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW); } catch (shareErr) { Logger.log('⚠️ setSharing failed: ' + shareErr); }
    return { success: true, fileUrl: file.getUrl(), fileName: file.getName(), mimeType: file.getMimeType() };
  } catch (e) {
    return { success: false, error: e.toString() };
  }
}

function testSpreadsheetConnection(spreadsheetId, sheetName) {
  try {
    var ss = SpreadsheetApp.openById(spreadsheetId);
    var sheet = ss.getSheetByName(sheetName);
    
    if (!sheet) {
      return {
        success: false,
        error: 'ไม่พบ Sheet "' + sheetName + '"',
        availableSheets: ss.getSheets().map(function(s) { return s.getName(); })
      };
    }
    
    return {
      success: true,
      details: {
        spreadsheetName: ss.getName(),
        sheetName: sheet.getName(),
        rows: sheet.getLastRow(),
        columns: sheet.getLastColumn()
      }
    };
  } catch (e) {
    return { success: false, error: e.toString() };
  }
}

function testFolderConnection(folderId) {
  try {
    var folder = DriveApp.getFolderById(folderId);
    return {
      success: true,
      details: { folderName: folder.getName() }
    };
  } catch (e) {
    return { success: false, error: e.toString() };
  }
}

// ===================================================================
// 🛠️ UTILITIES
// ===================================================================

/**
 * ✅ [FIXED] ดึงข้อมูล user - รองรับทั้ง token และไม่มี token
 */
function getCurrentUser(token) {
  // ✅ ถ้ามี token ให้ตรวจสอบ
  if (token) {
    var authResult = verifyAuthToken(token);
    if (authResult.valid) {
      return { 
        success: true,  // ← เพิ่ม success flag
        email: authResult.username, 
        username: authResult.username,
        isAdmin: true 
      };
    }
  }
  
  // ✅ [FALLBACK] ถ้าไม่มี token → ให้สิทธิ์ Admin ไปก่อน
  // (เพื่อความ backward compatible กับระบบเก่า)
  return { 
    success: true,  // ← เพิ่ม success flag
    email: 'admin@local', 
    username: 'admin',
    isAdmin: true  // ← ให้ true เพื่อให้ปุ่มลบแสดง
  };
}

/**
 * ✅ [REMOVED] ไม่ใช้ Session.getActiveUser() อีกต่อไป
 * ฟังก์ชันเดิม:
 * function getCurrentUser() {
 *   return { email: Session.getActiveUser().getEmail(), isAdmin: true };
 * }
 */

function openGoogleForm() {
  return getSchoolConfig().googleFormUrl || '';
}

function _formatDateTH(dateObj, dateOnly) {
  if (!dateObj) return '';
  if (!(dateObj instanceof Date)) dateObj = new Date(dateObj);
  if (isNaN(dateObj.getTime())) return '';
  var options = { year: 'numeric', month: 'long', day: 'numeric', timeZone: 'Asia/Bangkok' };
  if (!dateOnly) { options.hour = '2-digit'; options.minute = '2-digit'; }
  return dateObj.toLocaleDateString('th-TH', options);
}

function _parseDate(val) {
  if (val instanceof Date) return val;
  if (!val) return new Date(0);
  return new Date(val);
}

function getExtension(mimeType) {
  var map = {
    'image/png': '.png',
    'image/jpeg': '.jpg',
    'image/gif': '.gif',
    'image/webp': '.webp'
  };
  return map[mimeType] || '.png';
}

// ===================================================================
// 📥 FILE DOWNLOAD SYSTEM
// ===================================================================

/**
 * ⭐ ตั้งค่าสิทธิ์ไฟล์ให้ใครก็เข้าถึงได้ (อ่านอย่างเดียว) แล้วคืน download URL
 * @param {string} fileId - Google Drive File ID
 * @returns {Object} - {success, downloadUrl, fileName, mimeType, size}
 */
function ensureFileAccess(fileId) {
  try {
    if (!fileId) return { success: false, error: 'ไม่ได้ระบุ File ID' };
    
    var file = DriveApp.getFileById(fileId);
    
    // ✅ ตั้งค่าให้ใครก็เข้าถึงได้ (ทุกครั้ง เพื่อความแน่นอน)
    try {
      file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);
    } catch (shareErr) {
      Logger.log('⚠️ ไม่สามารถตั้งค่า sharing: ' + shareErr.toString());
    }
    
    var downloadUrl = 'https://drive.google.com/uc?export=download&id=' + fileId;
    
    return {
      success: true,
      downloadUrl: downloadUrl,
      fileName: file.getName(),
      mimeType: file.getMimeType(),
      size: file.getSize()
    };
  } catch (e) {
    Logger.log('❌ ensureFileAccess Error: ' + e.toString());
    return { success: false, error: e.toString() };
  }
}

/**
 * ⭐ สร้าง Direct Download URL จาก Google Drive File ID (+ ตั้งค่าสิทธิ์อัตโนมัติ)
 * @param {string} fileId - Google Drive File ID
 * @returns {Object} - {success, downloadUrl, fileName, mimeType, size}
 */
function getFileDownloadUrl(fileId) {
  return ensureFileAccess(fileId);
}

/**
 * ⭐ ดาวน์โหลดไฟล์เป็น Base64 (สำหรับไฟล์ขนาดเล็ก < 10MB)
 * @param {string} fileId - Google Drive File ID
 * @returns {Object} - {success, base64, fileName, mimeType, size}
 */
function getFileAsBase64(fileId) {
  try {
    if (!fileId) return { success: false, error: 'ไม่ได้ระบุ File ID' };
    
    var file = DriveApp.getFileById(fileId);
    var size = file.getSize();
    
    // ตั้งค่าสิทธิ์ก่อน
    try {
      file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);
    } catch (shareErr) {}
    
    // จำกัดขนาด 10MB
    if (size > 10 * 1024 * 1024) {
      return {
        success: false,
        error: 'ไฟล์ใหญ่เกิน 10MB กรุณาใช้ลิงก์ดาวน์โหลดตรง',
        downloadUrl: 'https://drive.google.com/uc?export=download&id=' + fileId,
        fileName: file.getName(),
        size: size
      };
    }
    
    var blob = file.getBlob();
    var base64 = Utilities.base64Encode(blob.getBytes());
    
    return {
      success: true,
      base64: base64,
      fileName: file.getName(),
      mimeType: file.getMimeType(),
      size: size
    };
  } catch (e) {
    Logger.log('❌ getFileAsBase64 Error: ' + e.toString());
    return { success: false, error: e.toString() };
  }
}

/**
 * ⭐ ดาวน์โหลดไฟล์ผ่าน Apps Script (bypass สิทธิ์ Drive)
 * @param {string} fileUrl - Google Drive URL ของไฟล์
 * @returns {Object} - {success, base64, fileName, mimeType, size} หรือ {downloadUrl} สำหรับไฟล์ใหญ่
 */
function serveFileForDownload(fileUrl) {
  try {
    if (!fileUrl) return { success: false, error: 'ไม่ได้ระบุ URL' };
    
    var fileId = extractGoogleDriveId(fileUrl);
    if (!fileId) {
      // ไม่ใช่ Google Drive URL → เปิดตรง
      return { success: true, isExternal: true, downloadUrl: fileUrl };
    }
    
    var file = DriveApp.getFileById(fileId);
    var size = file.getSize();
    var fileName = file.getName();
    var mimeType = file.getMimeType();
    
    // ตั้งค่าสิทธิ์ด้วย (เผื่อ)
    try {
      file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);
    } catch (e) {}
    
    // ไฟล์ใหญ่เกิน 25MB → ส่ง download URL แทน
    if (size > 25 * 1024 * 1024) {
      return {
        success: true,
        isLargeFile: true,
        downloadUrl: 'https://drive.google.com/uc?export=download&id=' + fileId,
        fileName: fileName,
        mimeType: mimeType,
        size: size
      };
    }
    
    // ดึงไฟล์เป็น base64 แล้วส่งกลับ
    var blob = file.getBlob();
    var base64 = Utilities.base64Encode(blob.getBytes());
    
    return {
      success: true,
      base64: base64,
      fileName: fileName,
      mimeType: mimeType,
      size: size
    };
  } catch (e) {
    Logger.log('❌ serveFileForDownload Error: ' + e.toString());
    return { success: false, error: e.toString() };
  }
}

/**
 * ⭐ ดึง Download URLs สำหรับไฟล์ทั้งหมดในเอกสาร
 *   ✅ ตั้งค่าสิทธิ์ ANYONE_WITH_LINK อัตโนมัติทุกไฟล์ก่อนส่ง URL
 * @param {number} docId - Document ID
 * @returns {Object} - {success, files: [{fileName, fileId, downloadUrl, mimeType, size}]}
 */
function getDocumentDownloadLinks(docId) {
  try {
    var result = getDocumentById(docId);
    if (!result.success) return result;
    
    var doc = result.data;
    var files = [];
    
    if (doc.file_objects_json) {
      var parsed = JSON.parse(doc.file_objects_json);
      if (Array.isArray(parsed)) {
        for (var i = 0; i < parsed.length; i++) {
          var f = parsed[i];
          var url = f.url || f.fileUrl || '';
          var fileId = extractGoogleDriveId(url);
          
          if (fileId) {
            try {
              var driveFile = DriveApp.getFileById(fileId);
              
              // ✅ ตั้งค่าสิทธิ์ให้ใครก็เข้าถึงได้
              try {
                driveFile.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);
              } catch (shareErr) {
                Logger.log('⚠️ ตั้งค่าสิทธิ์ไม่ได้สำหรับ: ' + fileId);
              }
              
              files.push({
                fileName: f.name || f.fileName || driveFile.getName(),
                fileId: fileId,
                downloadUrl: 'https://drive.google.com/uc?export=download&id=' + fileId,
                viewUrl: url,
                mimeType: driveFile.getMimeType(),
                size: driveFile.getSize()
              });
            } catch (fileErr) {
              files.push({
                fileName: f.name || f.fileName || 'ไฟล์ที่ ' + (i + 1),
                fileId: fileId,
                downloadUrl: 'https://drive.google.com/uc?export=download&id=' + fileId,
                viewUrl: url,
                error: 'ไม่สามารถเข้าถึงไฟล์ได้'
              });
            }
          } else if (url) {
            files.push({
              fileName: f.name || f.fileName || 'ลิงก์ภายนอก',
              downloadUrl: url,
              viewUrl: url,
              isExternal: true
            });
          }
        }
      }
    }
    
    return {
      success: true,
      data: doc,
      documentTitle: doc.title,
      files: files,
      totalFiles: files.length
    };
  } catch (e) {
    Logger.log('❌ getDocumentDownloadLinks Error: ' + e.toString());
    return { success: false, error: e.toString() };
  }
}

/**
 * ⭐ ตั้งค่าสิทธิ์ไฟล์ทั้งหมดในเอกสารที่ระบุ
 * @param {number} docId - Document ID
 * @returns {Object} - {success, fixed, errors}
 */
function fixDocumentFilePermissions(docId) {
  try {
    var result = getDocumentById(docId);
    if (!result.success) return result;
    
    var doc = result.data;
    var fixed = 0;
    var errors = 0;
    
    if (doc.file_objects_json) {
      var parsed = JSON.parse(doc.file_objects_json);
      if (Array.isArray(parsed)) {
        for (var i = 0; i < parsed.length; i++) {
          var f = parsed[i];
          var url = f.url || f.fileUrl || '';
          var fileId = extractGoogleDriveId(url);
          
          if (fileId) {
            try {
              var driveFile = DriveApp.getFileById(fileId);
              try { driveFile.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW); } catch (shareErr) { Logger.log('⚠️ setSharing failed: ' + shareErr); }
              fixed++;
            } catch (e) {
              errors++;
            }
          }
        }
      }
    }
    
    return { success: true, fixed: fixed, errors: errors };
  } catch (e) {
    return { success: false, error: e.toString() };
  }
}

/**
 * ⭐ ตั้งค่าสิทธิ์ไฟล์ทั้งหมดในระบบ (เรียกครั้งเดียวเพื่อแก้ไฟล์เก่า)
 * @returns {Object} - {success, total, fixed, errors}
 */
function fixAllFilePermissions() {
  try {
    var docs = _getAllDocumentsCached_();
    var total = 0;
    var fixed = 0;
    var errors = 0;
    
    for (var d = 0; d < docs.length; d++) {
      var doc = docs[d];
      if (doc.file_objects_json) {
        try {
          var parsed = JSON.parse(doc.file_objects_json);
          if (Array.isArray(parsed)) {
            for (var i = 0; i < parsed.length; i++) {
              var f = parsed[i];
              var url = f.url || f.fileUrl || '';
              var fileId = extractGoogleDriveId(url);
              
              if (fileId) {
                total++;
                try {
                  var driveFile = DriveApp.getFileById(fileId);
                  try { driveFile.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW); } catch (shareErr) { Logger.log('⚠️ setSharing failed: ' + shareErr); }
                  fixed++;
                } catch (e) {
                  errors++;
                  Logger.log('⚠️ ไม่สามารถตั้งค่าสิทธิ์: ' + fileId + ' - ' + e.toString());
                }
              }
            }
          }
        } catch (parseErr) {}
      }
    }
    
    Logger.log('✅ fixAllFilePermissions: total=' + total + ', fixed=' + fixed + ', errors=' + errors);
    return { success: true, total: total, fixed: fixed, errors: errors };
  } catch (e) {
    Logger.log('❌ fixAllFilePermissions Error: ' + e.toString());
    return { success: false, error: e.toString() };
  }
}

// ===================================================================
// ��️ CACHE MANAGEMENT
// ===================================================================

function clearDocumentCache() {
  try {
    var cache = CacheService.getScriptCache();
    if (cache) {
      cache.remove(DOCS_CACHE_KEY);
      Logger.log('✅ ล้าง Cache สำเร็จ: ' + DOCS_CACHE_KEY);
    }
    return { success: true };
  } catch (e) {
    Logger.log('⚠️ ไม่สามารถล้าง Cache: ' + e.message);
    return { success: false, error: e.message };
  }
}

function clearAllCache() {
  try {
    CacheService.getScriptCache().removeAll([DOCS_CACHE_KEY]);
    Logger.log('✅ ล้าง Cache ทั้งหมดสำเร็จ');
    return { success: true };
  } catch (e) {
    Logger.log('⚠️ Error clearing all cache: ' + e.message);
    return { success: false, error: e.message };
  }
}
// ===================================================================
// 📂 FOLDER UPLOAD SYSTEM (v9.0)
// ===================================================================

/**
 * ⭐ อัปโหลดไฟล์พร้อมสร้างโครงสร้างโฟลเดอร์ตาม Path
 * @param {Object} fileData - ข้อมูลไฟล์ (base64, name, mimeType)
 * @param {string} relativePath - Path เช่น "MyFolder/SubFolder/file.pdf"
 * @param {string} baseFolderId - ID ของโฟลเดอร์หลักที่จะอัปโหลด
 * @returns {Object} - {success, fileUrl, fileName, path}
 */
function uploadFileWithPath(fileData, relativePath, baseFolderId) {
  try {
    // ใช้ค่าเริ่มต้นถ้าไม่ได้ระบุ
    var baseFolder;
    if (baseFolderId) {
      try {
        baseFolder = DriveApp.getFolderById(baseFolderId);
      } catch (e) {
        baseFolder = getSystemRootFolder();
      }
    } else {
      baseFolder = getSystemRootFolder();
    }
    var targetFolder = baseFolder;
    
    // ถ้ามี relativePath ให้สร้างโฟลเดอร์ตามโครงสร้าง
    if (relativePath && relativePath.trim() !== '') {
      var pathParts = relativePath.split('/');
      
      // ลบชื่อไฟล์ออก (element สุดท้าย)
      pathParts.pop();
      
      // สร้างโฟลเดอร์ตาม path
      for (var i = 0; i < pathParts.length; i++) {
        var folderName = pathParts[i].trim();
        
        if (folderName === '') continue;
        
        // ค้นหาโฟลเดอร์ที่มีอยู่แล้ว
        var existingFolders = targetFolder.getFoldersByName(folderName);
        
        if (existingFolders.hasNext()) {
          // ใช้โฟลเดอร์ที่มีอยู่
          targetFolder = existingFolders.next();
        } else {
          // สร้างโฟลเดอร์ใหม่
          targetFolder = targetFolder.createFolder(folderName);
          Logger.log('📁 สร้างโฟลเดอร์: ' + folderName);
        }
      }
    }
    
    // แปลง Base64 เป็น Blob
    var base64Data = fileData.base64;
    
    // ถ้าเป็น DataURL ให้ตัด prefix ออก
    if (base64Data.indexOf(',') > -1) {
      base64Data = base64Data.split(',')[1];
    }
    
    var blob = Utilities.newBlob(
      Utilities.base64Decode(base64Data),
      fileData.mimeType || 'application/octet-stream',
      fileData.name
    );
    
    // อัปโหลดไฟล์
    var file = targetFolder.createFile(blob);
    
    // ตั้งค่าให้ใครก็เข้าถึงได้ (อ่านอย่างเดียว)
    try { file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW); } catch (shareErr) { Logger.log('⚠️ setSharing failed: ' + shareErr); }
    
    Logger.log('✅ อัปโหลดสำเร็จ: ' + fileData.name + ' → ' + (relativePath || 'root'));
    
    return {
      success: true,
      fileUrl: file.getUrl(),
      fileId: file.getId(),
      fileName: fileData.name,
      path: relativePath || '',
      folderId: targetFolder.getId(),
      folderName: targetFolder.getName(),
      mimeType: file.getMimeType()
    };
    
  } catch (error) {
    Logger.log('❌ uploadFileWithPath Error: ' + error.toString());
    return {
      success: false,
      error: error.toString(),
      fileName: fileData ? fileData.name : 'unknown'
    };
  }
}

/**
 * ⭐ อัปโหลดหลายไฟล์พร้อม Path (Batch)
 * @param {Array} filesData - Array ของ {base64, name, mimeType, relativePath}
 * @param {string} baseFolderId - ID ของโฟลเดอร์หลัก
 * @returns {Object} - {success, results, summary}
 */
function uploadFilesWithPath(filesData, baseFolderId) {
  var results = [];
  var successCount = 0;
  var errorCount = 0;
  
  for (var i = 0; i < filesData.length; i++) {
    var fileData = filesData[i];
    var relativePath = fileData.relativePath || '';
    
    var result = uploadFileWithPath(
      {
        base64: fileData.base64,
        name: fileData.name,
        mimeType: fileData.mimeType
      },
      relativePath,
      baseFolderId
    );
    
    results.push(result);
    
    if (result.success) {
      successCount++;
    } else {
      errorCount++;
    }
    
    // Log progress
    Logger.log('📤 Progress: ' + (i + 1) + '/' + filesData.length);
  }
  
  return {
    success: errorCount === 0,
    results: results,
    summary: {
      total: filesData.length,
      success: successCount,
      error: errorCount
    }
  };
}

/**
 * ⭐ อัปโหลดไฟล์เดี่ยวพร้อม Path (สำหรับเรียกจาก Client ทีละไฟล์)
 * @param {string} base64Data - ข้อมูลไฟล์แบบ Base64 หรือ DataURL
 * @param {string} fileName - ชื่อไฟล์
 * @param {string} mimeType - MIME type
 * @param {string} relativePath - Path สัมพัทธ์
 * @param {string} category - หมวดหมู่ (ใช้เป็นโฟลเดอร์ย่อย)
 * @returns {Object}
 */
function uploadSingleFileWithPath(base64Data, fileName, mimeType, relativePath, category) {
  try {
    var baseFolder = getSystemRootFolder();
    var baseFolderId = baseFolder.getId();
    
    // ถ้ามี category ให้สร้างโฟลเดอร์หมวดหมู่ก่อน
    if (category && category.trim() !== '') {
      var catFolders = baseFolder.getFoldersByName(category);
      
      if (catFolders.hasNext()) {
        baseFolderId = catFolders.next().getId();
      } else {
        var newCatFolder = baseFolder.createFolder(category);
        baseFolderId = newCatFolder.getId();
        Logger.log('📁 สร้างโฟลเดอร์หมวดหมู่: ' + category);
      }
    }
    
    return uploadFileWithPath(
      {
        base64: base64Data,
        name: fileName,
        mimeType: mimeType || 'application/octet-stream'
      },
      relativePath,
      baseFolderId
    );
    
  } catch (error) {
    Logger.log('❌ uploadSingleFileWithPath Error: ' + error.toString());
    return {
      success: false,
      error: error.toString(),
      fileName: fileName
    };
  }
}

/**
 * ⭐ ตรวจสอบว่าโฟลเดอร์มีอยู่หรือไม่ ถ้าไม่มีให้สร้าง
 * @param {string} folderName - ชื่อโฟลเดอร์
 * @param {string} parentFolderId - ID ของโฟลเดอร์แม่
 * @returns {Object} - {folderId, folderName, created}
 */
function getOrCreateFolder(folderName, parentFolderId) {
  try {
    var parentFolder;
    if (parentFolderId) {
      try {
        parentFolder = DriveApp.getFolderById(parentFolderId);
      } catch (e) {
        parentFolder = getSystemRootFolder();
      }
    } else {
      parentFolder = getSystemRootFolder();
    }
    
    var existingFolders = parentFolder.getFoldersByName(folderName);
    
    if (existingFolders.hasNext()) {
      var folder = existingFolders.next();
      return {
        success: true,
        folderId: folder.getId(),
        folderName: folder.getName(),
        folderUrl: folder.getUrl(),
        created: false
      };
    } else {
      var newFolder = parentFolder.createFolder(folderName);
      return {
        success: true,
        folderId: newFolder.getId(),
        folderName: newFolder.getName(),
        folderUrl: newFolder.getUrl(),
        created: true
      };
    }
  } catch (error) {
    Logger.log('❌ getOrCreateFolder Error: ' + error.toString());
    return {
      success: false,
      error: error.toString()
    };
  }
}

/**
 * ⭐ สร้างโครงสร้างโฟลเดอร์ตาม Path
 * @param {string} folderPath - Path เช่น "Folder1/Folder2/Folder3"
 * @param {string} baseFolderId - ID โฟลเดอร์หลัก
 * @returns {Object} - {success, folderId, folderPath}
 */
function createFolderStructure(folderPath, baseFolderId) {
  try {
    var currentFolder;
    if (baseFolderId) {
      try {
        currentFolder = DriveApp.getFolderById(baseFolderId);
      } catch (e) {
        currentFolder = getSystemRootFolder();
      }
    } else {
      currentFolder = getSystemRootFolder();
    }
    
    var pathParts = folderPath.split('/').filter(function(p) { return p.trim() !== ''; });
    var createdFolders = [];
    
    for (var i = 0; i < pathParts.length; i++) {
      var folderName = pathParts[i].trim();
      var existingFolders = currentFolder.getFoldersByName(folderName);
      
      if (existingFolders.hasNext()) {
        currentFolder = existingFolders.next();
        createdFolders.push({ name: folderName, created: false });
      } else {
        currentFolder = currentFolder.createFolder(folderName);
        createdFolders.push({ name: folderName, created: true });
        Logger.log('📁 สร้างโฟลเดอร์: ' + folderName);
      }
    }
    
    return {
      success: true,
      folderId: currentFolder.getId(),
      folderName: currentFolder.getName(),
      folderUrl: currentFolder.getUrl(),
      folderPath: folderPath,
      structure: createdFolders
    };
    
  } catch (error) {
    Logger.log('❌ createFolderStructure Error: ' + error.toString());
    return {
      success: false,
      error: error.toString()
    };
  }
}

// ===================================================================
// 📋 #8 AUDIT LOG SYSTEM
// ===================================================================

/**
 * ⭐ บันทึก Audit Log ทุกกิจกรรม (เพิ่ม/แก้/ลบ)
 * @param {string} action - ชื่อ action เช่น 'เพิ่มเอกสาร', 'แก้ไขเอกสาร', 'ลบเอกสาร'
 * @param {Object} details - รายละเอียด {title, category, id, docId}
 * @param {string} username - ชื่อผู้ทำ
 */
function saveAuditLog_(action, details, username) {
  try {
    var ssId = getMasterSpreadsheetId_();
    var ss = SpreadsheetApp.openById(ssId);
    var logSheet = ss.getSheetByName(AUDIT_LOG_SHEET_NAME);
    
    if (!logSheet) {
      logSheet = ss.insertSheet(AUDIT_LOG_SHEET_NAME);
      logSheet.appendRow(['วันเวลา', 'ผู้ดำเนินการ', 'การกระทำ', 'รายละเอียด']);
      logSheet.getRange(1, 1, 1, 4).setFontWeight('bold').setBackground('#e8f0fe').setFontColor('#1a73e8');
      logSheet.setColumnWidth(1, 160);
      logSheet.setColumnWidth(2, 120);
      logSheet.setColumnWidth(3, 120);
      logSheet.setColumnWidth(4, 400);
    }
    
    var detailStr = '';
    if (details) {
      var parts = [];
      if (details.title) parts.push('ชื่อ: ' + details.title);
      if (details.category) parts.push('หมวด: ' + details.category);
      if (details.id !== undefined) parts.push('ID: ' + details.id);
      if (details.docId) parts.push('DocID: ' + details.docId);
      detailStr = parts.join(' | ');
    }
    
    logSheet.appendRow([
      new Date(),
      username || 'ระบบ',
      action,
      detailStr
    ]);
  } catch (e) {
    Logger.log('⚠️ saveAuditLog_ Error: ' + e.toString());
  }
}

/**
 * ⭐ ดึง Audit Log (สำหรับแสดงใน Admin)
 * @param {number} limit - จำนวนรายการที่ต้องการ (default: 50)
 * @returns {Object} - {success, data: [{timestamp, user, action, details}]}
 */
function getAuditLogs(limit) {
  try {
    limit = limit || 50;
    var ssId = getMasterSpreadsheetId_();
    var ss = SpreadsheetApp.openById(ssId);
    var logSheet = ss.getSheetByName(AUDIT_LOG_SHEET_NAME);
    
    if (!logSheet) return { success: true, data: [], total: 0 };
    
    var data = logSheet.getDataRange().getValues();
    if (data.length <= 1) return { success: true, data: [], total: 0 };
    
    var logs = [];
    var startRow = Math.max(1, data.length - limit);
    
    for (var i = data.length - 1; i >= startRow; i--) {
      logs.push({
        timestamp: _formatDateTH(data[i][0]),
        user: String(data[i][1] || ''),
        action: String(data[i][2] || ''),
        details: String(data[i][3] || '')
      });
    }
    
    return { success: true, data: logs, total: data.length - 1 };
  } catch (e) {
    return { success: false, error: e.toString() };
  }
}

// ===================================================================
// 💾 #11 BACKUP SYSTEM
// ===================================================================

/**
 * ⭐ สำรองข้อมูล Spreadsheet ทั้งหมดไปไฟล์ใหม่ใน Drive
 * @returns {Object} - {success, backupFileId, backupUrl, backupName}
 */
function backupSpreadsheet() {
  try {
    var ssId = getMasterSpreadsheetId_();
    var ss = SpreadsheetApp.openById(ssId);
    var config = getSchoolConfig();
    
    var now = new Date();
    var dateStr = Utilities.formatDate(now, 'Asia/Bangkok', 'yyyy-MM-dd_HHmm');
    var backupName = 'Backup_' + (config.schoolShort || 'DataCenter') + '_' + dateStr;
    
    // คัดลอก Spreadsheet ทั้งหมด
    var backupFile = DriveApp.getFileById(ssId).makeCopy(backupName);
    
    // ย้ายไปโฟลเดอร์ Backup (สร้างอัตโนมัติ)
    var rootFolder = getSystemRootFolder();
    var backupFolders = rootFolder.getFoldersByName('Backups');
    var backupFolder;
    if (backupFolders.hasNext()) {
      backupFolder = backupFolders.next();
    } else {
      backupFolder = rootFolder.createFolder('Backups');
    }
    
    backupFolder.addFile(backupFile);
    try { DriveApp.getRootFolder().removeFile(backupFile); } catch(e) {}
    
    // บันทึก Audit Log
    saveAuditLog_('สำรองข้อมูล', { title: backupName }, 'ระบบ');
    
    Logger.log('✅ Backup created: ' + backupName);
    
    return {
      success: true,
      backupFileId: backupFile.getId(),
      backupUrl: backupFile.getUrl(),
      backupName: backupName,
      timestamp: _formatDateTH(now)
    };
  } catch (e) {
    Logger.log('❌ backupSpreadsheet Error: ' + e.toString());
    return { success: false, error: e.toString() };
  }
}

// ===================================================================
// 📱 #10 LINE NOTIFICATION
// ===================================================================

/**
 * ⭐ ส่งแจ้งเตือนผ่าน LINE Notify
 * @param {string} message - ข้อความที่จะส่ง
 */
function sendLineNotify_(message) {
  var config = getSchoolConfig();
  var lineToken = config.lineNotifyToken;
  
  if (!lineToken) return; // ถ้าไม่ได้ตั้งค่า token → ข้าม
  
  try {
    var options = {
      method: 'post',
      headers: { 'Authorization': 'Bearer ' + lineToken },
      payload: { message: '\n' + message }
    };
    UrlFetchApp.fetch('https://notify-api.line.me/api/notify', options);
    Logger.log('✅ LINE Notify sent');
  } catch (e) {
    Logger.log('⚠️ LINE Notify failed: ' + e.toString());
  }
}

/**
 * ⭐ ทดสอบส่ง LINE Notify
 * @returns {Object} - {success, message}
 */
function testLineNotify() {
  try {
    var config = getSchoolConfig();
    if (!config.lineNotifyToken) {
      return { success: false, error: 'ยังไม่ได้ตั้งค่า LINE Notify Token' };
    }
    sendLineNotify_('🔔 ทดสอบแจ้งเตือนจาก Data Center ' + (config.schoolShort || ''));
    return { success: true, message: 'ส่งแจ้งเตือน LINE สำเร็จ!' };
  } catch (e) {
    return { success: false, error: e.toString() };
  }
}

// ===================================================================
// 👤 #9 USER/SUBMITTER MANAGEMENT
// ===================================================================

/**
 * ⭐ เพิ่มผู้ส่ง (Submitter)
 * @param {string} displayName - ชื่อผู้ส่ง
 * @param {string} position - ตำแหน่ง
 * @returns {Object} - {success, message}
 */
function addSubmitter(displayName, position) {
  try {
    if (!displayName || !displayName.trim()) {
      return { success: false, error: 'กรุณาระบุชื่อ' };
    }
    
    var config = getSchoolConfig();
    var ss = SpreadsheetApp.openById(config.spreadsheetId);
    var sheet = ss.getSheetByName(SUBMITTERS_SHEET_NAME);
    
    if (!sheet) {
      sheet = ss.insertSheet(SUBMITTERS_SHEET_NAME);
      sheet.appendRow(['ชื่อผู้ส่ง', 'ตำแหน่ง']);
      sheet.getRange(1, 1, 1, 2).setFontWeight('bold').setBackground('#e8f5e9');
    }
    
    // ตรวจสอบซ้ำ
    var data = sheet.getDataRange().getValues();
    for (var i = 1; i < data.length; i++) {
      if (String(data[i][0]).trim() === displayName.trim()) {
        return { success: false, error: 'มีชื่อนี้อยู่แล้ว' };
      }
    }
    
    sheet.appendRow([displayName.trim(), (position || '').trim()]);
    
    saveAuditLog_('เพิ่มผู้ส่ง', { title: displayName }, 'admin');
    
    return { success: true, message: 'เพิ่ม "' + displayName + '" เรียบร้อย' };
  } catch (e) {
    return { success: false, error: e.toString() };
  }
}

/**
 * ⭐ ลบผู้ส่ง (Submitter)
 * @param {string} displayName - ชื่อผู้ส่งที่ต้องการลบ
 * @returns {Object} - {success, message}
 */
function deleteSubmitter(displayName) {
  try {
    var config = getSchoolConfig();
    var ss = SpreadsheetApp.openById(config.spreadsheetId);
    var sheet = ss.getSheetByName(SUBMITTERS_SHEET_NAME);
    
    if (!sheet) return { success: false, error: 'ไม่พบชีตผู้ส่ง' };
    
    var data = sheet.getDataRange().getValues();
    for (var i = 1; i < data.length; i++) {
      if (String(data[i][0]).trim() === displayName.trim()) {
        sheet.deleteRow(i + 1);
        saveAuditLog_('ลบผู้ส่ง', { title: displayName }, 'admin');
        return { success: true, message: 'ลบ "' + displayName + '" เรียบร้อย' };
      }
    }
    
    return { success: false, error: 'ไม่พบผู้ส่ง: ' + displayName };
  } catch (e) {
    return { success: false, error: e.toString() };
  }
}

// ===================================================================
// 🔧 #15 DocID COLUMN SETUP
// ===================================================================

/**
 * ⭐ เพิ่มคอลัมน์ DocID ให้ Sheet (รันครั้งเดียว)
 * สำหรับเอกสารเก่าที่ยังไม่มี DocID จะสร้าง UUID ให้อัตโนมัติ
 */
function setupDocIdColumn() {
  try {
    var sheet = _getSheetSafe_();
    var headers = sheet.getRange(1, 1, 1, sheet.getLastColumn()).getValues()[0];
    
    // ตรวจว่ามี DocID column หรือยัง
    var docIdCol = -1;
    for (var i = 0; i < headers.length; i++) {
      if (headers[i] === 'DocID') { docIdCol = i; break; }
    }
    
    // ถ้ายังไม่มี → เพิ่มคอลัมน์ใหม่
    if (docIdCol === -1) {
      var newCol = headers.length + 1;
      sheet.getRange(1, newCol).setValue('DocID');
      sheet.getRange(1, newCol).setFontWeight('bold');
      docIdCol = newCol - 1;
      Logger.log('✅ เพิ่มคอลัมน์ DocID ที่คอลัมน์ ' + newCol);
    }
    
    // สร้าง UUID ให้เอกสารที่ยังไม่มี
    var lastRow = sheet.getLastRow();
    var filled = 0;
    
    if (lastRow > 1) {
      var docIdRange = sheet.getRange(2, docIdCol + 1, lastRow - 1, 1);
      var docIds = docIdRange.getValues();
      
      for (var r = 0; r < docIds.length; r++) {
        if (!docIds[r][0]) {
          docIds[r][0] = Utilities.getUuid();
          filled++;
        }
      }
      
      docIdRange.setValues(docIds);
    }
    
    _invalidateDocsCache_();
    
    Logger.log('✅ setupDocIdColumn: filled ' + filled + ' rows with UUID');
    return { success: true, message: 'สร้าง DocID เรียบร้อย (' + filled + ' รายการ)', filled: filled };
  } catch (e) {
    Logger.log('❌ setupDocIdColumn Error: ' + e.toString());
    return { success: false, error: e.toString() };
  }
}

// ===================================================================
// 🤖 LINE BOT WEBHOOK (รับไฟล์ผ่าน LINE → บันทึกลง Sheet + Drive)
// ===================================================================

/**
 * ⭐ Webhook endpoint สำหรับรับข้อมูลจาก LINE Messaging API
 * LINE จะส่ง POST request มาที่ Web App URL นี้
 */
function doPost(e) {
  try {
    if (!e || !e.postData || !e.postData.contents) {
      return ContentService.createTextOutput(JSON.stringify({ status: 'error', message: 'No data' }))
        .setMimeType(ContentService.MimeType.JSON);
    }

    var body = JSON.parse(e.postData.contents);
    var events = body.events || [];

    if (events.length === 0) {
      // LINE ส่ง verify webhook มาพร้อม events ว่าง → ตอบ ok
      return ContentService.createTextOutput(JSON.stringify({ status: 'ok' }))
        .setMimeType(ContentService.MimeType.JSON);
    }

    var config = getSchoolConfig();
    var accessToken = config.lineChannelAccessToken;

    if (!accessToken) {
      Logger.log('⚠️ LINE Bot: ไม่พบ Channel Access Token');
      return ContentService.createTextOutput(JSON.stringify({ status: 'error', message: 'No access token configured' }))
        .setMimeType(ContentService.MimeType.JSON);
    }

    for (var i = 0; i < events.length; i++) {
      var event = events[i];
      if (event.type === 'message') {
        handleLineMessageEvent_(event, accessToken, config);
      }
    }

    return ContentService.createTextOutput(JSON.stringify({ status: 'ok' }))
      .setMimeType(ContentService.MimeType.JSON);

  } catch (err) {
    Logger.log('❌ doPost error: ' + err.toString());
    return ContentService.createTextOutput(JSON.stringify({ status: 'error', message: err.toString() }))
      .setMimeType(ContentService.MimeType.JSON);
  }
}

/**
 * ⭐ จัดการ message event จาก LINE (แยก text / file / image / video / audio)
 */
function handleLineMessageEvent_(event, accessToken, config) {
  var msgType = event.message.type;
  var replyToken = event.replyToken;

  if (msgType === 'image' || msgType === 'video' || msgType === 'audio' || msgType === 'file') {
    handleLineFileMessage_(event, accessToken, config);
  } else if (msgType === 'text') {
    handleLineTextMessage_(event, accessToken, config);
  } else {
    replyLineMessage_(replyToken, [{
      type: 'text',
      text: '⚠️ ขออภัย ระบบรองรับเฉพาะข้อความ, รูปภาพ, วิดีโอ, เสียง และไฟล์เอกสารเท่านั้น'
    }], accessToken);
  }
}

/**
 * ⭐ จัดการข้อความ text จาก LINE (คำสั่ง + ตั้งชื่อ/หมวดล่วงหน้า)
 */
function handleLineTextMessage_(event, accessToken, config) {
  var text = event.message.text || '';
  var replyToken = event.replyToken;
  var userId = event.source ? event.source.userId : 'unknown';
  var trimmed = text.trim();

  // === คำสั่ง: สถานะ ===
  if (trimmed === 'สถานะ' || trimmed.toLowerCase() === 'status') {
    try {
      var sheet = _getSheetSafe_();
      var totalDocs = Math.max(0, sheet.getLastRow() - 1);
      var statusText = '📊 สถานะระบบ\n'
        + '━━━━━━━━━━━━\n'
        + '🏫 ' + (config.schoolName || '-') + '\n'
        + '📄 เอกสารทั้งหมด: ' + totalDocs + ' รายการ\n'
        + '✅ ระบบทำงานปกติ';
      replyLineMessage_(replyToken, [{ type: 'text', text: statusText }], accessToken);
    } catch (e) {
      replyLineMessage_(replyToken, [{ type: 'text', text: '⚠️ ไม่สามารถเชื่อมต่อฐานข้อมูลได้' }], accessToken);
    }
    return;
  }

  // === คำสั่ง: ตั้งชื่อเอกสารล่วงหน้า ===
  if (trimmed.indexOf('ชื่อ:') === 0 || trimmed.toLowerCase().indexOf('title:') === 0) {
    var pendingTitle = trimmed.replace(/^(ชื่อ:|title:)\s*/i, '');
    if (pendingTitle) {
      var cache = CacheService.getScriptCache();
      cache.put('LINE_PENDING_TITLE_' + userId, pendingTitle, 600);
      replyLineMessage_(replyToken, [{
        type: 'text',
        text: '✅ ตั้งชื่อเอกสาร: "' + pendingTitle + '"\n📎 ส่งไฟล์ได้เลย!'
      }], accessToken);
      return;
    }
  }

  // === คำสั่ง: ตั้งหมวดหมู่ล่วงหน้า ===
  if (trimmed.indexOf('หมวด:') === 0 || trimmed.toLowerCase().indexOf('cat:') === 0) {
    var pendingCat = trimmed.replace(/^(หมวด:|cat:)\s*/i, '');
    if (pendingCat) {
      var cache2 = CacheService.getScriptCache();
      cache2.put('LINE_PENDING_CAT_' + userId, pendingCat, 600);
      replyLineMessage_(replyToken, [{
        type: 'text',
        text: '✅ ตั้งหมวดหมู่: "' + pendingCat + '"\n📎 ส่งไฟล์ได้เลย!'
      }], accessToken);
      return;
    }
  }

  // === Default: แสดงวิธีใช้ ===
  var helpText = '📚 ' + (config.schoolName || 'Data Center') + '\n\n'
    + '🤖 วิธีใช้ LINE Bot:\n'
    + '1️⃣ ส่งไฟล์/รูปภาพ → บันทึกลงระบบอัตโนมัติ\n'
    + '2️⃣ พิมพ์ "ชื่อ:xxx" → ตั้งชื่อเอกสารล่วงหน้า\n'
    + '3️⃣ พิมพ์ "หมวด:xxx" → ตั้งหมวดหมู่ล่วงหน้า\n'
    + '4️⃣ พิมพ์ "สถานะ" → ดูสถานะระบบ\n\n'
    + '💡 ตัวอย่าง:\n'
    + '  ส่ง "ชื่อ:ใบเสร็จค่าไฟ"\n'
    + '  ส่ง "หมวด:การเงิน"\n'
    + '  จากนั้นส่งไฟล์เอกสาร';

  replyLineMessage_(replyToken, [{ type: 'text', text: helpText }], accessToken);
}

/**
 * ⭐ จัดการไฟล์/รูปภาพ/วิดีโอ/เสียง จาก LINE
 *   ดาวน์โหลด → บันทึก Drive → บันทึก Sheet → ตอบกลับ
 */
function handleLineFileMessage_(event, accessToken, config) {
  var msgType = event.message.type;
  var messageId = event.message.id;
  var replyToken = event.replyToken;
  var userId = event.source ? event.source.userId : '';

  try {
    // 1) ดึงชื่อผู้ส่งจาก LINE Profile
    var displayName = 'LINE User';
    if (userId) {
      try {
        var profile = getLineUserProfile_(userId, accessToken);
        if (profile && profile.displayName) {
          displayName = profile.displayName;
        }
      } catch (profileErr) {
        Logger.log('⚠️ Get LINE profile failed: ' + profileErr);
      }
    }

    // 2) กำหนดชื่อไฟล์ตามประเภท
    var fileName = '';
    var timeStamp = Utilities.formatDate(new Date(), 'Asia/Bangkok', 'yyyyMMdd_HHmmss');

    if (msgType === 'file') {
      fileName = event.message.fileName || ('ไฟล์จาก_LINE_' + timeStamp);
    } else if (msgType === 'image') {
      fileName = 'IMG_LINE_' + timeStamp + '.jpg';
    } else if (msgType === 'video') {
      fileName = 'VID_LINE_' + timeStamp + '.mp4';
    } else if (msgType === 'audio') {
      fileName = 'AUD_LINE_' + timeStamp + '.m4a';
    }

    // 3) ดาวน์โหลดไฟล์จาก LINE Content API
    var blob = downloadLineContent_(messageId, accessToken);
    if (!blob) {
      replyLineMessage_(replyToken, [{ type: 'text', text: '❌ ไม่สามารถดาวน์โหลดไฟล์ได้' }], accessToken);
      return;
    }
    blob.setName(fileName);

    // 4) ตรวจ pending หมวดหมู่จาก cache
    var category = 'เอกสารจาก LINE';
    var cache = CacheService.getScriptCache();
    if (userId) {
      var pendingCat = cache.get('LINE_PENDING_CAT_' + userId);
      if (pendingCat) {
        category = pendingCat;
        cache.remove('LINE_PENDING_CAT_' + userId);
      }
    }

    // 5) บันทึกลง Google Drive
    var folder = getOrCreateCategoryFolder(category);
    var file = folder.createFile(blob);
    try {
      file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);
    } catch (shareErr) {
      Logger.log('⚠️ setSharing failed: ' + shareErr);
    }

    // 6) ตรวจ pending ชื่อเอกสารจาก cache
    var docTitle = fileName;
    if (userId) {
      var pendingTitle = cache.get('LINE_PENDING_TITLE_' + userId);
      if (pendingTitle) {
        docTitle = pendingTitle;
        cache.remove('LINE_PENDING_TITLE_' + userId);
      }
    }

    // 7) บันทึกลง Google Sheet (ใช้ addDocument เดิม)
    var fileObjects = JSON.stringify([{
      name: file.getName(),
      url: file.getUrl(),
      fileUrl: file.getUrl(),
      mimeType: file.getMimeType(),
      size: file.getSize()
    }]);

    var docData = {
      title: docTitle,
      category: category,
      document_type: msgType === 'image' ? 'รูปภาพ' : msgType === 'video' ? 'วิดีโอ' : msgType === 'audio' ? 'เสียง' : 'ไฟล์เอกสาร',
      submitter_name: displayName,
      tags: 'LINE Bot',
      description: 'ส่งผ่าน LINE Bot โดย ' + displayName,
      file_objects_json: fileObjects
    };

    var result = addDocument(docData);

    // 8) ตอบกลับผู้ส่ง
    if (result && result.success) {
      var successText = '✅ บันทึกสำเร็จ!\n'
        + '━━━━━━━━━━━━\n'
        + '📄 ชื่อ: ' + docTitle + '\n'
        + '📁 หมวด: ' + category + '\n'
        + '👤 ผู้ส่ง: ' + displayName + '\n'
        + '🔗 ' + file.getUrl();
      replyLineMessage_(replyToken, [{ type: 'text', text: successText }], accessToken);
    } else {
      replyLineMessage_(replyToken, [{
        type: 'text',
        text: '❌ บันทึกไม่สำเร็จ: ' + (result ? result.error : 'Unknown error')
      }], accessToken);
    }

    Logger.log('✅ LINE Bot: บันทึกไฟล์สำเร็จ - ' + docTitle);

  } catch (err) {
    Logger.log('❌ LINE Bot handleFile error: ' + err.toString());
    try {
      replyLineMessage_(replyToken, [{
        type: 'text',
        text: '❌ เกิดข้อผิดพลาด: ' + err.toString()
      }], accessToken);
    } catch (replyErr) {
      Logger.log('❌ Reply failed: ' + replyErr);
    }
  }
}

/**
 * ⭐ ดาวน์โหลดไฟล์จาก LINE Content API
 */
function downloadLineContent_(messageId, accessToken) {
  var url = 'https://api-data.line.me/v2/bot/message/' + messageId + '/content';
  var options = {
    method: 'get',
    headers: { 'Authorization': 'Bearer ' + accessToken },
    muteHttpExceptions: true
  };

  var response = UrlFetchApp.fetch(url, options);

  if (response.getResponseCode() === 200) {
    return response.getBlob();
  }

  Logger.log('❌ Download LINE content failed: HTTP ' + response.getResponseCode());
  return null;
}

/**
 * ⭐ ดึงโปรไฟล์ผู้ใช้ LINE
 */
function getLineUserProfile_(userId, accessToken) {
  var url = 'https://api.line.me/v2/bot/profile/' + userId;
  var options = {
    method: 'get',
    headers: { 'Authorization': 'Bearer ' + accessToken },
    muteHttpExceptions: true
  };

  var response = UrlFetchApp.fetch(url, options);

  if (response.getResponseCode() === 200) {
    return JSON.parse(response.getContentText());
  }

  Logger.log('⚠️ Get LINE profile failed: HTTP ' + response.getResponseCode());
  return null;
}

/**
 * ⭐ ตอบกลับข้อความไปยัง LINE
 */
function replyLineMessage_(replyToken, messages, accessToken) {
  var url = 'https://api.line.me/v2/bot/message/reply';
  var payload = {
    replyToken: replyToken,
    messages: messages
  };

  var options = {
    method: 'post',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + accessToken
    },
    payload: JSON.stringify(payload),
    muteHttpExceptions: true
  };

  var response = UrlFetchApp.fetch(url, options);

  if (response.getResponseCode() !== 200) {
    Logger.log('⚠️ LINE reply failed: ' + response.getContentText());
  }
}

/**
 * ⭐ ดึง Webhook URL สำหรับตั้งค่าใน LINE Developers Console
 */
function getLineBotWebhookUrl() {
  try {
    var url = ScriptApp.getService().getUrl();
    return { success: true, url: url };
  } catch (e) {
    return { success: false, error: e.toString() };
  }
}

/**
 * ⭐ ทดสอบ LINE Bot (เช็คว่า Token ใช้ได้หรือไม่)
 */
function testLineBot() {
  try {
    var config = getSchoolConfig();
    if (!config.lineChannelAccessToken) {
      return { success: false, error: 'ยังไม่ได้ตั้งค่า LINE Channel Access Token' };
    }

    var url = 'https://api.line.me/v2/bot/info';
    var options = {
      method: 'get',
      headers: { 'Authorization': 'Bearer ' + config.lineChannelAccessToken },
      muteHttpExceptions: true
    };

    var response = UrlFetchApp.fetch(url, options);

    if (response.getResponseCode() === 200) {
      var botInfo = JSON.parse(response.getContentText());
      return {
        success: true,
        message: 'LINE Bot เชื่อมต่อสำเร็จ! ชื่อ Bot: ' + (botInfo.displayName || botInfo.basicId || 'Unknown'),
        botName: botInfo.displayName || '',
        botId: botInfo.basicId || ''
      };
    } else {
      return { success: false, error: 'Token ไม่ถูกต้อง (HTTP ' + response.getResponseCode() + ')' };
    }
  } catch (e) {
    return { success: false, error: e.toString() };
  }
}
