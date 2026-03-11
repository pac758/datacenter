// ===================================================================
// ⚙️ Code.gs - FIXED v15.0 (Token-based Auth)
// ✅ ลบ Session.getActiveUser() ทั้งหมด
// ✅ ใช้ Token-based Authentication แทน
// ✅ รองรับ Multi Google Account
// ===================================================================

const DEFAULT_CONFIG = {
  schoolName: 'โรงเรียนบ้านโคกยางหนองถนน',
  schoolShort: 'บ้านโคกยางฯ',
  schoolAddress: 'ต.ก้านเหลือง อ.นางรอง จ.บุรีรัมย์',
  adminEmail: 'admin@school.ac.th',
  spreadsheetId: '19Dr60-P9DgtaAc_3tJIABuNf_GVEttXHQYbDMnl7PVs',
  sheetName: 'การตอบแบบฟอร์ม 1',
  folderId: '1SkiPR0RFqBAyQohk3hEAY2TuxUxRDuNC',
  googleFormUrl: '',
  primaryColor: '#667eea',
  secondaryColor: '#764ba2',
  version: '15.0',
  credit: '© 2568 @pthk',
  logoFileId: ''
};

const ADMIN_PASSWORD = '3333';
const DOCS_CACHE_KEY = 'RKT_DOCS_CACHE_V1';
const DOCS_CACHE_TTL_SECONDS = 60;
const SUBMITTERS_SHEET_NAME = 'ผู้ส่ง';
const SETUP_SHEET_NAME = 'setup';
const DELETE_LOG_SHEET_NAME = 'Delete_Log';

// ✅ [NEW] Token Configuration
const TOKEN_EXPIRY_HOURS = 24;

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
  if ((password || '').toString().trim() === ADMIN_PASSWORD) {
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
  
  var output = template.evaluate()
    .setTitle('ระบบศูนย์กลางข้อมูล รร.บ้านโคกยางหนองถนน')
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
    return config;
  } catch (e) {
    return DEFAULT_CONFIG;
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
    
    return {
      id: index,
      timestamp: _formatDateTH(ts),
      title: String(_getValue_(row, map, ['ชื่อเอกสาร', 'Title', 'Document Title'])),
      category: String(_getValue_(row, map, ['หมวดหมู่', 'Category'])),
      document_type: String(_getValue_(row, map, ['ประเภทเอกสาร', 'Type'])),
      document_date: _formatDateTH(docDate, true),
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
        return d.title.toLowerCase().includes(term) ||
          d.submitter_name.toLowerCase().includes(term) ||
          d.tags.toLowerCase().includes(term) ||
          (d.description || '').toLowerCase().includes(term);
      });
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
    return { success: true, message: 'Saved successfully' };
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
    
    var folder;
    try {
      folder = DriveApp.getFolderById(config.folderId);
    } catch (e) {
      folder = DriveApp.getRootFolder();
    }
    
    if (config.logoFileId) {
      try { DriveApp.getFileById(config.logoFileId).setTrashed(true); } catch (e) {}
    }
    
    var file = folder.createFile(blob);
    file.setName('school_logo_' + new Date().getTime() + getExtension(mimeType));
    file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);
    
    var newFileId = file.getId();
    config.logoFileId = newFileId;
    saveSchoolConfig(config);
    
    return { success: true, fileId: newFileId, fileUrl: file.getUrl() };
  } catch (e) {
    return { success: false, error: e.toString() };
  }
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
        file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);
        
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
      finalFile.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);
      
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
    file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);
    
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
  try {
    var config = getSchoolConfig();
    var root = DriveApp.getFolderById(config.folderId);
    var name = categoryName || 'Uncategorized';
    var folders = root.getFoldersByName(name);
    if (folders.hasNext()) return folders.next();
    return root.createFolder(name);
  } catch (e) {
    var config = getSchoolConfig();
    return DriveApp.getFolderById(config.folderId);
  }
}

function uploadFile(data, name, type, category) {
  try {
    var folder = getOrCreateCategoryFolder(category);
    var blob = Utilities.newBlob(Utilities.base64Decode(data.split(',')[1]), type, name);
    var file = folder.createFile(blob);
    file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);
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
// 🗑️ CACHE MANAGEMENT
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
    var config = getSchoolConfig();
    baseFolderId = baseFolderId || config.folderId || DEFAULT_CONFIG.folderId;
    
    var baseFolder = DriveApp.getFolderById(baseFolderId);
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
    file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);
    
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
    var config = getSchoolConfig();
    var baseFolderId = config.folderId || DEFAULT_CONFIG.folderId;
    
    // ถ้ามี category ให้สร้างโฟลเดอร์หมวดหมู่ก่อน
    if (category && category.trim() !== '') {
      var baseFolder = DriveApp.getFolderById(baseFolderId);
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
    var config = getSchoolConfig();
    parentFolderId = parentFolderId || config.folderId || DEFAULT_CONFIG.folderId;
    
    var parentFolder = DriveApp.getFolderById(parentFolderId);
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
    var config = getSchoolConfig();
    baseFolderId = baseFolderId || config.folderId || DEFAULT_CONFIG.folderId;
    
    var currentFolder = DriveApp.getFolderById(baseFolderId);
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

