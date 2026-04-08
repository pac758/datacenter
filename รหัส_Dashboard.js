// ============================================================
//  getDashboardData() — เพิ่มใน รหัส.js
//  อ่านข้อมูลจาก Google Sheet แล้วส่งกลับให้ Dashboard
// ============================================================

/**
 * ฟังก์ชันหลักสำหรับ Dashboard
 * เรียกจาก client ด้วย google.script.run.getDashboardData()
 */
function getDashboardData() {
  try {
    var cfg    = getSchoolConfig();          // ดึง config ที่มีอยู่แล้ว
    var ss     = SpreadsheetApp.openById(cfg.spreadsheetId);
    var sheet  = ss.getSheetByName(cfg.sheetName);

    if (!sheet) throw new Error('ไม่พบ Sheet: ' + cfg.sheetName);

    var data   = sheet.getDataRange().getValues();
    var headers = data[0];

    // ---- หา index ของคอลัมน์สำคัญ ----
    // *** ปรับชื่อคอลัมน์ให้ตรงกับ Sheet จริงของคุณ ***
    var colMap = {
      timestamp : findCol(headers, ['timestamp','วันที่','เวลา','Timestamp']),
      title     : findCol(headers, ['ชื่อเอกสาร','title','หัวข้อ','ชื่อ']),
      category  : findCol(headers, ['หมวดหมู่','category','ประเภท','Category']),
      submitter : findCol(headers, ['ผู้ส่ง','submitter','ชื่อผู้ส่ง','name']),
      fileType  : findCol(headers, ['ประเภทไฟล์','filetype','type']),
      docId     : findCol(headers, ['docId','DocID','เลขที่'])
    };

    var rows   = data.slice(1).filter(function(r) { return r[colMap.title] || r[colMap.timestamp]; });
    var today  = new Date(); today.setHours(0,0,0,0);

    // ---- Stats ----
    var totalCount     = rows.length;
    var todayCount     = 0;
    var thisMonthCount = 0;
    var submitterSet   = {};
    var categoryCount  = {};

    rows.forEach(function(row) {
      var ts = row[colMap.timestamp];
      var d  = ts ? new Date(ts) : null;
      if (d) {
        d.setHours(0,0,0,0);
        if (d.getTime() === today.getTime()) todayCount++;
        var now = new Date();
        if (d.getMonth() === now.getMonth() && d.getFullYear() === now.getFullYear()) thisMonthCount++;
      }
      var sub = String(row[colMap.submitter] || '').trim();
      if (sub) submitterSet[sub] = true;

      var cat = String(row[colMap.category] || 'อื่นๆ').trim();
      if (cat) categoryCount[cat] = (categoryCount[cat] || 0) + 1;
    });

    // ---- Categories Array ----
    var categories = Object.keys(categoryCount)
      .map(function(k) { return { name: k, count: categoryCount[k] }; })
      .sort(function(a,b) { return b.count - a.count; });

    // ---- Monthly (ปีงบประมาณ: ต.ค. ถึง ก.ย.) ----
    var monthly = buildMonthlyData(rows, colMap, categories);

    // ---- Recent Documents ----
    var recent = rows.slice().reverse().slice(0, 10).map(function(row) {
      return {
        title    : String(row[colMap.title]     || '').substring(0, 60),
        category : String(row[colMap.category]  || 'อื่นๆ'),
        submitter: String(row[colMap.submitter] || '-'),
        fileType : String(row[colMap.fileType]  || ''),
        docId    : String(row[colMap.docId]     || ''),
        date     : row[colMap.timestamp] ? new Date(row[colMap.timestamp]).toISOString() : ''
      };
    });

    return {
      stats: {
        total      : totalCount,
        today      : todayCount,
        categories : categories.length,
        submitters : Object.keys(submitterSet).length,
        thisMonth  : thisMonthCount
      },
      categories : categories,
      monthly    : monthly,
      recent     : recent
    };

  } catch (e) {
    Logger.log('getDashboardData error: ' + e.toString());
    return { error: e.toString(), stats: { total:0, today:0, categories:0, submitters:0, thisMonth:0 }, categories:[], monthly:[], recent:[] };
  }
}

/** สร้างข้อมูลรายเดือน (ปีงบประมาณ ต.ค. - ก.ย.) */
function buildMonthlyData(rows, colMap, categories) {
  // ลำดับเดือนในปีงบประมาณ: 10,11,12,1,2,...,9
  var fiscalMonths = [10,11,12,1,2,3,4,5,6,7,8,9];
  var now = new Date();
  var fiscalYear = now.getMonth() >= 9 ? now.getFullYear() : now.getFullYear() - 1;

  var monthlyData = fiscalMonths.map(function(m) {
    var obj = { month: m };
    categories.forEach(function(c) { obj[c.name] = 0; });
    return obj;
  });

  rows.forEach(function(row) {
    var ts = row[colMap.timestamp];
    if (!ts) return;
    var d  = new Date(ts);
    var m  = d.getMonth() + 1;  // 1-12
    var y  = d.getFullYear();

    // เช็คปีงบประมาณ
    var isSameFY = (m >= 10 && y === fiscalYear) || (m < 10 && y === fiscalYear + 1);
    if (!isSameFY) return;

    var idx = fiscalMonths.indexOf(m);
    if (idx < 0) return;

    var cat = String(row[colMap.category] || 'อื่นๆ').trim();
    if (monthlyData[idx][cat] !== undefined) {
      monthlyData[idx][cat]++;
    }
  });

  return monthlyData;
}

/** หา index ของ column จาก header row */
function findCol(headers, candidates) {
  for (var i = 0; i < candidates.length; i++) {
    var idx = headers.findIndex(function(h) {
      return String(h).toLowerCase().indexOf(candidates[i].toLowerCase()) >= 0;
    });
    if (idx >= 0) return idx;
  }
  return -1;  // ไม่พบ
}

// ============================================================
//  exportToSheet() — Export รายงานเป็น Google Sheets
// ============================================================
function exportToSheet() {
  try {
    var cfg   = getSchoolConfig();
    var ss    = SpreadsheetApp.openById(cfg.spreadsheetId);
    var sheet = ss.getSheetByName(cfg.sheetName);
    if (!sheet) throw new Error('ไม่พบ Sheet');

    var now        = new Date();
    var exportName = 'รายงานเอกสาร_' + Utilities.formatDate(now, 'Asia/Bangkok', 'dd-MM-yyyy_HH-mm');
    var exportSS   = ss.copy(exportName);

    // Log การ export
    logAudit('Export', 'ส่งออกรายงาน: ' + exportName);

    return exportSS.getUrl();
  } catch (e) {
    Logger.log('exportToSheet error: ' + e);
    throw e;
  }
}

// ============================================================
//  logAudit() — บันทึก Audit Log (ถ้ายังไม่มี)
// ============================================================
function logAudit(action, detail) {
  try {
    var cfg   = getSchoolConfig();
    var ss    = SpreadsheetApp.openById(cfg.spreadsheetId);
    var auditSheet = ss.getSheetByName('AuditLog');
    if (!auditSheet) {
      auditSheet = ss.insertSheet('AuditLog');
      auditSheet.appendRow(['วันที่เวลา', 'การกระทำ', 'รายละเอียด', 'ผู้ใช้']);
    }
    var user = Session.getActiveUser().getEmail() || 'unknown';
    auditSheet.appendRow([new Date(), action, detail, user]);
  } catch (e) {
    Logger.log('logAudit error: ' + e);
  }
}
