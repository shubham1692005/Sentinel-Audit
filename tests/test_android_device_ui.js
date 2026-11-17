const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const source = fs.readFileSync('web/app.js', 'utf8');
assert.match(source, /Download #\$\{a\.id\} PDF/, 'Findings identifies the assessment attached to each PDF action');
assert.match(source, /selected-assessment-pdf/, 'Findings exposes a PDF action for any assessment selected in the filter');
assert.match(source, /Project-wide reports/, 'Project-wide reporting remains explicitly labeled separately');
const context = {
  window: { addEventListener() {} },
  document: { addEventListener() {}, querySelector() { return null; } },
  sessionStorage: { getItem() { return ''; }, setItem() {}, removeItem() {} },
  URLSearchParams,
};
vm.createContext(context);
vm.runInContext(source, context);

assert.equal(context.androidAuditAvailable(), false, 'desktop browser has no native bridge');
vm.runInContext('state.user = { id: 1 }; state.project = { id: 1 };', context);
assert.equal(context.androidAuditAvailable(), false, 'Android action stays hidden without the native bridge');
context.window.SentinelAndroid = { requestAndroidDeviceAudit() {} };
assert.equal(context.androidAuditAvailable(), true, 'signed-in Android WebView exposes the native action');
let nativeDownload = null;
context.window.SentinelAndroid.requestReportDownload = (path, filename) => {
  nativeDownload = { path, filename };
};
context.download('/reports/pdf?project_id=1&type=technical', 'security-technical-report.pdf');
assert.deepEqual(nativeDownload, {
  path: '/api/reports/pdf?project_id=1&type=technical',
  filename: 'security-technical-report.pdf',
}, 'Android WebView hands report downloads to the authenticated native downloader');
context.downloadAssessmentPdf(27);
assert.deepEqual(nativeDownload, {
  path: '/api/reports/pdf?project_id=1&type=technical&assessment_id=27',
  filename: 'security-technical-assessment-27.pdf',
}, 'Assessment-specific PDF downloads use a unique assessment ID on Android');
context.downloadAssessmentPdf(0);
assert.deepEqual(nativeDownload, {
  path: '/api/reports/pdf?project_id=1&type=technical&assessment_id=27',
  filename: 'security-technical-assessment-27.pdf',
}, 'Invalid assessment IDs are not sent to the native downloader');
vm.runInContext('state.user = null;', context);
assert.equal(context.androidAuditAvailable(), false, 'logged-out users cannot submit an on-device audit');

vm.runInContext('state.user = { id: 1 };', context);
let queued = null;
context.queueScan = (kind, options) => { queued = { kind, options }; };
context.window.SentinelAudit.onAndroidDeviceAuditCollected({ schema_version: 1 });
assert.equal(queued.kind, 'android_device');
assert.equal(queued.options.consent_confirmed, true);
assert.deepEqual(JSON.parse(JSON.stringify(queued.options.device_audit)), { schema_version: 1 });

async function verifyPasswordChangeForm() {
  let shownModal = null;
  let submitted = null;
  let toastMessage = null;
  let closed = false;
  const form = { data: {}, reset() { this.data = {}; } };
  context.modal = (title, html) => { shownModal = { title, html }; };
  context.document.querySelector = selector => selector === '#password-form' ? form : null;
  context.FormData = class {
    constructor(element) { this.element = element; }
    [Symbol.iterator]() { return Object.entries(this.element.data)[Symbol.iterator](); }
  };
  context.api = async (path, options) => { submitted = { path, body: JSON.parse(options.body) }; return {}; };
  context.closeModal = () => { closed = true; };
  context.toast = message => { toastMessage = message; };
  context.passwordDialog();
  assert.equal(shownModal.title, 'Change password');
  assert.match(shownModal.html, /name="current_password"/);
  assert.match(shownModal.html, /name="new_password"[^>]*minlength="6"/);
  assert.match(shownModal.html, /name="confirm_password"/);
  form.data = { current_password: 'current-password-123', new_password: 'new-password-1234', confirm_password: 'not-the-same-password' };
  await form.onsubmit({ preventDefault() {}, currentTarget: form });
  assert.equal(submitted, null, 'mismatched new passwords are rejected before the API call');
  form.data = { current_password: 'current-password-123', new_password: 'new-password-1234', confirm_password: 'new-password-1234' };
  await form.onsubmit({ preventDefault() {}, currentTarget: form });
  assert.equal(submitted.path, '/auth/change-password');
  assert.equal(submitted.body.new_password, 'new-password-1234');
  assert.equal(closed, true);
  assert.match(toastMessage, /Password changed/);
  console.log('Android device audit and password change UI checks passed');
}

verifyPasswordChangeForm().catch(error => { console.error(error); process.exitCode = 1; });
